using System.Buffers.Binary;

namespace CodeDesigner.Ps2.Multiplayer.Protocol;

/// <summary>Direction-specific TCP flow key: source and destination IPv4 endpoints.</summary>
public readonly record struct TcpFlowKey(uint SrcIp, ushort SrcPort, uint DstIp, ushort DstPort)
{
    public TcpFlowKey Reverse => new(DstIp, DstPort, SrcIp, SrcPort);
}

/// <summary>TCP header values of one IPv4 segment, as read by <see cref="FrameBuilder.TryReadTcp"/>.</summary>
public readonly record struct TcpSegmentInfo(TcpFlowKey Flow, uint Seq, uint Ack, byte Flags, int PayloadLength)
{
    /// <summary>Sequence number the next segment in this direction starts at (SYN/FIN count as one byte).</summary>
    public uint NextSeq => unchecked(Seq + (uint)PayloadLength + ((Flags & 0x02) != 0 ? 1u : 0u) + ((Flags & 0x01) != 0 ? 1u : 0u));
}

/// <summary>
/// Edits raw Ethernet/IPv4 frames for packet injection: swap the TCP/UDP payload, recompute the
/// IPv4 total length and header checksum, the UDP length and checksum and the TCP checksum, and
/// move a TCP segment onto a live connection's sequence numbers. Frames that are not IPv4
/// TCP/UDP pass through <see cref="FixLengthsAndChecksums"/> untouched.
/// </summary>
public static class FrameBuilder
{
    private const int EthHeader = 14;

    /// <summary>Locate the TCP/UDP payload. False for anything that isn't IPv4 TCP/UDP.</summary>
    public static bool TryLocatePayload(byte[] frame, out int protocol, out int payloadOffset, out int payloadLength)
    {
        protocol = payloadOffset = payloadLength = 0;
        if (frame.Length < EthHeader + 20 || frame[12] != 0x08 || frame[13] != 0x00) return false;
        int ihl = (frame[EthHeader] & 0x0F) * 4;
        protocol = frame[EthHeader + 9];
        int l4 = EthHeader + ihl;
        int totalLen = BinaryPrimitives.ReadUInt16BigEndian(frame.AsSpan(EthHeader + 2));
        int ipEnd = Math.Min(EthHeader + totalLen, frame.Length);
        if (protocol == 6 && frame.Length >= l4 + 20)
        {
            payloadOffset = l4 + ((frame[l4 + 12] >> 4) & 0xF) * 4;
        }
        else if (protocol == 17 && frame.Length >= l4 + 8)
        {
            payloadOffset = l4 + 8;
        }
        else return false;
        payloadLength = Math.Max(ipEnd - payloadOffset, 0);
        return payloadOffset <= frame.Length;
    }

    /// <summary>Copy of <paramref name="frame"/> with its TCP/UDP payload replaced, lengths and checksums fixed.</summary>
    public static byte[] ReplacePayload(byte[] frame, ReadOnlySpan<byte> payload)
    {
        if (!TryLocatePayload(frame, out _, out int off, out _))
            throw new ArgumentException("The template frame isn't IPv4 TCP/UDP, so it has no payload to replace");
        var result = new byte[off + payload.Length];
        frame.AsSpan(0, off).CopyTo(result);
        payload.CopyTo(result.AsSpan(off));
        WriteIpTotalLength(result, result.Length - EthHeader);
        FixChecksums(result);
        return result;
    }

    /// <summary>
    /// Recompute lengths and checksums after a hand edit. The IPv4 total length follows the frame
    /// length, except for a minimum-size (60-byte) frame whose old length is shorter, which is
    /// Ethernet padding and keeps its length.
    /// </summary>
    public static void FixLengthsAndChecksums(byte[] frame)
    {
        if (frame.Length < EthHeader + 20 || frame[12] != 0x08 || frame[13] != 0x00) return;
        int oldTotal = BinaryPrimitives.ReadUInt16BigEndian(frame.AsSpan(EthHeader + 2));
        bool padded = frame.Length == 60 && oldTotal < 46;
        if (!padded) WriteIpTotalLength(frame, frame.Length - EthHeader);
        FixChecksums(frame);
    }

    /// <summary>Read the TCP header of an IPv4 TCP frame.</summary>
    public static bool TryReadTcp(byte[] frame, out TcpSegmentInfo info)
    {
        info = default;
        if (!TryLocatePayload(frame, out int proto, out int payOff, out int payLen) || proto != 6) return false;
        int ihl = (frame[EthHeader] & 0x0F) * 4;
        int l4  = EthHeader + ihl;
        var key = new TcpFlowKey(
            BinaryPrimitives.ReadUInt32BigEndian(frame.AsSpan(EthHeader + 12)),
            BinaryPrimitives.ReadUInt16BigEndian(frame.AsSpan(l4)),
            BinaryPrimitives.ReadUInt32BigEndian(frame.AsSpan(EthHeader + 16)),
            BinaryPrimitives.ReadUInt16BigEndian(frame.AsSpan(l4 + 2)));
        info = new TcpSegmentInfo(key,
            BinaryPrimitives.ReadUInt32BigEndian(frame.AsSpan(l4 + 4)),
            BinaryPrimitives.ReadUInt32BigEndian(frame.AsSpan(l4 + 8)),
            frame[l4 + 13], payLen);
        return true;
    }

    /// <summary>Overwrite the TCP sequence and acknowledgment numbers and refresh the checksum.</summary>
    public static void SetTcpSeqAck(byte[] frame, uint seq, uint? ack)
    {
        if (!TryLocatePayload(frame, out int proto, out _, out _) || proto != 6) return;
        int l4 = EthHeader + (frame[EthHeader] & 0x0F) * 4;
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(l4 + 4), seq);
        if (ack is uint a) BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(l4 + 8), a);
        FixChecksums(frame);
    }

    // ── Checksums ────────────────────────────────────────────────────────────

    private static void WriteIpTotalLength(byte[] frame, int length)
        => BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(EthHeader + 2), (ushort)Math.Min(length, ushort.MaxValue));

    private static void FixChecksums(byte[] frame)
    {
        int ihl = (frame[EthHeader] & 0x0F) * 4;
        if (frame.Length < EthHeader + ihl) return;
        var ip = frame.AsSpan(EthHeader, ihl);
        ip[10] = ip[11] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(ip[10..], Checksum(ip, 0));

        if (!TryLocatePayload(frame, out int proto, out _, out _)) return;
        int totalLen = BinaryPrimitives.ReadUInt16BigEndian(frame.AsSpan(EthHeader + 2));
        int l4 = EthHeader + ihl;
        int l4Len = Math.Min(totalLen - ihl, frame.Length - l4);
        if (l4Len <= 0) return;
        var seg = frame.AsSpan(l4, l4Len);

        // Pseudo-header: src, dst, zero, protocol, L4 length.
        uint sum = 0;
        sum += Sum16(frame.AsSpan(EthHeader + 12, 8));
        sum += (uint)proto;
        sum += (uint)l4Len;

        if (proto == 17)
        {
            BinaryPrimitives.WriteUInt16BigEndian(seg[4..], (ushort)l4Len);
            seg[6] = seg[7] = 0;
            ushort c = Checksum(seg, sum);
            BinaryPrimitives.WriteUInt16BigEndian(seg[6..], c == 0 ? (ushort)0xFFFF : c);
        }
        else if (proto == 6 && l4Len >= 20)
        {
            seg[16] = seg[17] = 0;
            BinaryPrimitives.WriteUInt16BigEndian(seg[16..], Checksum(seg, sum));
        }
    }

    private static uint Sum16(ReadOnlySpan<byte> data)
    {
        uint sum = 0;
        int i = 0;
        for (; i + 1 < data.Length; i += 2) sum += (uint)((data[i] << 8) | data[i + 1]);
        if (i < data.Length) sum += (uint)(data[i] << 8);
        return sum;
    }

    private static ushort Checksum(ReadOnlySpan<byte> data, uint initial)
    {
        ulong sum = initial + (ulong)Sum16(data);
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }
}
