using System.Net;
using System.Text;
using CodeDesigner.Ps2.Multiplayer.Crypto;

namespace CodeDesigner.Ps2.Multiplayer.Protocol;

/// <summary>
/// Represents a raw decoded SCERT transport packet.
/// Wire format: [type: 1 byte][length: 2 bytes LE][payload: length bytes]
/// If the high bit of type is set, 4 hash bytes follow the header before payload (encrypted).
/// </summary>
public class ScertPacket
{
    public const int HeaderSize        = 3;
    public const int EncryptedHashSize = 4;

    /// <summary>Largest payload the 16-bit length field can carry.</summary>
    public const int MaxPayloadLength  = 0xFFFF;

    public RT_MSG_TYPE MessageType { get; set; }
    public byte[]      Payload     { get; set; } = Array.Empty<byte>();
    public bool        IsEncrypted { get; set; }
    /// <summary>4-byte per-packet hash from the SCERT encrypted-packet header. Non-null only when IsEncrypted=true.</summary>
    public byte[]?     Hash        { get; set; }

    // -------------------------------------------------------------------------
    // Factory helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// SERVER_HELLO — PS2 format: exactly 4 bytes [ARG1: ushort = 0x006E][ARG2: ushort = 0x0001].
    /// (Matches Horizon: RT_MSG_SERVER_HELLO.Serialize writes only ARG1+ARG2 for MediusVersion ≤ 111.
    ///  The RSA public key is NOT embedded in SERVER_HELLO for PS2; it is only sent for PS3
    ///  MediusVersion 112/113 inside a full certificate blob.)
    /// </summary>
    public static ScertPacket CreateHello() => new()
    {
        MessageType = RT_MSG_TYPE.RT_MSG_SERVER_HELLO,
        Payload = [0x6E, 0x00, 0x01, 0x00],
    };

    /// <summary>
    /// SERVER_CRYPTKEY_PEER — server's RC4 session key (64 bytes).
    /// Pass a non-null <paramref name="hash"/> (4 bytes) to send as an encrypted packet
    /// (0x80 flag set) with the payload RSA-encrypted using the client's public key.
    /// </summary>
    public static ScertPacket CreateCryptKeyPeer(byte[] key, byte[]? hash = null) => new()
    {
        MessageType = RT_MSG_TYPE.RT_MSG_SERVER_CRYPTKEY_PEER,
        Payload     = key,
        Hash        = hash,
    };

    /// <summary>
    /// SERVER_CRYPTKEY_GAME — same RC4 key used for game-layer traffic.
    /// </summary>
    public static ScertPacket CreateCryptKeyGame(byte[] key) => new()
    {
        MessageType = RT_MSG_TYPE.RT_MSG_SERVER_CRYPTKEY_GAME,
        Payload     = key,
    };

    /// <summary>
    /// SERVER_CONNECT_ACCEPT_TCP — completes the SCERT connect handshake.
    /// Format depends on Medius version:
    ///   v &lt;= 108 (PS2 old): [UNK_07: 3 bytes][PlayerId: ushort][PlayerCount: ushort][IP: 4 bytes]
    ///                         [ScertId: uint][Port: uint][Pad: uint] = 23 bytes
    ///     (2012 SOCOM II MUIS capture confirms plen=23 for this version)
    ///   v &gt; 108 (newer):    [PlayerId: ushort][ScertId: uint][PlayerCount: ushort][IP: 4 bytes] = 12 bytes
    /// </summary>
    public static ScertPacket CreateConnectAcceptTcp(uint scertId, ushort playerId, ushort playerCount, IPAddress? clientIp, int mediusVersion = 108, ushort serverPort = 0)
    {
        byte[] ip = (clientIp ?? IPAddress.Any).MapToIPv4().GetAddressBytes();

        if (mediusVersion <= 108)
        {
            // Old PS2 format — 2012 MUIS capture shows plen=23 for this version.
            // Layout: UNK_07(3) + PlayerId(2) + PlayerCount(2) + IP(4) + ScertId(4) + Port(4) + Pad(4) = 23
            using var ms = new MemoryStream(23);
            using var bw = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);
            bw.Write(new byte[] { 0x01, 0x08, 0x10 }); // UNK_07          3 bytes
            bw.Write(playerId);                         // PlayerId         2 bytes LE
            bw.Write(playerCount);                      // PlayerCount      2 bytes LE
            ms.Write(ip, 0, 4);                         // IP               4 bytes NBO
            bw.Write(scertId);                          // ScertId          4 bytes LE
            bw.Write((uint)serverPort);                 // Port             4 bytes LE
            bw.Write((uint)0);                          // Pad              4 bytes
            return new ScertPacket
            {
                MessageType = RT_MSG_TYPE.RT_MSG_SERVER_CONNECT_ACCEPT_TCP,
                Payload     = ms.ToArray(),
            };
        }
        else
        {
            // New format
            using var ms = new MemoryStream(12);
            using var bw = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);
            bw.Write(playerId);     // 2 bytes LE
            bw.Write(scertId);      // 4 bytes LE
            bw.Write(playerCount);  // 2 bytes LE
            ms.Write(ip, 0, 4);     // 4 bytes NBO
            return new ScertPacket
            {
                MessageType = RT_MSG_TYPE.RT_MSG_SERVER_CONNECT_ACCEPT_TCP,
                Payload     = ms.ToArray(),
            };
        }
    }

    /// <summary>SERVER_CONNECT_COMPLETE — signals session is fully open.</summary>
    public static ScertPacket CreateConnectComplete() => new()
    {
        MessageType = RT_MSG_TYPE.RT_MSG_SERVER_CONNECT_COMPLETE,
        Payload     = BitConverter.GetBytes((ushort)0x0001),  // ARG1: ushort per Horizon
    };

    /// <summary>
    /// SERVER_CONNECT_REQUIRE — triggers CLIENT_CONNECT_TCP from the PS2 SCERT overlay.
    /// Old protocol (v &lt;= 108): sent from the CLIENT_CONNECT_TCP handler (new-proto path only).
    /// New protocol (v &gt; 108): sent after CLIENT_CONNECT_TCP; client replies with CLIENT_CONNECT_READY_REQUIRE.
    /// Payload is empty; the PS2 SCERT overlay reads only its global state, not the packet.
    /// </summary>
    public static ScertPacket CreateConnectRequire() => new()
    {
        MessageType = RT_MSG_TYPE.RT_MSG_SERVER_CONNECT_REQUIRE,
        Payload     = Array.Empty<byte>(),
    };

    /// <summary>SERVER_ECHO — used only on the new-protocol (v &gt; 108) post-connect path.</summary>
    public static ScertPacket CreateServerEcho() => new()
    {
        MessageType = RT_MSG_TYPE.RT_MSG_SERVER_ECHO,
        Payload     = Array.Empty<byte>(),
    };

    /// <summary>
    /// CLIENT_ECHO keepalive — byte-for-byte match of the 2012 retail SOCOM II MAS capture.
    ///
    /// The retail Medius server pings idle PS2 clients with a CLIENT_ECHO (0x05) carrying a
    /// single 0xA5 byte, encrypted under <see cref="CipherContext.RcClientSession"/>.
    /// SHA1(0xA5)[0..3] = 4F B8 CF EA; OR-ing the context-3 bits into byte[3] yields the
    /// constant hash 4F B8 CF 6A seen on every echo in the reference captures
    /// (Join_Medley / Join_US_East / Masquarr_logoff_SII).
    ///
    /// This replaces the old empty-payload SERVER_ECHO (0x1F) keepalive, which was the wrong
    /// message type/length/context — SOCOM II rejected it and popped "Disconnected from
    /// Network" on the persona screen the instant the keepalive fired.
    /// </summary>
    public static ScertPacket CreateClientEcho(byte[]? payload = null) => new()
    {
        MessageType = RT_MSG_TYPE.RT_MSG_CLIENT_ECHO,
        Payload     = payload ?? new byte[] { 0xA5 },
    };

    /// <summary>
    /// Mirror a client's CLIENT_ECHO back verbatim. The 2012 captures show the server
    /// replying to a C-&gt;S CLIENT_ECHO with the same CLIENT_ECHO (0x05) and identical
    /// hash — NOT a SERVER_ECHO. Send under <see cref="CipherContext.RcClientSession"/>.
    /// </summary>
    public static ScertPacket CreateEchoResponse(ReadOnlySpan<byte> echoData) => new()
    {
        MessageType = RT_MSG_TYPE.RT_MSG_CLIENT_ECHO,
        Payload     = echoData.ToArray(),
    };

    public static ScertPacket CreateForcedDisconnect(byte reason) => new()
    {
        MessageType = RT_MSG_TYPE.RT_MSG_SERVER_FORCED_DISCONNECT,
        Payload     = [reason],
    };

    public static ScertPacket CreateServerApp(byte[] mediusPayload) => new()
    {
        MessageType = RT_MSG_TYPE.RT_MSG_SERVER_APP,
        Payload     = mediusPayload,
    };

    /// <summary>
    /// RT_MSG_SERVER_CHEAT_QUERY (0x1D) — 13-byte challenge payload.
    /// The PS2 responds with a matching 0x1D packet; we ignore the response.
    /// </summary>
    public static ScertPacket CreateCheatQuery(byte[]? payload = null) => new()
    {
        MessageType = RT_MSG_TYPE.RT_MSG_SERVER_CHEAT_QUERY,
        Payload     = payload ?? new byte[13],
    };

    /// <summary>
    /// RT_MSG_SERVER_CHEAT_QUERY (0x1D) — 29-byte SALTED challenge for the in-lobby
    /// anti-cheat heartbeat. Layout is the authoritative Horizon RT.Models
    /// RT_MSG_SERVER_CHEAT_QUERY, confirmed against the 2012 retail acceptEULA.pcap
    /// (which streams a continuous plen=29 cheat-query exchange on the community screen):
    ///   [QueryType:1][SequenceId:4 LE][Address:4 LE][Length:4 LE][Salt:16]
    /// The 13-byte base is identical to <see cref="CreateCheatQuery"/> (the non-salted
    /// variant the MUIS login handshake accepts); the trailing 16-byte salt is what the
    /// in-game lobby anti-cheat requires (a SALTY_MD5 region-hash challenge). The PS2
    /// hashes mem[Address..Address+Length] salted with Salt and replies 0x1D; we ignore it.
    /// </summary>
    public static ScertPacket CreateSaltedCheatQuery(int sequenceId, uint address, int length, byte[] salt)
    {
        var payload = new byte[29];
        payload[0] = (byte)CheatQueryType.DME_SERVER_CHEAT_QUERY_SALTY_MD5_HASH; // 6
        BitConverter.GetBytes(sequenceId).CopyTo(payload, 1);  // SequenceId : int32 LE
        BitConverter.GetBytes(address).CopyTo(payload, 5);      // Address    : uint32 LE
        BitConverter.GetBytes(length).CopyTo(payload, 9);       // Length     : int32 LE
        Array.Copy(salt, 0, payload, 13, Math.Min(salt.Length, 16));
        return new()
        {
            MessageType = RT_MSG_TYPE.RT_MSG_SERVER_CHEAT_QUERY,
            Payload     = payload,
        };
    }

    /// <summary>
    /// RT_MSG_SERVER_CHEAT_QUERY (0x1D) RAW_MEMORY read: [QueryType 0][SequenceId:4][Address:4][Length:4] (13 B).
    /// The client answers with the same header followed by <paramref name="length"/> bytes of EE memory
    /// (horizon RT_MSG_SERVER_CHEAT_QUERY: Data = rest of the message). The MUIS login round already uses this
    /// query type (with length 0).
    /// </summary>
    public static ScertPacket CreateRawMemoryQuery(int sequenceId, uint address, int length)
    {
        var payload = new byte[13];
        payload[0] = (byte)CheatQueryType.DME_SERVER_CHEAT_QUERY_RAW_MEMORY;
        BitConverter.GetBytes(sequenceId).CopyTo(payload, 1);
        BitConverter.GetBytes(address).CopyTo(payload, 5);
        BitConverter.GetBytes(length).CopyTo(payload, 9);
        return new() { MessageType = RT_MSG_TYPE.RT_MSG_SERVER_CHEAT_QUERY, Payload = payload };
    }

    /// <summary>
    /// RT_MSG_SERVER_MEMORY_POKE (0x1E) — 14-byte payload.
    /// Sent once during the MUIS anti-cheat exchange (round 2), followed immediately
    /// by another CHEAT_QUERY in the same TCP write.
    /// </summary>
    public static ScertPacket CreateMemoryPoke(byte[]? payload = null) => new()
    {
        MessageType = RT_MSG_TYPE.RT_MSG_SERVER_MEMORY_POKE,
        Payload     = payload ?? new byte[14],
    };

    // -------------------------------------------------------------------------
    // Serialization
    // -------------------------------------------------------------------------

    /// <summary>
    /// Serialize this packet to bytes.
    /// If <see cref="Hash"/> is set (4 bytes), the packet is sent encrypted:
    ///   [type|0x80][len_lo][len_hi][hash:4][payload]
    /// Otherwise it is sent plaintext:
    ///   [type][len_lo][len_hi][payload]
    /// </summary>
    public byte[] Serialize()
    {
        // A longer payload would wrap the length field and desync the receiver's stream.
        if (Payload.Length > MaxPayloadLength)
            throw new InvalidOperationException($"{MessageType} payload of {Payload.Length} bytes exceeds the SCERT frame limit.");

        // Encrypted but empty: flag set, no hash (matches what the PS2 itself sends, e.g. "8F 00 00").
        if (Hash is { Length: EncryptedHashSize } && Payload.Length == 0)
            return [(byte)((byte)MessageType | 0x80), 0, 0];

        if (Hash is { Length: EncryptedHashSize })
        {
            var enc = new byte[HeaderSize + EncryptedHashSize + Payload.Length];
            enc[0] = (byte)((byte)MessageType | 0x80);
            enc[1] = (byte)(Payload.Length & 0xFF);
            enc[2] = (byte)((Payload.Length >> 8) & 0xFF);
            Buffer.BlockCopy(Hash, 0, enc, HeaderSize, EncryptedHashSize);
            Buffer.BlockCopy(Payload, 0, enc, HeaderSize + EncryptedHashSize, Payload.Length);
            return enc;
        }

        var result = new byte[HeaderSize + Payload.Length];
        result[0] = (byte)MessageType;
        result[1] = (byte)(Payload.Length & 0xFF);
        result[2] = (byte)((Payload.Length >> 8) & 0xFF);
        Buffer.BlockCopy(Payload, 0, result, HeaderSize, Payload.Length);
        return result;
    }

    // -------------------------------------------------------------------------
    // Deserialization
    // -------------------------------------------------------------------------

    /// <summary>
    /// Try to read one SCERT packet from <paramref name="buffer"/>.
    /// Returns null if not enough bytes yet; advances <paramref name="consumed"/>.
    /// </summary>
    public static ScertPacket? TryRead(byte[] buffer, int offset, int length, out int consumed)
    {
        consumed = 0;
        if (length < HeaderSize)
            return null;

        bool isEncrypted = (buffer[offset + 0] & 0x80) != 0;
        var  msgType     = (RT_MSG_TYPE)(buffer[offset + 0] & 0x7F);
        int  payloadLen  = buffer[offset + 1] | (buffer[offset + 2] << 8);

        // An encrypted frame with no payload has no hash: the PS2 sends a bare "8F 00 00" (encrypted
        // FLUSH). Reading 4 hash bytes for it swallows the start of the next frame and desyncs the stream
        // (seen on PCSX2 when a 24-player match started: the DME connection dropped).
        if (payloadLen == 0)
            isEncrypted = false;

        int totalSize = HeaderSize + payloadLen;
        if (isEncrypted)
            totalSize += EncryptedHashSize;

        if (length < totalSize)
            return null;

        byte[]? hash = null;
        int payloadOffset;
        if (isEncrypted)
        {
            hash = new byte[EncryptedHashSize];
            Buffer.BlockCopy(buffer, offset + HeaderSize, hash, 0, EncryptedHashSize);
            payloadOffset = offset + HeaderSize + EncryptedHashSize;
        }
        else
        {
            payloadOffset = offset + HeaderSize;
        }
        var payload = new byte[payloadLen];
        Buffer.BlockCopy(buffer, payloadOffset, payload, 0, payloadLen);

        consumed = totalSize;
        return new ScertPacket
        {
            MessageType = msgType,
            Payload     = payload,
            IsEncrypted = isEncrypted,
            Hash        = hash,
        };
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    // (No private helpers needed — factory methods build payloads inline)
}
