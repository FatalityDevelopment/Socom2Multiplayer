using System.Text;

namespace CodeDesigner.Ps2.Multiplayer.Protocol;

/// <summary>
/// Reads Medius binary fields from a byte buffer using the endianness that the PS2 sends.
/// All multi-byte integers are little-endian.
/// Strings are null-terminated ASCII, padded to a fixed length.
/// </summary>
public class MediusReader
{
    private readonly byte[] _data;
    private int _pos;

    public MediusReader(byte[] data) { _data = data; _pos = 0; }
    public MediusReader(ReadOnlySpan<byte> data) { _data = data.ToArray(); _pos = 0; }

    public int Position => _pos;
    public int Remaining => _data.Length - _pos;

    // All reads are bounds-safe: if the field runs past the end of the buffer the cursor
    // still advances by the field width (so later fields stay aligned) but the missing
    // bytes read as zero. A short or unexpected message must never throw — an exception
    // here kills the whole TCP connection and drops every message queued behind it
    // (this is exactly what crashed the MLS lobby flow: PlayerInfo's 64-byte read ran off
    // a 44-byte payload → IndexOutOfRange → disconnect at the community screen).
    private bool InBounds(int count) => _pos >= 0 && _pos + count <= _data.Length;

    public byte   ReadByte()  { var v = InBounds(1) ? _data[_pos] : (byte)0; _pos++; return v; }
    public sbyte  ReadSByte() { return (sbyte)ReadByte(); }

    public short  ReadInt16()
    {
        var v = InBounds(2) ? (short)(_data[_pos] | (_data[_pos + 1] << 8)) : (short)0;
        _pos += 2;
        return v;
    }

    public ushort ReadUInt16()
    {
        var v = InBounds(2) ? (ushort)(_data[_pos] | (_data[_pos + 1] << 8)) : (ushort)0;
        _pos += 2;
        return v;
    }

    public int ReadInt32()
    {
        var v = InBounds(4)
            ? _data[_pos] | (_data[_pos + 1] << 8) | (_data[_pos + 2] << 16) | (_data[_pos + 3] << 24)
            : 0;
        _pos += 4;
        return v;
    }

    public uint ReadUInt32()
    {
        var v = InBounds(4)
            ? (uint)(_data[_pos] | (_data[_pos + 1] << 8) | (_data[_pos + 2] << 16) | (_data[_pos + 3] << 24))
            : 0u;
        _pos += 4;
        return v;
    }

    /// <summary>Read a fixed-length null-terminated ASCII string (bounds-safe).</summary>
    public string ReadString(int maxLength)
    {
        // Clamp the readable window to what's actually in the buffer.
        int avail   = Math.Max(0, Math.Min(maxLength, _data.Length - _pos));
        int nullIdx = -1;
        for (int i = 0; i < avail; i++)
        {
            if (_data[_pos + i] == 0) { nullIdx = i; break; }
        }
        int strLen = nullIdx >= 0 ? nullIdx : avail;
        var result = strLen > 0 ? Encoding.ASCII.GetString(_data, _pos, strLen) : string.Empty;
        _pos += maxLength;   // advance the full field width even if it ran past the end
        return result;
    }

    public byte[] ReadBytes(int count)
    {
        var v = new byte[count];
        int n = Math.Max(0, Math.Min(count, _data.Length - _pos));
        if (n > 0) Buffer.BlockCopy(_data, _pos, v, 0, n);
        _pos += count;
        return v;
    }

    public void Skip(int count) { _pos += count; }
}

/// <summary>
/// Writes Medius binary fields in the encoding expected by the PS2 client.
/// </summary>
public class MediusWriter
{
    private readonly MemoryStream _ms;
    private readonly BinaryWriter _bw;

    public MediusWriter()
    {
        _ms = new MemoryStream();
        _bw = new BinaryWriter(_ms, Encoding.ASCII, leaveOpen: true);
    }

    public void Write(byte v)   => _bw.Write(v);
    public void Write(sbyte v)  => _bw.Write(v);
    public void Write(short v)  => _bw.Write(v);
    public void Write(ushort v) => _bw.Write(v);
    public void Write(int v)    => _bw.Write(v);
    public void Write(uint v)   => _bw.Write(v);

    /// <summary>Write a fixed-length null-terminated ASCII string (padded with 0x00).</summary>
    public void WriteString(string s, int maxLength)
    {
        var encoded = Encoding.ASCII.GetBytes(s ?? string.Empty);
        int writeLen = Math.Min(encoded.Length, maxLength - 1);
        _bw.Write(encoded, 0, writeLen);
        // Pad with zeroes to fill the fixed-length slot
        for (int i = writeLen; i < maxLength; i++)
            _bw.Write((byte)0);
    }

    public void Write(byte[] data) => _bw.Write(data);

    public void WritePadding(int count)
    {
        for (int i = 0; i < count; i++)
            _bw.Write((byte)0);
    }

    public byte[] ToArray()
    {
        _bw.Flush();
        return _ms.ToArray();
    }
}
