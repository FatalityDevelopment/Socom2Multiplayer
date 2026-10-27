using System;
using System.Text;

namespace DNAS;

/// <summary>
/// PS2-side inputs recovered from the *executed code* of the four DNAS
/// proof-producer helpers. These are pre-encryption inputs, not whole proofs.
/// </summary>
public static class ProofInputs
{
    /// <summary>
    /// Producer D (0x0052F008-0x0052F070) copies 4 executable-prefix letters,
    /// skips '_', copies 3 digits, skips '.', and copies 2 digits. This is the
    /// 9-byte input to the common DNAS engine, not its 40-byte encrypted output.
    /// </summary>
    public static byte[] FromGameSerial(string gameSerial)
    {
        string serial = Identity.NormalizeGameSerial(gameSerial);
        return Encoding.ASCII.GetBytes(serial[..4] + serial.Substring(5, 5));
    }

    /// <summary>
    /// Producer A (0x0052E2FC-0x0052E35C) builds 16 input bytes from
    /// eight bytes returned in its first stack buffer and three bytes in the
    /// second buffer. The last eight bytes are explicitly cleared to zero.
    /// The buffers are populated by two distinct DNAS CDVDFSV RPC results:
    /// 0x24 ReadGUID (eight bytes) and 0x26 ReadModelID (four significant
    /// bytes). They are not clock samples.
    /// </summary>
    public static byte[] ComposeA16(ReadOnlySpan<byte> source8, ReadOnlySpan<byte> source3)
    {
        if (source8.Length != 8 || source3.Length != 3) throw new ArgumentException("Producer A requires eight source bytes and three secondary bytes.");
        byte[] value = new byte[16];
        value[0] = source3[2];
        value[1] = source3[1];
        value[2] = source3[0];
        value[3] = source8[0];
        value[4] = source8[7];
        value[5] = source8[6];
        value[6] = source8[5];
        value[7] = source8[4];
        return value;
    }

    /// <summary>
    /// Producer A copies eight bytes from RPC 0x24 and reads the first three
    /// bytes of the eight-byte copied RPC 0x26 buffer. The 0x26 operation
    /// itself defines only a four-byte ModelID; any additional RPC buffer
    /// bytes must not be inferred from the i.Link ID.
    /// </summary>
    public static byte[] FromCdvdResults(ReadOnlySpan<byte> cdvdRead24, ReadOnlySpan<byte> cdvdRead26)
    {
        if (cdvdRead24.Length != 8 || (cdvdRead26.Length != 4 && cdvdRead26.Length != 8)) throw new ArgumentException("Expected eight GUID bytes and four ModelID bytes (or its eight-byte RPC copy).");
        return ComposeA16(cdvdRead24, cdvdRead26[..3]);
    }


    /// <summary>
    /// Producer B's observed successful path writes 32 bytes of 0xFF at
    /// 0x0052E6DC-0x0052E6FC. Later helper operations are separate.
    /// </summary>
    public static byte[] InitialB32()
    {
        byte[] result = new byte[32];
        Array.Fill(result, (byte)0xFF);
        return result;
    }

    /// <summary>
    /// Producer C (0x0052EB80-0x0052EBAC) expands four returned bytes into
    /// [high nibble of byte3, low nibble of byte3, byte2, byte1, byte0].
    /// The four bytes come from the first four bytes of the five-byte CDVD
    /// ReadKey result copied by 0x0052E940 (at EE 0x001CA8C4 in this run).
    /// </summary>
    public static byte[] ExpandC5(ReadOnlySpan<byte> raw4)
    {
        if (raw4.Length != 4) throw new ArgumentException("The original helper accepts four source bytes.", nameof(raw4));
        return new byte[] { (byte)(raw4[3] >> 4), (byte)(raw4[3] & 15), raw4[2], raw4[1], raw4[0] };
    }

    /// <summary>
    /// Producer C fetches five bytes from the CDVD ReadKey result at +4,
    /// but the next helper constructs its five-byte input from the first four
    /// via nibble expansion. Byte 4 of the supplied disc ID is not copied by
    /// this particular conversion; its other uses remain under investigation.
    /// </summary>
    public static byte[] FromDiscDnasId(ReadOnlySpan<byte> discId5)
    {
        if (discId5.Length != 5) throw new ArgumentException("The CDVD ReadKey DNAS identifier contains five bytes.", nameof(discId5));
        return ExpandC5(discId5[..4]);
    }
}
