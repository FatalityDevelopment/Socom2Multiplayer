using System;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>Wire framing and command identifiers for the DNAS protocol.</summary>
public static class Public
{
    public const int HeaderSize = 40;
    public const int HttpsPort = 443;
    public const uint ClientConnect = 0x01080000;
    public const uint ServerConnect = 0x01080005;
    public const uint ClientProof = 0x01080001;
    public const uint ServerProof = 0x01080006;
    public const uint ClientFinal = 0x01088008;
    public const uint ServerFinal = 0x0108800D;
    // The four on-wire bytes are [version=01][mode][command BE16].
    // Only recorded mode/command combinations are mapped to the normalized
    // six-message crypto API. An unknown command is NEVER accepted merely
    // because its first byte is 01.
    public const uint DiscClientConnect = 0x01220000;
    public const uint DiscServerConnect = 0x01220005; // not present in the replay corpus: experimental
    public const uint DiscClientProof = 0x01220001;
    public const uint DiscServerProof = 0x01220006;
    public const uint DiscClientFinal = 0x01228008; // older experimental hypothesis, not corpus-confirmed
    public const uint DiscServerFinal = 0x0122800D; // older experimental hypothesis, not corpus-confirmed

    public static bool IsDiscOperation(uint op) => OperationMode(op) is 0x22 or 0xA2;
    public static byte OperationMode(uint op) => (byte)(op >> 16);
    public static ushort OperationCommand(uint op) => (ushort)op;
    public static bool IsNormalCryptoMode(byte mode) => mode is 0x08 or 0x10 or 0x18 or 0x22;

    public static uint ToConnectOperation(uint op)
    {
        if ((byte)(op >> 24) != 1) return op;
        byte mode = OperationMode(op);
        ushort command = OperationCommand(op);
        if (mode == 0x08 || mode == 0x22)
            return command switch
            {
                0x0000 => ClientConnect, 0x0005 => ServerConnect,
                0x0001 => ClientProof, 0x0006 => ServerProof,
                0x8008 => ClientFinal, 0x800D => ServerFinal,
                _ => op
            };
        if (mode is 0x10 or 0x18 or 0x90 or 0x98)
            return command switch
            {
                0x0000 => ClientConnect, 0x0005 => ServerConnect,
                0x8001 => ClientProof, 0x8006 => ServerProof,
                _ => op
            };
        // 0x22/0xA2 additionally carry an observed 0x8003/0x8007 exchange,
        // which is NOT the same state as the standard C3/S3.
        return op;
    }

    public static uint FromConnectOperation(uint canonical, byte mode)
    {
        ushort command = (ushort)canonical;
        if (mode is 0x10 or 0x18 or 0x90 or 0x98)
        {
            if (canonical is ClientConnect or ServerConnect) { }
            else if (canonical == ClientProof) command = 0x8001;
            else if (canonical == ServerProof) command = 0x8006;
            else throw new FormatException($"No replay-confirmed phase for mode 0x{mode:X2}: 0x{canonical:X8}.");
        }
        else if (mode is not (0x08 or 0x22)) throw new FormatException($"Unsupported DNAS crypto mode 0x{mode:X2}.");
        return ((uint)1 << 24) | ((uint)mode << 16) | command;
    }

    // Compatibility overload retained for existing callers.
    public static uint FromConnectOperation(uint op, bool disc) => FromConnectOperation(op, disc ? (byte)0x22 : (byte)0x08);

    public static byte[] RewriteOperation(byte[] packet, uint operation)
    {
        byte[] copy = (byte[])packet.Clone();
        _ = PS2BodyLength(operation);
        copy[0] = (byte)(operation >> 24);
        copy[1] = (byte)(operation >> 16);
        copy[2] = (byte)(operation >> 8);
        copy[3] = (byte)operation;
        _ = new Packet(copy);
        return copy;
    }

    public static int PS2BodyLength(uint operation)
    {
        if ((byte)(operation >> 24) != 1) throw new FormatException($"Unrecognized DNAS protocol version in 0x{operation:X8}.");
        byte mode = OperationMode(operation);
        ushort command = OperationCommand(operation);
        // Recorded 0x22/0xA2 final exchanges are NOT 0108's four-byte C3/37-byte S3.
        if (mode == 0x22 && command == 0x8003) return 4; // body length inferred from command's recorded phase, validate independently
        if (mode == 0x22 && command == 0x8007) return 1;
        if (mode == 0xA2 && command == 0x8003) return 4;
        if (mode == 0xA2 && command == 0x8007) return 339;
        if (mode == 0xA2 && command == 0x0001) return 144;
        if (mode == 0xA2 && command == 0x0006) return 130;
        uint normalized = ToConnectOperation(operation);
        if (normalized == ClientConnect) return 268;
        if (normalized == ServerConnect) return mode is 0x90 or 0x98 ? 289 : 288;
        if (normalized == ClientProof) return 144;
        if (normalized == ServerProof) return 130;
        if (normalized == ClientFinal) return 4;
        if (normalized == ServerFinal) return 37;
        throw new FormatException($"Unmapped DNAS mode 0x{mode:X2} / command 0x{command:X4} (operation 0x{operation:X8}).");
    }
    public const int RsaExponent = 65537;
    public static readonly byte[] FixedTrailer8 = Convert.FromHexString("5A0698774DEAE638");

    public static byte[] ParseDnasId(string id)
    {
        if (string.IsNullOrWhiteSpace(id)) throw new ArgumentException("Disc DNAS ID cannot be empty.", nameof(id));
        string value = id.Replace("-", "").Replace(":", "").Replace(" ", "");
        if (value.Length != 10) throw new ArgumentException("Expected five DNAS-ID bytes (e.g. 30-61-04-30-FC).", nameof(id));
        try { return Convert.FromHexString(value); }
        catch (FormatException ex) { throw new ArgumentException("Invalid hex DNAS ID.", nameof(id), ex); }
    }
}
