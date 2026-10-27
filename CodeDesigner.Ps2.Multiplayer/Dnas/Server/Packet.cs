using System;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>
/// One structurally recognized PS2 DNAS binary message (the HTTPS body).
/// Header bytes 0x04..0x23 are preserved verbatim; their unidentified subfields
/// are never replaced with a generic packet/session abstraction.
/// </summary>

public sealed class Packet
{
    public readonly byte[] Raw;
    public readonly uint Operation;
    public readonly DnasOperation OperationFields;
    public readonly byte[] Header;
    public readonly byte[] Payload;
    public readonly byte[] SessionId;

    public Packet(byte[] raw)
    {
        if (raw == null || raw.Length < 40) throw new ArgumentException("PS2 DNAS message must have its 40-byte header.", nameof(raw));
        uint op = ((uint)raw[0] << 24) | ((uint)raw[1] << 16) | ((uint)raw[2] << 8) | raw[3];
        int expected = Public.PS2BodyLength(op);
        int declared = (raw[36] << 24) | (raw[37] << 16) | (raw[38] << 8) | raw[39];
        bool observedExtendedA2 = op == 0x01A28007 && (declared == 339 || declared == 560);
        bool variableDiscFinalRequest = op == 0x01228003 && declared >= 0 && declared <= 1024;
        if (declared < 0 || raw.Length != 40 + declared ||
            (!observedExtendedA2 && !variableDiscFinalRequest && declared != expected))
            throw new FormatException($"DNAS operation 0x{op:X8}: body length {declared} is not supported (expected {expected}).");
        if (Public.ToConnectOperation(op) == Public.ClientConnect && !raw.AsSpan(40, 4).SequenceEqual(new byte[] { 0, 2, 0, 5 }))
            throw new FormatException("Unexpected initial PS2 DNAS parameter at 0x28.");
        if (Public.ToConnectOperation(op) == Public.ServerProof && (raw[40] != 2 || raw[41] != 1))
            throw new FormatException("Unexpected PS2 DNAS second-reply marker.");
        // The four-byte C3 parameter is client-supplied session data.
        // Validate the packet state and binding, not an example payload.
        if (Public.ToConnectOperation(op) == Public.ServerFinal && !raw.AsSpan(41, 4).SequenceEqual(new byte[] { 0, 0, 0, 32 }))
            throw new FormatException("Unexpected PS2 DNAS final result length field.");
        Raw = (byte[])raw.Clone();
        Operation = op;
        OperationFields = new DnasOperation(op);
        Header = Raw.AsSpan(0, 40).ToArray();
        Payload = Raw.AsSpan(40).ToArray();
        SessionId = Raw.AsSpan(27, 8).ToArray();
    }

    /// <summary>Internal protocol serializer; caller cannot select arbitrary opcodes or lengths.</summary>
    internal static Packet Make(byte[] header40, uint operation, byte[] payload)
    {
        Guard.Size(header40, 40, nameof(header40));
        if (payload == null || (payload.Length != Public.PS2BodyLength(operation) &&
            !(operation == 0x01A28007 && payload.Length == 560) &&
            !(operation == 0x01228003 && payload.Length <= 1024)))
            throw new ArgumentException($"Invalid PS2 DNAS body length for 0x{operation:X8}.", nameof(payload));
        byte[] result = new byte[40 + payload.Length];
        Buffer.BlockCopy(header40, 0, result, 0, 40);
        result[0] = (byte)(operation >> 24);
        result[1] = (byte)(operation >> 16);
        result[2] = (byte)(operation >> 8);
        result[3] = (byte)operation;
        result[36] = (byte)(payload.Length >> 24);
        result[37] = (byte)(payload.Length >> 16);
        result[38] = (byte)(payload.Length >> 8);
        result[39] = (byte)payload.Length;
        Buffer.BlockCopy(payload, 0, result, 40, payload.Length);
        return new Packet(result);
    }
}
