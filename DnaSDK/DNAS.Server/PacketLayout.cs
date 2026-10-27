using System;

namespace DNAS;

/// <summary>A named byte range within a complete, 40-byte-header DNAS packet.</summary>
public readonly struct PacketField
{
    public readonly string Name;
    public readonly int Offset;
    public readonly int Length;

    public PacketField(string name, int offset, int length)
    {
        Name = name;
        Offset = offset;
        Length = length;
    }

    public byte[] Read(byte[] packet)
    {
        if (packet == null || Offset < 0 || Length < 0 ||
            Offset > packet.Length || Length > packet.Length - Offset)
        {
            throw new ArgumentException("Packet does not contain this field.", nameof(packet));
        }

        return packet.AsSpan(Offset, Length).ToArray();
    }
}

/// <summary>
/// Wire layouts recovered from packet captures. Offsets include the 40-byte
/// header; extended packet families retain explicit unverified body labels.
/// </summary>
public static class PacketByteMap
{
    public static readonly PacketField Operation = new("Operation", 0, 4);
    public static readonly PacketField SessionHeader = new("Session/header metadata", 4, 32);
    public static readonly PacketField SessionMetadata = new("Session metadata (unresolved)", 4, 23);
    public static readonly PacketField SessionId = new("Server-assigned session ID", 27, 8);
    public static readonly PacketField SessionSuffix = new("Session suffix (unresolved)", 35, 1);
    public static readonly PacketField BodyLength = new("Big-endian body length", 36, 4);

    public static PacketField[] Fields(uint operation)
    {
        byte mode = Public.OperationMode(operation);
        uint command = Public.OperationCommand(operation);

        if ((mode == 0x90 || mode == 0x98) && Public.ToConnectOperation(operation) == Public.ServerConnect)
        {
            return WithBody(new PacketField(
                "Extended S1 body (289 bytes; layout unverified)", 40, 289));
        }

        if (mode == 0x22 && command == 0x8007)
            return WithBody(new PacketField("0122 result byte (observed 01)", 40, 1));

        if (mode == 0xA2 && command == 0x8007)
            return WithBody(new PacketField("01A2 extended result (unmapped)", 40, 339));

        return CanonicalFields(operation);
    }

    private static PacketField[] WithBody(PacketField body)
    {
        return new[] { Operation, SessionMetadata, SessionId, SessionSuffix, BodyLength, body };
    }

    private static PacketField[] CanonicalFields(uint operation)
    {
        return Public.ToConnectOperation(operation) switch
        {
            Public.ClientConnect => WithBody(
                new PacketField("Initial parameter", 40, 4),
                new PacketField("Lookup identifier", 44, 8),
                new PacketField("Wrapped client proofs", 52, 256)),

            Public.ServerConnect => WithBody(
                new PacketField("Challenge A", 40, 8),
                new PacketField("DES challenge", 48, 16),
                new PacketField("Challenge B", 64, 8),
                new PacketField("RSA signed operand", 72, 128),
                new PacketField("Nested encrypted field", 200, 32),
                new PacketField("S1 remainder", 232, 96)),

            Public.ClientProof => WithBody(
                new PacketField("DES challenge answer", 40, 16),
                new PacketField("RSA decoded data", 56, 117),
                new PacketField("Reserved zeros", 173, 11)),

            Public.ServerProof => WithBody(
                new PacketField("02 01 marker", 40, 2),
                new PacketField("Second server data", 42, 128)),

            Public.ClientFinal => WithBody(
                new PacketField("Client final parameter", 40, 4)),

            Public.ServerFinal => WithBody(
                new PacketField("Result flag", 40, 1),
                new PacketField("Result size", 41, 4),
                new PacketField("Result bytes", 45, 32)),

            _ => throw new ArgumentOutOfRangeException(nameof(operation),
                "Not one of the six captured DNAS operations.")
        };
    }

    private static PacketField[] WithBody(params PacketField[] bodyFields)
    {
        PacketField[] fields = new PacketField[5 + bodyFields.Length];
        fields[0] = Operation;
        fields[1] = SessionMetadata;
        fields[2] = SessionId;
        fields[3] = SessionSuffix;
        fields[4] = BodyLength;
        Array.Copy(bodyFields, 0, fields, 5, bodyFields.Length);
        return fields;
    }

    /// <summary>
    /// Unwrapped C1's four proofs are stored A/B/D/C, not A/B/C/D producer order.
    /// </summary>
    public static PacketField[] FirstRequestPlaintextFields()
    {
        return new[]
        {
            new PacketField("Proof A: CDVD samples", 0, 40),
            new PacketField("Proof B: initialized working field", 40, 56),
            new PacketField("Proof D: executable serial", 96, 40),
            new PacketField("Proof C: disc ReadKey identity", 136, 32),
            new PacketField("Reserved zeros", 168, 64),
            new PacketField("PS2 random material", 232, 16),
            new PacketField("Fixed tail", 248, 8)
        };
    }

    /// <summary>Rejects missing, overlapping, or extra fields in the selected map.</summary>
    public static void ValidateFieldCoverage(Packet packet)
    {
        int nextOffset = 0;
        foreach (PacketField field in Fields(packet.Operation))
        {
            if (field.Offset != nextOffset)
            {
                throw new InvalidOperationException(
                    $"Field {field.Name} breaks packet coverage at 0x{nextOffset:X}.");
            }

            nextOffset += field.Length;
        }

        if (nextOffset != packet.Raw.Length)
            throw new InvalidOperationException("The PS2 byte map does not cover the complete packet.");
    }
}
