using System;
using System.Buffers.Binary;

namespace DNAS;

/// <summary>
/// Common 40-byte DNAS packet header. All wire integers use big-endian order.
/// Unknown metadata is retained byte-for-byte, not decoded speculatively.
/// </summary>
public sealed class DnasHeader
{
    public readonly uint Operation;
    public readonly byte[] Metadata23;
    public readonly byte[] SessionId8;
    public readonly byte Suffix;
    public readonly int BodyLength;

    internal DnasHeader(uint operation, byte[] metadata23, byte[] sessionId8, byte suffix, int bodyLength)
    {
        Guard.Size(metadata23, 23, nameof(metadata23));
        Guard.Size(sessionId8, 8, nameof(sessionId8));

        if (bodyLength < 0 || bodyLength > 1024 * 1024)
            throw new FormatException("DNAS body exceeds supported bounds.");

        Operation = operation;
        Metadata23 = (byte[])metadata23.Clone();
        SessionId8 = (byte[])sessionId8.Clone();
        Suffix = suffix;
        BodyLength = bodyLength;
    }

    public static DnasHeader Read(ReadOnlySpan<byte> wire)
    {
        if (wire.Length < 40)
            throw new FormatException("DNAS header is shorter than 40 bytes.");

        return new DnasHeader(BinaryPrimitives.ReadUInt32BigEndian(wire[..4]), wire.Slice(4, 23).ToArray(), wire.Slice(27, 8).ToArray(), wire[35], BinaryPrimitives.ReadInt32BigEndian(wire.Slice(36, 4)));
    }

    public byte[] Write()
    {
        byte[] header = new byte[40];
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(0, 4), Operation);
        Metadata23.CopyTo(header, 4);
        SessionId8.CopyTo(header, 27);
        header[35] = Suffix;
        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(36, 4), BodyLength);
        return header;
    }
}

/// <summary>
/// Base for typed DNAS messages. Transport deals with serialized bytes;
/// protocol code works with explicit C1/S1/C2/S2/C3/S3 message fields.
/// </summary>
public abstract class DnasMessage
{
    public readonly DnasHeader Header;

    protected DnasMessage(DnasHeader header)
    {
        Header = header;
    }

    public abstract byte[] Body();

    public byte[] Serialize()
    {
        byte[] body = Body();
        if (body.Length != Header.BodyLength)
            throw new FormatException("DNAS structured body/header length mismatch.");

        byte[] wire = new byte[40 + body.Length];
        Header.Write().CopyTo(wire, 0);
        body.CopyTo(wire, 40);
        return wire;
    }
}

/// <summary>Initial request: 4-byte parameter, 8-byte lookup ID, 256-byte wrapped proofs.</summary>
public sealed class C1Packet : DnasMessage
{
    public readonly uint InitialParameter;
    public readonly byte[] LookupId8;
    public readonly byte[] WrappedProofs256;

    public C1Packet(DnasHeader header, byte[] body) : base(header)
    {
        Guard.Size(body, 268, nameof(body));

        InitialParameter = BinaryPrimitives.ReadUInt32BigEndian(body.AsSpan(0, 4));
        LookupId8 = body.AsSpan(4, 8).ToArray();
        WrappedProofs256 = body.AsSpan(12, 256).ToArray();

        if (InitialParameter != 0x00020005)
            throw new FormatException("Unexpected C1 initial parameter.");
    }

    public override byte[] Body()
    {
        byte[] body = new byte[268];
        BinaryPrimitives.WriteUInt32BigEndian(body.AsSpan(0, 4), InitialParameter);
        LookupId8.CopyTo(body, 4);
        WrappedProofs256.CopyTo(body, 12);
        return body;
    }
}

/// <summary>First server reply: an encrypted 288-byte S1 body.</summary>
public sealed class S1Packet : DnasMessage
{
    public readonly byte[] Ciphertext288;

    public S1Packet(DnasHeader header, byte[] body) : base(header)
    {
        Guard.Size(body, 288, nameof(body));
        Ciphertext288 = (byte[])body.Clone();
    }

    public override byte[] Body() => (byte[])Ciphertext288.Clone();
}

/// <summary>
/// The decrypted S1 layout is A8 + DES16 + B8 + RSA128 + nested32 + tail96.
/// The 32-byte nested field and the metadata retain unresolved semantics.
/// </summary>
public sealed class S1Plaintext
{
    public readonly byte[] ChallengeA8;
    public readonly byte[] DesChallenge16;
    public readonly byte[] ChallengeB8;
    public readonly byte[] Signature128;
    public readonly byte[] NestedField32;
    public readonly byte[] Tail96;

    public S1Plaintext(ReadOnlySpan<byte> plain)
    {
        if (plain.Length != 288)
            throw new FormatException("Decrypted S1 must be 288 bytes.");

        ChallengeA8 = plain.Slice(0, 8).ToArray();
        DesChallenge16 = plain.Slice(8, 16).ToArray();
        ChallengeB8 = plain.Slice(24, 8).ToArray();
        Signature128 = plain.Slice(32, 128).ToArray();
        NestedField32 = plain.Slice(160, 32).ToArray();
        Tail96 = plain.Slice(192, 96).ToArray();
    }

    public byte[] Serialize()
    {
        byte[] body = new byte[288];
        ChallengeA8.CopyTo(body, 0);
        DesChallenge16.CopyTo(body, 8);
        ChallengeB8.CopyTo(body, 24);
        Signature128.CopyTo(body, 32);
        NestedField32.CopyTo(body, 160);
        Tail96.CopyTo(body, 192);
        return body;
    }
}

/// <summary>Client answer: 16-byte DES result, 117 RSA-decoded bytes, 11 reserved bytes.</summary>
public sealed class C2Packet : DnasMessage
{
    public readonly byte[] DesAnswer16;
    public readonly byte[] RsaMessage117;
    public readonly byte[] Reserved11;

    public C2Packet(DnasHeader header, byte[] body) : base(header)
    {
        Guard.Size(body, 144, nameof(body));
        DesAnswer16 = body.AsSpan(0, 16).ToArray();
        RsaMessage117 = body.AsSpan(16, 117).ToArray();
        Reserved11 = body.AsSpan(133, 11).ToArray();
    }

    public override byte[] Body()
    {
        byte[] body = new byte[144];
        DesAnswer16.CopyTo(body, 0);
        RsaMessage117.CopyTo(body, 16);
        Reserved11.CopyTo(body, 133);
        return body;
    }
}

/// <summary>Second server reply: 02 01 marker followed by 128 opaque bytes.</summary>
public sealed class S2Packet : DnasMessage
{
    public readonly byte[] Opaque128;

    public S2Packet(DnasHeader header, byte[] body) : base(header)
    {
        Guard.Size(body, 130, nameof(body));
        if (body[0] != 2 || body[1] != 1)
            throw new FormatException("Invalid S2 0201 marker.");

        Opaque128 = body.AsSpan(2, 128).ToArray();
    }

    public override byte[] Body()
    {
        byte[] body = new byte[130];
        body[0] = 2;
        body[1] = 1;
        Opaque128.CopyTo(body, 2);
        return body;
    }
}

/// <summary>Final client request, containing a four-byte game-supplied parameter.</summary>
public sealed class C3Packet : DnasMessage
{
    public readonly uint ClientParameter;

    public C3Packet(DnasHeader header, byte[] body) : base(header)
    {
        Guard.Size(body, 4, nameof(body));
        ClientParameter = BinaryPrimitives.ReadUInt32BigEndian(body);
    }

    public override byte[] Body()
    {
        byte[] body = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(body, ClientParameter);
        return body;
    }
}

/// <summary>Final server result: one flag, 32-bit result length, 32-byte payload.</summary>
public sealed class S3Packet : DnasMessage
{
    public readonly byte ResultFlag;
    public readonly byte[] Result32;

    public S3Packet(DnasHeader header, byte[] body) : base(header)
    {
        Guard.Size(body, 37, nameof(body));
        ResultFlag = body[0];

        if (BinaryPrimitives.ReadInt32BigEndian(body.AsSpan(1, 4)) != 32)
            throw new FormatException("S3 result length must be 32.");

        Result32 = body.AsSpan(5, 32).ToArray();
    }

    public override byte[] Body()
    {
        byte[] body = new byte[37];
        body[0] = ResultFlag;
        BinaryPrimitives.WriteInt32BigEndian(body.AsSpan(1, 4), 32);
        Result32.CopyTo(body, 5);
        return body;
    }
}

/// <summary>Observed d-connect 8003/8007 final packet with a mode-specific body.</summary>
public sealed class DConnectFinalPacket : DnasMessage
{
    public readonly byte[] Opaque;

    public DConnectFinalPacket(DnasHeader header, byte[] body) : base(header)
    {
        Opaque = (byte[])body.Clone();
    }

    public override byte[] Body() => (byte[])Opaque.Clone();
}

/// <summary>Parses known wire opcodes into their corresponding typed packet structures.</summary>
public static class DnasPackets
{
    public static DnasMessage Parse(byte[] wire)
    {
        // Keep the original framing checks, which also recognize the observed
        // alternative 0122 and extended-family lengths.
        Packet packet = new(wire);
        DnasHeader header = DnasHeader.Read(packet.Raw);

        if (packet.Operation is 0x01228003 or 0x01228007)
            return new DConnectFinalPacket(header, packet.Payload);

        uint canonicalOperation = Public.ToConnectOperation(packet.Operation);
        return canonicalOperation switch
        {
            Public.ClientConnect => new C1Packet(header, packet.Payload),
            Public.ServerConnect => new S1Packet(header, packet.Payload),
            Public.ClientProof => new C2Packet(header, packet.Payload),
            Public.ServerProof => new S2Packet(header, packet.Payload),
            Public.ClientFinal => new C3Packet(header, packet.Payload),
            Public.ServerFinal => new S3Packet(header, packet.Payload),
            _ => throw new NotSupportedException($"DNAS operation 0x{packet.Operation:X8} has no defined typed packet.")
        };
    }
}
