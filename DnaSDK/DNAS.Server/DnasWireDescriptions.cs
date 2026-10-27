// Related protocol definitions maintained together.
namespace DNAS
{
using System;
using System.Buffers.Binary;

public readonly struct DnasWirePacket
{
    public readonly ReadOnlyMemory<byte> Raw;
    public readonly bool HasCompleteHeader;
    public readonly uint Operation;
    public readonly int DeclaredBodyLength;
    public readonly int ActualBodyLength;
    public readonly ReadOnlyMemory<byte> HeaderMetadata;
    public readonly ReadOnlyMemory<byte> SessionId;
    public readonly byte HeaderSuffix;
    public readonly ReadOnlyMemory<byte> Body;

    public DnasWirePacket(byte[] packet)
    {
        if (packet == null) throw new ArgumentNullException(nameof(packet));
        Raw = new ReadOnlyMemory<byte>((byte[])packet.Clone());
        HasCompleteHeader = Raw.Length >= 40;
        Operation = Raw.Length >= 4 ? BinaryPrimitives.ReadUInt32BigEndian(Raw.Span[..4]) : 0;
        DeclaredBodyLength = HasCompleteHeader ? BinaryPrimitives.ReadInt32BigEndian(Raw.Span.Slice(36, 4)) : -1;
        ActualBodyLength = HasCompleteHeader ? Raw.Length - 40 : 0;
        HeaderMetadata = HasCompleteHeader ? Raw.Slice(4, 23) : ReadOnlyMemory<byte>.Empty;
        SessionId = HasCompleteHeader ? Raw.Slice(27, 8) : ReadOnlyMemory<byte>.Empty;
        HeaderSuffix = HasCompleteHeader ? Raw.Span[35] : (byte)0;
        Body = HasCompleteHeader ? Raw.Slice(40) : ReadOnlyMemory<byte>.Empty;
    }

    public bool BodyLengthMatches => HasCompleteHeader && DeclaredBodyLength >= 0 && DeclaredBodyLength == ActualBodyLength;
    public string WireSessionId => HasCompleteHeader ? Convert.ToHexString(SessionId.Span) : "<no header>";
    public DnasOperation OperationFields => new(Operation);
    public string TypeName => Operation switch
    {
        0x01228003 => "0122 / client terminal request (body not mapped)",
        0x01228007 => "0122 / one-byte server result",
        0x01A28003 => "01A2 / extended terminal request",
        0x01A28007 => "01A2 / extended terminal response",
        _ => CanonicalTypeName()
    };
    private string CanonicalTypeName() => Public.ToConnectOperation(Operation) switch
    {
        Public.ClientConnect => "C1 / client connect",
        Public.ServerConnect => "S1 / server challenge",
        Public.ClientProof => "C2 / client proof",
        Public.ServerProof => "S2 / server proof",
        Public.ClientFinal => "C3 / client final",
        Public.ServerFinal => "S3 / server result",
        _ => "UNKNOWN"
    };

    public bool HasKnownOperation => Public.ToConnectOperation(Operation) is Public.ClientConnect or Public.ServerConnect or Public.ClientProof
        or Public.ServerProof or Public.ClientFinal or Public.ServerFinal;
}
}

namespace DNAS
{
public readonly struct DnasOperation
{
    public readonly byte Version;
    public readonly byte Mode;
    public readonly ushort Command;
    public readonly ushort Message;
    public readonly bool Flag8000;
    public DnasOperation(uint raw)
    {
        Version = (byte)(raw >> 24);
        Mode = (byte)(raw >> 16);
        Command = (ushort)raw;
        Flag8000 = (Command & 0x8000) != 0;
        Message = (ushort)(Command & 0x7FFF);
    }
    public override string ToString() => $"version=0x{Version:X2}, mode=0x{Mode:X2}, command=0x{Command:X4} (message={Message}, flag8000={Flag8000})";
}
}

