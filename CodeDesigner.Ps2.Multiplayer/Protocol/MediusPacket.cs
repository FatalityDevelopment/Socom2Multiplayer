namespace CodeDesigner.Ps2.Multiplayer.Protocol;

/// <summary>
/// Parsed Medius application-layer message extracted from an RT_MSG_CLIENT_APP_TOSERVER payload.
/// Wire format: [msgClass: 1 byte][msgType: 1 byte][payload: remaining bytes]
/// </summary>
public class MediusPacket
{
    public NetMessageClass MessageClass { get; set; }
    public byte            MessageType  { get; set; }
    public byte[]          Payload      { get; set; } = Array.Empty<byte>();

    /// <summary>Parse a raw app payload into a MediusPacket.</summary>
    public static MediusPacket? Parse(byte[] data)
    {
        if (data == null || data.Length < 2)
            return null;

        return new MediusPacket
        {
            MessageClass = (NetMessageClass)data[0],
            MessageType  = data[1],
            Payload      = data.Length > 2 ? data[2..] : Array.Empty<byte>(),
        };
    }

    /// <summary>Serialize this message for sending inside RT_MSG_SERVER_APP.</summary>
    public byte[] Serialize()
    {
        var result = new byte[2 + Payload.Length];
        result[0] = (byte)MessageClass;
        result[1] = MessageType;
        Buffer.BlockCopy(Payload, 0, result, 2, Payload.Length);
        return result;
    }

    // -------------------------------------------------------------------------
    // Builder helpers
    // -------------------------------------------------------------------------

    public static MediusPacket Build(NetMessageClass cls, byte type, byte[] payload) => new()
    {
        MessageClass = cls,
        MessageType  = type,
        Payload      = payload,
    };

    public static MediusPacket BuildLobby(MediusLobbyMessageId type, byte[] payload) =>
        Build(NetMessageClass.MessageClassLobby, (byte)type, payload);

    public static MediusPacket BuildLobbyExt(MediusLobbyExtMessageId type, byte[] payload) =>
        Build(NetMessageClass.MessageClassLobbyExt, (byte)type, payload);
}
