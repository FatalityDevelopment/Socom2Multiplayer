namespace DNAS;

/// <summary>
/// A processed DNAS message and its session diagnostics. The transport
/// serializes the packet and sends it over the established TLS connection.
/// </summary>
public sealed class DnasResponse
{
    public readonly DnasMessage Packet;
    public readonly NativeLiveC1Report? ClientProof;
    public readonly int Phase;
    public readonly string SessionId;
    public readonly string Note;

    internal DnasResponse(DnasMessage packet, NativeLiveC1Report? clientProof, int phase, string sessionId, string note)
    {
        Packet = packet;
        ClientProof = clientProof;
        Phase = phase;
        SessionId = sessionId;
        Note = note;
    }
}
