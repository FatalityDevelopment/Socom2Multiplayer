using System;
using System.Collections.Concurrent;

namespace DNAS;

/// <summary>
/// Maintains DNAS protocol state across independent HTTPS connections.
/// A retail exchange uses C1/S1, C2/S2 and C3/S3 on separate sockets;
/// therefore a TCP disconnect must not discard an authenticated DNAS session.
/// </summary>
public sealed class DnasSessionRegistry
{
    private sealed class SessionEntry
    {
        public readonly object Gate = new();
        public readonly DnasServerSession Session;
        public readonly byte Mode;
        public DateTime LastSeenUtc;

        public SessionEntry(DnasServerSession session, byte mode)
        {
            Session = session;
            Mode = mode;
            LastSeenUtc = DateTime.UtcNow;
        }
    }

    private readonly ConcurrentDictionary<string, SessionEntry> _sessions = new(StringComparer.Ordinal);
    private readonly ProofInputPlan? _identity;
    private readonly DnasServerSession.FirstReplyProducer? _firstProducer;
    private readonly Func<byte[], NativeLiveC1Report, DnasServerSession.FirstReplyProducer>? _firstProducerFactory;
    private readonly DnasServerSession.SecondReplyProducer? _secondProducer;
    private readonly DnasServerSession.FinalResultProducer? _finalProducer;
    private readonly TimeSpan _idleExpiry = TimeSpan.FromMinutes(10);

    public int ActiveCount => _sessions.Count;

    public DnasSessionRegistry(ProofInputPlan? identity, DnasServerSession.FirstReplyProducer? firstProducer = null, DnasServerSession.SecondReplyProducer? secondProducer = null, DnasServerSession.FinalResultProducer? finalProducer = null, Func<byte[], NativeLiveC1Report, DnasServerSession.FirstReplyProducer>? firstProducerFactory = null)
    {
        _identity = identity; // Null means identities come from the validated C1 proof.
        _firstProducer = firstProducer;
        _secondProducer = secondProducer;
        _finalProducer = finalProducer;
        _firstProducerFactory = firstProducerFactory;
    }

    /// <summary>Validates and decodes the initial C1 proof without opening a socket.</summary>
    public NativeLiveC1Report InspectC1(byte[] request)
    {
        Packet packet = new(request);
        if (Public.ToConnectOperation(packet.Operation) != Public.ClientConnect)
            throw new FormatException("Not a C1 operation.");

        // Native C1 proof decoding uses the canonical i-connect opcode for all normal modes.
        byte[] canonical = packet.Operation == Public.ClientConnect
            ? request
            : Public.RewriteOperation(request, Public.ClientConnect);

        return NativeLiveC1Report.Inspect(canonical, _identity);
    }

    /// <summary>Typed application interface; binary serialization stays in the DNAS layer.</summary>
    public (DnasMessage reply, int phase, string sessionId) HandlePacket(DnasMessage request, NativeLiveC1Report? inspected = null)
    {
        ArgumentNullException.ThrowIfNull(request);

        var result = HandlePacket(request.Serialize(), inspected);
        return (DnasPackets.Parse(result.reply), result.phase, result.sessionId);
    }

    /// <summary>Routes an incoming packet to an initial, continuation, or disc-final exchange.</summary>
    public (byte[] reply, int phase, string sessionId) HandlePacket(byte[] request, NativeLiveC1Report? inspected = null)
    {
        Packet packet = new(request);
        uint operation = Public.ToConnectOperation(packet.Operation);

        if (operation == Public.ClientConnect)
            return HandleInitialConnect(packet, inspected);

        // The 0122 family ends with 8003/8007, not the normal 8008/800D pair.
        if (packet.Operation == 0x01228003)
            return HandleDiscFinal(packet);

        if (operation is Public.ClientProof or Public.ClientFinal)
            return HandleContinuation(packet, operation);

        throw new FormatException($"Unexpected incoming DNAS operation 0x{packet.Operation:X8}.");
    }

    private (byte[] reply, int phase, string sessionId) HandleInitialConnect(Packet packet, NativeLiveC1Report? inspected)
    {
        byte mode = Public.OperationMode(packet.Operation);
        if (!Public.IsNormalCryptoMode(mode))
        {
            throw new NotSupportedException(
                $"DNAS mode 0x{mode:X2} requires a dedicated extended S1 producer; the normal 288-byte reply is not interchangeable.");
        }

        byte[] canonical = mode == 0x08
            ? packet.Raw
            : Public.RewriteOperation(packet.Raw, Public.ClientConnect);

        NativeLiveC1Report decoded = inspected ?? InspectC1(packet.Raw);

        // C1 acceptance depends on the decoded proofs, not on reconstructing
        // the client's RNG algorithm, seed, or draw schedule.
        decoded.RequireValid();

        DnasServerSession.FirstReplyProducer? producer = _firstProducerFactory == null
            ? _firstProducer
            : _firstProducerFactory(packet.Raw, decoded);

        DnasServerSession session = DnasServerSession.FromRecoveredProofs(decoded.Identity, firstProducer: producer, secondProducer: _secondProducer, finalProducer: _finalProducer);

        byte[] firstReply = session.HandleRequest(canonical);
        string sessionId = Convert.ToHexString(new Packet(firstReply).SessionId);
        if (!_sessions.TryAdd(sessionId, new SessionEntry(session, mode)))
            throw new InvalidOperationException("Issued session ID collision.");

        ExpireIdle();

        byte[] response = mode == 0x08
            ? firstReply
            : Public.RewriteOperation(firstReply, Public.FromConnectOperation(Public.ServerConnect, mode));

        return (response, session.Phase, sessionId);
    }

    private (byte[] reply, int phase, string sessionId) HandleContinuation(Packet packet, uint canonicalOperation)
    {
        string sessionId = Convert.ToHexString(packet.SessionId);
        if (!_sessions.TryGetValue(sessionId, out SessionEntry? entry))
            throw new InvalidOperationException("No active DNAS session for this response.");

        lock (entry.Gate)
        {
            EnsureActive(entry, sessionId);

            byte receivedMode = Public.OperationMode(packet.Operation);
            if (receivedMode != entry.Mode)
            {
                throw new FormatException(
                    $"DNAS mode changed within session: expected 0x{entry.Mode:X2}, received 0x{receivedMode:X2}.");
            }

            // The lower-level session checks phase, C2 proof and C3 session binding.
            byte[] canonical = entry.Mode == 0x08
                ? packet.Raw
                : Public.RewriteOperation(packet.Raw, canonicalOperation);

            byte[] reply = entry.Session.HandleRequest(canonical);
            entry.LastSeenUtc = DateTime.UtcNow;
            int phase = entry.Session.Phase;

            if (phase == 3)
            {
                _sessions.TryRemove(sessionId, out _);
            }

            uint replyOperation = Public.FromConnectOperation(new Packet(reply).Operation, entry.Mode);
            byte[] response = entry.Mode == 0x08 ? reply : Public.RewriteOperation(reply, replyOperation);
            return (response, phase, sessionId);
        }
    }

    private (byte[] reply, int phase, string sessionId) HandleDiscFinal(Packet packet)
    {
        string sessionId = Convert.ToHexString(packet.SessionId);
        if (!_sessions.TryGetValue(sessionId, out SessionEntry? entry))
            throw new InvalidOperationException("No active 0122 DNAS session for 8003.");

        lock (entry.Gate)
        {
            EnsureActive(entry, sessionId);

            if (entry.Mode != 0x22 || entry.Session.Phase != 2)
                throw new FormatException("01228003 requires a verified 0122 C1/C2 exchange and phase 2.");

            _sessions.TryRemove(sessionId, out _);

            // 01 occurs in original captures; its backend policy semantics remain
            // unproven. Do not interpret it as a universal authorization rule.
            byte[] response = Packet.Make(packet.Header, 0x01228007, new byte[] { 1 }).Raw;
            return (response, 3, sessionId);
        }
    }

    private void EnsureActive(SessionEntry entry, string sessionId)
    {
        if (DateTime.UtcNow - entry.LastSeenUtc <= _idleExpiry)
            return;

        _sessions.TryRemove(sessionId, out _);
        throw new InvalidOperationException("DNAS session expired.");
    }

    public void ExpireIdle()
    {
        DateTime now = DateTime.UtcNow;
        foreach (var pair in _sessions)
        {
            lock (pair.Value.Gate)
            {
                if (now - pair.Value.LastSeenUtc > _idleExpiry)
                    _sessions.TryRemove(pair.Key, out _);
            }
        }
    }

}
