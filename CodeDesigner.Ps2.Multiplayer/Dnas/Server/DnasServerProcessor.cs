using System;
using System.Security.Cryptography;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>
/// Performs DNAS operation dispatch and proof validation without owning a
/// TCP listener, TLS stream or any game-specific key material.
/// </summary>
public sealed class DnasServerProcessor
{
    private readonly DnasSessionRegistry _sessions;

    public DnasServerProcessor(DnasSessionRegistry sessions)
    {
        _sessions = sessions ?? throw new ArgumentNullException(nameof(sessions));
    }

    public DnasResponse Handle(DnasMessage request)
    {
        ArgumentNullException.ThrowIfNull(request);

        uint operation = request.Header.Operation;
        byte mode = Public.OperationMode(operation);

        // Extended packet families need their proper response producers.
        // Never return a fabricated standard S1 for an unknown format.
        if (mode is 0x90 or 0x98 or 0xA2)
            throw new NotSupportedException($"DNAS mode 0x{mode:X2} requires its original extended response producer.");

        NativeLiveC1Report? decoded = null;
        string diagnostic = "";

        if (Public.ToConnectOperation(operation) == Public.ClientConnect)
        {
            // Verify the decrypted C1 proofs and envelope. RNG seed recovery
            // is not a DNAS authentication requirement and is not attempted.
            decoded = _sessions.InspectC1(request.Serialize());
            decoded.RequireValid();
        }

        var result = _sessions.HandlePacket(request, decoded);
        DnasMessage reply = result.reply;

        if (reply is S1Packet)
        {
            // Log the issued S1 challenge and RSA ticket digest. The outer
            // cryptography and packet construction remain in DNAS classes.
            byte[] serialized = reply.Serialize();
            byte[] canonical = mode == 0x08 ? serialized : Public.RewriteOperation(serialized, Public.ServerConnect);
            Packet plaintext = Protocol.DecryptReply1Outer(new Packet(canonical));
            S1Plaintext fields = new(plaintext.Payload);
            string rsaDigest = Convert.ToHexString(SHA256.HashData(fields.Signature128));

            diagnostic = $" [S1] A={Convert.ToHexString(fields.ChallengeA8)} B={Convert.ToHexString(fields.ChallengeB8)} RSA_SHA256={rsaDigest}";
        }

        return new DnasResponse(reply, decoded, result.phase, result.sessionId, diagnostic);
    }
}
