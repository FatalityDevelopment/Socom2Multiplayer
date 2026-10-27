using System;
using System.Security.Cryptography;

namespace DNAS;

/// <summary>
/// Constructs new DNAS response fields using the reconstructed wire algorithms.
/// S1 metadata, session IDs and suffixes are generated; the nested S1 plaintext is a shared protocol constant.
/// These producers apply to the common DNAS protocol path; they do
/// not claim to reproduce the historical DNAS backend authorization policy.
/// </summary>
public sealed class DnasResponseProducer
{
    public DnasResponseProducer() { }

    /// <summary>
    /// Produces a fresh session/header, DES challenge, Challenge B and tail.
    /// The nested plaintext was identical across 138 decoded standard S1 captures.
    /// The outer and inner wire encryption is performed by Server.
    /// Header metadata and session IDs are freshly generated for every S1.
    /// </summary>
    public FirstResponseData ProduceFirstReply(byte[] initial308, UnwrappedInitial decoded, byte[]? challenge8A, byte[] ticket128, byte[]? rsaModulus128 = null)
    {
        Packet c1 = new(initial308);
        Guard.Operation(c1, Public.ClientConnect, 268);
        if (decoded == null || !decoded.ZeroPaddingValid || !decoded.FixedTrailerValid)
            throw new CryptographicException("Initial original envelope failed validation.");

        Guard.Size(ticket128, 128, nameof(ticket128));
        // Ticket is chosen from the current C1 serial by the session service.
        // It is never inferred from a hard-coded title-specific fallback.
        byte[] header = DnasServerConstants.CreateS1Header40();
        // Let Packet.Make write the correct opcode and big-endian body length.
        byte[] actualChallengeA = challenge8A == null ? ImageIndependentChallenge.NewChallengeA() : (byte[])challenge8A.Clone();
        Guard.Size(actualChallengeA, 8, nameof(challenge8A));
        byte[] originalChallenge16 = RandomNumberGenerator.GetBytes(16);
        byte[] encryptedChallenge16 = DES.Encrypt(originalChallenge16, ImageIndependentChallenge.DeriveKey(actualChallengeA));
        // Challenge B and the final 96 bytes are independently random per S1.
        // Retail tests accepted independently randomized B and tail fields.
        // The protocol plaintext is constant; the nested 3DES key/IV are derived
        // from this client's C1, so the transmitted ciphertext is session-specific.
        byte[] nestedPlaintext32 = DnasProtocolConstants.GetS1InnerPlaintext32();
        return new FirstResponseData(header, actualChallengeA, encryptedChallenge16, RandomNumberGenerator.GetBytes(8), (byte[])ticket128!.Clone(), nestedPlaintext32, RandomNumberGenerator.GetBytes(96), rsaModulus128);
    }

    /// <summary>
    /// The original S2 client handler observed does not read this 128-byte
    /// region. The user verified that BOTH zeroed and independently randomized
    /// S2 fields were accepted as independently randomized payloads in tested retail sessions. Generate fresh bytes
    /// instead of depending on the historical S2 packet fixture. This does
    /// NOT establish how the original backend produced its 128 bytes.
    /// </summary>
    public byte[] ProduceSecondReply(byte[] c1, byte[] s1, byte[] c2)
    {
        Guard.Operation(new Packet(c1), Public.ClientConnect, 268);
        Guard.Operation(new Packet(s1), Public.ServerConnect, 288);
        Guard.Operation(new Packet(c2), Public.ClientProof, 144);
        return RandomNumberGenerator.GetBytes(128);
    }

    /// <summary>
    /// Final-result producer for the supported common DNAS wire family.
    /// The original 77-byte packet is NOT replayed: DnasServerSession has
    /// independently verified the native C1 proofs, generated S1, and verified
    /// C2 before invoking this callback. Packet/S3 framing and the unique
    /// session header are freshly serialized by Server.BuildResponse.
    ///
    /// Completed exchanges established the response flag and that the 32-byte
    /// result may vary. Historical backend authorization policy remains unknown.
    /// </summary>
    public (byte flag, byte[] result32) ProduceFinalResult(byte[] c1, byte[] s1, byte[] c2, byte[] s2, byte[] c3)
    {
        Guard.Operation(new Packet(c1), Public.ClientConnect, 268);
        Packet first = new Packet(s1);
        Packet clientProof = new Packet(c2);
        Packet second = new Packet(s2);
        Packet final = new Packet(c3);
        Guard.Operation(first, Public.ServerConnect, 288);
        Guard.Operation(clientProof, Public.ClientProof, 144);
        Guard.Operation(second, Public.ServerProof, 130);
        Guard.Operation(final, Public.ClientFinal, 4);
        Guard.SameSession(first, clientProof);
        Guard.SameSession(clientProof, second);
        Guard.SameSession(second, final);
        // The final four-byte client parameter is variable; do not constrain it to a recorded example.
        // Both tested retail variants accepted randomized S3 result bytes.
        // Historical backend authorization semantics are still NOT recovered.
        return (DnasServerConstants.CompatibleFinalResultFlag, RandomNumberGenerator.GetBytes(32));
    }
}
