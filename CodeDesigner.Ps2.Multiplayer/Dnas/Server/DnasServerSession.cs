using System;
using System.Security.Cryptography;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>
/// A single DNAS protocol transaction, retained across its HTTP/TLS connections.
/// C1 must pass the native A/B/C/D proof checks; C2 must match the issued DES
/// challenge and frame. The RSA payload is also checked when a public modulus
/// is explicitly supplied for diagnostics; it is not a server prerequisite.
///
/// Response producers are supplied by the caller. The recovered client-side
/// checks do not, by themselves, establish the historical backend policy.
/// </summary>
public sealed partial class DnasServerSession
{
    public delegate FirstResponseData FirstReplyProducer(byte[] initialRequest308, UnwrappedInitial decodedProofs);
    public delegate byte[] SecondReplyProducer(byte[] initialRequest308, byte[] issuedFirstReply328, byte[] verifiedClientProof184);
    public delegate (byte flag, byte[] result32) FinalResultProducer(byte[] initialRequest308, byte[] issuedFirstReply328, byte[] verifiedClientProof184, byte[] issuedSecondReply170, byte[] finalRequest44);

    private readonly Server _server = new();
    private readonly ProofInputPlan _identity;
    private readonly NativeProofCore.Material[] _banks;
    private readonly ulong? _nativeRngEntry;
    private readonly byte _nativeParameter;
    private readonly NativeProofDrawSchedule? _callerDrawSchedule;
    private bool _useRecoveredAudit;
    private readonly FirstReplyProducer? _firstProducer;
    private readonly SecondReplyProducer? _secondProducer;
    private readonly FinalResultProducer? _finalProducer;
    private byte[]? _c1, _s1, _c2, _s2, _c3, _s3;
    private byte[]? _rsaModulus128;
    private int _phase;

    /// <summary>0 expects c1; 1 expects c2; 2 expects c3; 3 is complete.</summary>
    public int Phase => _phase;

    /// <summary>
    /// The caller supplies original native per-stage caller material; it is
    /// not derived from an arbitrary title and MUST have independent provenance.
    /// nativeRngEntry is enforced only when the uninterrupted four-stage RNG
    /// sequence is independently known for this session.
    /// </summary>
    public DnasServerSession(ProofInputPlan identity, NativeProofCore.Material[] banks, FirstReplyProducer? firstProducer = null, SecondReplyProducer? secondProducer = null, FinalResultProducer? finalProducer = null, ulong? nativeRngEntry = null, byte nativeParameter = 2, NativeProofDrawSchedule? callerDrawSchedule = null)
    {
        _identity = identity ?? throw new ArgumentNullException(nameof(identity));
        if (banks == null || banks.Length != 4) throw new ArgumentException("Exactly four native material banks are required.", nameof(banks));
        _banks = new NativeProofCore.Material[4];
        for (int i = 0; i < 4; i++)
        {
            if (banks[i] == null) throw new ArgumentException("Null native material bank.", nameof(banks));
            NativeProofCore.Material b = banks[i];
            _banks[i] = new NativeProofCore.Material(b.InitialEcbSource32, b.InitialEcbKey8, b.FirstBlockSource8, b.FirstBlockKeyIv32, b.FinalEcbSource32, b.FinalEcbKey8);
        }
        _firstProducer = firstProducer;
        _secondProducer = secondProducer;
        _finalProducer = finalProducer;
        if (callerDrawSchedule != null && !nativeRngEntry.HasValue) throw new ArgumentException("Scheduled original RNG verification requires its independently established entry state.", nameof(nativeRngEntry));
        _nativeRngEntry = nativeRngEntry;
        _nativeParameter = nativeParameter;
        _callerDrawSchedule = callerDrawSchedule;
    }

    /// <summary>
    /// Create a server transaction that recovers the four per-request proof sources
    /// directly from C1, using the common DNAS cipher parameters.
    /// No client RNG recovery is attempted.
    /// </summary>
    public static DnasServerSession FromRecoveredProofs(ProofInputPlan identity, FirstReplyProducer? firstProducer = null, SecondReplyProducer? secondProducer = null, FinalResultProducer? finalProducer = null, byte nativeParameter = 2)
    {
        byte[][] placeholders = { new byte[8], new byte[8], new byte[8], new byte[8] };
        DnasServerSession session = new(identity, DnasProofConstants.CreateMaterials(placeholders), firstProducer, secondProducer, finalProducer, nativeParameter: nativeParameter);
        session._useRecoveredAudit = true;
        return session;
    }

    /// <summary>
    /// Handle the next request in this session. C1, C2 and C3 are distinct stages;
    /// a correctly formatted packet does not bypass the preceding cryptographic checks.
    /// </summary>
    public byte[] HandleRequest(byte[] request)
    {
        Packet packet = new(request);

        if (_phase == 0 && packet.Operation == Public.ClientConnect)
            return HandleInitialRequest(packet);

        if (_phase == 1 && packet.Operation == Public.ClientProof)
            return HandleClientProof(packet);

        if (_phase == 2 && packet.Operation == Public.ClientFinal)
            return HandleClientFinal(packet);

        throw new InvalidOperationException($"Invalid retail server phase {_phase} or operation 0x{packet.Operation:X8}.");
    }

    /// <summary>Verify all four original C1 identity proofs before issuing the S1 challenge.</summary>
    private byte[] HandleInitialRequest(Packet request)
    {
        ValidateInitialProofs(request);

        if (_firstProducer == null)
            throw new NotSupportedException("Original first-reply signing/field producer has not been supplied.");

        UnwrappedInitial decoded = _server.InspectInitialClientProof(request.Raw);
        FirstResponseData data = _firstProducer((byte[])request.Raw.Clone(), decoded);
        byte[] reply = _server.BuildResponse(request.Raw, data);

        // These values must survive the next HTTP/TLS connection.
        _rsaModulus128 = data.RsaModulus128 == null ? null : (byte[])data.RsaModulus128.Clone();
        _c1 = (byte[])request.Raw.Clone();
        _s1 = reply;
        _phase = 1;
        return (byte[])reply.Clone();
    }

    private void ValidateInitialProofs(Packet request)
    {
        if (_useRecoveredAudit)
        {
            // Verify the original four proof calculations independently of
            // any assumed client RNG algorithm or seed.
            _ = NativeRetailProofAudit.Inspect(request.Raw, _identity, parameter: _nativeParameter);

            return;
        }

        bool valid;
        if (_callerDrawSchedule != null)
            valid = _server.VerifyInitialNativeProofsWithSchedule(request.Raw, _identity, _banks, _nativeRngEntry!.Value, _callerDrawSchedule, _nativeParameter);
        else if (_nativeRngEntry.HasValue)
            valid = _server.VerifyInitialNativeProofsWithRng(request.Raw, _identity, _banks, _nativeRngEntry.Value, _nativeParameter);
        else
            valid = _server.VerifyInitialNativeProofs(request.Raw, _identity, _banks, _nativeParameter);

        if (!valid)
            throw new CryptographicException("Original native A/B/C/D identity calculation failed.");
    }

    /// <summary>Verify the issued DES challenge, C2 frame, and optionally the RSA payload.</summary>
    private byte[] HandleClientProof(Packet request)
    {
        if (!_server.VerifyClientProof(_s1!, request.Raw, _rsaModulus128))
            throw BuildClientProofFailure(request);

        if (_secondProducer == null)
            throw new NotSupportedException("The native 128-byte second-response producer has not been reconstructed.");

        byte[] result128 = _secondProducer((byte[])_c1!.Clone(), (byte[])_s1!.Clone(), (byte[])request.Raw.Clone());
        byte[] reply = _server.BuildResponse(request.Raw, result128);

        _c2 = (byte[])request.Raw.Clone();
        _s2 = reply;
        _phase = 2;
        return (byte[])reply.Clone();
    }

    /// <summary>Create a diagnostic only after a genuine C2 verification failure.</summary>
    private CryptographicException BuildClientProofFailure(Packet request)
    {
        Packet outer = Protocol.DecryptReply1Outer(new Packet(_s1!));
        byte[] challengeA = outer.Payload.AsSpan(0, 8).ToArray();
        byte[] derivedKey8 = ImageIndependentChallenge.DeriveKey(challengeA);
        byte[] expectedPrefix = Protocol.FirstReplyPrefix(outer, derivedKey8);
        byte[] actualPrefix = request.Raw.AsSpan(40, 16).ToArray();
        // No modulus is required for the live handshake. A missing modulus
        // means the RSA payload cannot be compared independently on this side.
        string rsaStatus = "NOT CHECKED (modulus absent)";
        if (_rsaModulus128 != null)
        {
            byte[] rsa117 = RSA.VerifyServerOperand(outer.Raw.AsSpan(0x48, 128).ToArray(), _rsaModulus128);
            rsaStatus = request.Raw.AsSpan(56, 117).SequenceEqual(rsa117) ? "MATCH" : "MISMATCH";
        }

        string detail = $"C2 verification failed. S1 Challenge A={Convert.ToHexString(challengeA)}; " +
            $"DES challenge={Convert.ToHexString(outer.Payload.AsSpan(8, 16))}; " +
            $"predicted C2={Convert.ToHexString(expectedPrefix)}; " +
            $"actual C2={Convert.ToHexString(actualPrefix)}; " +
            $"RSA117={rsaStatus}; " +
            $"image-independent DES key={Convert.ToHexString(derivedKey8)}.";

        return new CryptographicException(detail);
    }

    /// <summary>Check the session binding and delegate the final backend decision.</summary>
    private byte[] HandleClientFinal(Packet request)
    {
        Guard.SameSession(new Packet(_s2!), request);

        if (_finalProducer == null)
            throw new NotSupportedException("The original final backend authorization policy has not been reconstructed.");

        var decision = _finalProducer((byte[])_c1!.Clone(), (byte[])_s1!.Clone(), (byte[])_c2!.Clone(), (byte[])_s2!.Clone(), (byte[])request.Raw.Clone());
        byte[] reply = _server.BuildResponse(request.Raw, decision.flag, decision.result32);

        _c3 = (byte[])request.Raw.Clone();
        _s3 = reply;
        _phase = 3;
        return (byte[])reply.Clone();
    }

    /// <summary>
    /// Typed boundary to the recovered original cryptographic implementation.
    /// This instance retains challenge/session state between requests.
    /// </summary>
    public DnasMessage HandleRequest(DnasMessage request)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));
        return DnasPackets.Parse(HandleRequest(request.Serialize()));
    }
}
