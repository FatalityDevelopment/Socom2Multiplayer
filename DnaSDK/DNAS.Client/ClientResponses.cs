using System;
using System.Security.Cryptography;

namespace DNAS;

/// <summary>
/// Receives S1, S2 and S3 for the artificial client. All protocol and
/// cryptographic acceptance checks remain in this partial client class;
/// no sockets or HTTP code are involved.
/// </summary>
public sealed partial class Client
{
    /// <summary>
    /// Authentically derives the first-reply challenge key from the same DNAS image
    /// used by the PS2 and generates the complete 184-byte second client request.
    /// The evidence provider must supply that image, beginning at EE 0x005498DC.
    /// </summary>
    public byte[] ProcessFirstResponse(byte[] serverReply328)
    {
        RequireStage(ExchangeStage.AwaitFirstReply);
        if (_dnasImage == null) throw new NotSupportedException("Provide the loaded DNAS image through ClientEvidence to derive the first-reply key.");
        // S1 Challenge-A key derivation uses only the supplied client image.
        // Optional signed-image verification occurs once before C2 is committed.
        Packet reply = new Packet(serverReply328);
        Packet outer = Protocol.DecryptReply1Outer(reply);
        byte[] challengeA = outer.Payload.AsSpan(0, 8).ToArray();
        byte[] key = ClientImage.DeriveFirstReplyKey(_dnasImage, challengeA);
        return ProcessFirstResponse(serverReply328, key);
    }

    /// <summary>
    /// For captured-trace verification, accepts the original two SHA-derived working
    /// values. Normal SDK callers should use ProcessFirstResponse(reply) above.
    /// </summary>
    public byte[] ProcessFirstResponse(byte[] serverReply328, byte[] working20A, byte[] working20B)
    {
        byte[] key = DES.FoldChallengeKey(working20A, working20B);
        return ProcessFirstResponse(serverReply328, key);
    }

    /// <summary>Builds the second request using a recovered eight-byte challenge key.</summary>
    public byte[] ProcessFirstResponse(byte[] serverReply328, byte[] recoveredDesKey8)
    {
        RequireStage(ExchangeStage.AwaitFirstReply);
        Packet reply = new Packet(serverReply328);
        Packet outer = Protocol.DecryptReply1Outer(reply);
        // Compute the native readiness predicate BEFORE committing this stage.
        // Both the normal image-derived key path and the trace-only key
        // overload must establish the same local state for reply two.
        Packet candidate = Protocol.BuildSecondRequest(reply.Header, outer, recoveredDesKey8, _rsaModulus128 ?? throw new InvalidOperationException("Configure the server RSA public modulus before processing S1."));
        uint readiness = _dnasImage != null && _dnasImage.Length == ClientImage.ImageLength && _imagePublicModulus128 != null
            ? NativeClientReadiness.Initialize(_dnasImage, _imagePublicModulus128) : 0;
        _request2 = candidate;
        _nativeReadyStatus = readiness;
        return (byte[])candidate.Raw.Clone();
    }

    /// <summary>
    /// The decoded original second-reply acceptance branch depends on the
    /// locally initialized original image/readiness state, NOT on decrypting
    /// the 128-byte response field in the observed native branch. A valid
    /// packet alone is insufficient: first-reply verification must have
    /// completed with a full, signature-validated DNAS image.
    /// </summary>
    public byte[] ProcessSecondResponse(byte[] serverReply170)
    {
        RequireStage(ExchangeStage.AwaitSecondReply);
        Packet reply = new Packet(serverReply170);
        Guard.SameSession(_request2, reply);
        // Parsing is not acceptance. Leave the existing client state completely
        // unchanged if native verification is not available.
        byte[] body = Protocol.InspectSecondReply(reply);
        // The protected client dispatcher at 0x0052D838 tests the locally
        // initialized status, returning 16 only when it equals 1. Its fallback
        // 0x0052DAF0 likewise tests this same word and returns 144 or -8.
        // On the traced normal path neither touches the 128-byte payload.
        // The caller at 0x004CBE34 rejects a separately set error bit; its
        // initial managed session value remains clear absent an error.
        if (_nativeReadyStatus == 0 && _imagePublicModulus128 == null)
        {
            throw new NotSupportedException("Configure the client image-signature public modulus with SetImagePublicKey before simulating the signed-image readiness check.");
        }
        if (SecondReplyCode.EvaluatePrimaryEntryStatus(_nativeReadyStatus) != 16)
        throw new CryptographicException("Original native readiness gate rejected the second response.");
        Packet finalRequest = Protocol.BuildFinalRequest(reply.Header, _finalPayload4 ?? throw new InvalidOperationException("The artificial client requires its final four-byte request payload."));
        _secondResponseBody = body;
        _request3 = finalRequest;
        return (byte[])_request3.Raw.Clone();
    }

    /// <summary>
    /// Research-only replay of the observed successful state transition. The
    /// captured PS2 state word had bit zero clear. This is NOT the complete
    /// cryptographic response validator and is not an authentication API.
    /// </summary>
    public byte[] AdvanceAfterObservedSecondReply(byte[] serverReply170, uint capturedWorkingStatus)
    {
        RequireStage(ExchangeStage.AwaitSecondReply);
        Packet reply = new Packet(serverReply170);
        Guard.SameSession(_request2, reply);
        if ((capturedWorkingStatus & 1) != 0) throw new FormatException("Observed PS2 bit-zero rejection condition at EE 0x004CBE38.");
        _secondResponseBody = Protocol.InspectSecondReply(reply);
        _request3 = Protocol.BuildFinalRequest(reply.Header, _finalPayload4 ?? throw new InvalidOperationException("The artificial client requires its final four-byte request payload."));
        return (byte[])_request3.Raw.Clone();
    }

    /// <summary>
    /// Research-only evaluation of the exact executed original inner and outer
    /// second-reply status branches. The two values MUST be measured native
    /// client state, not supplied by a server or treated as an authentication
    /// token. This does not reconstruct the producers of those state words.
    /// The normal ProcessSecondResponse remains fail-closed.
    /// </summary>
    public byte[] AdvanceAfterObservedSecondReplyState(byte[] serverReply170, uint measuredNativeGlobalStatus, uint measuredCallerWorkingStatus)
    {
        RequireStage(ExchangeStage.AwaitSecondReply);
        Packet reply = new Packet(serverReply170);
        Guard.SameSession(_request2, reply);
        int originalCode = SecondReplyCode.EvaluateObservedHandlerState(measuredNativeGlobalStatus, measuredCallerWorkingStatus);
        if (originalCode != 130) throw new FormatException($"Original measured second-reply handler returned {originalCode}, not 130.");
        _secondResponseBody = Protocol.InspectSecondReply(reply);
        _request3 = Protocol.BuildFinalRequest(reply.Header, _finalPayload4 ?? throw new InvalidOperationException("The artificial client requires its final four-byte request payload."));
        return (byte[])_request3.Raw.Clone();
    }

    /// <summary>Reads the final 32-byte result; a parsed result is not an authorization policy decision.</summary>
    public (byte flag, byte[] result32) ProcessFinalResponse(byte[] serverReply77)
    {
        RequireStage(ExchangeStage.AwaitFinalReply);
        Packet reply = new Packet(serverReply77);
        Guard.SameSession(_request3, reply);
        _finalResult = Protocol.InspectFinalReply(reply);
        return (_finalResult.Value.flag, (byte[])_finalResult.Value.value.Clone());
    }

    /// <summary>
    /// Two wire-level final flag values are documented. The original completed
    /// A completed capture carried zero; one is an independently observed alternate
    /// value. Neither flag alone establishes the original backend decision.
    /// </summary>
    public enum FinalFlagObservation : byte
    {
        MatchesRecordedCompletedPath = 0, AlternateObserved = 1
    }

    /// <summary>
    /// Indicates which OBSERVED final-wire flag was received. This is deliberately
    /// not IsAuthorized: the 32-byte result's original policy is not recovered.
    /// </summary>
    public FinalFlagObservation? LastFinalFlagObservation => _finalResult.HasValue
    ? (FinalFlagObservation)_finalResult.Value.flag : null;

    /// <summary>Raw original final-result fields, without an invented authorization verdict.</summary>
    public (byte flag, byte[] result32)? LastFinalResult => _finalResult.HasValue
    ? (_finalResult.Value.flag, (byte[])_finalResult.Value.value.Clone()) : null;

    /// <summary>Clear a completed or abandoned exchange before using new credentials.</summary>
    public void Reset()
    {
        if (_dnasImage != null) CryptographicOperations.ZeroMemory(_dnasImage);
        if (_secondResponseBody != null) CryptographicOperations.ZeroMemory(_secondResponseBody);
        if (_finalResult.HasValue) CryptographicOperations.ZeroMemory(_finalResult.Value.value);
        _dnasImage = null;
        _request1 = null;
        _request2 = null;
        _request3 = null;
        _secondResponseBody = null;
        _finalResult = null;
        _nativeReadyStatus = 0;
    }

    public byte[]? LastInitialRequest => _request1 == null ? null : (byte[])_request1.Raw.Clone();
    public byte[]? LastSecondRequest => _request2 == null ? null : (byte[])_request2.Raw.Clone();
    public byte[]? LastFinalRequest => _request3 == null ? null : (byte[])_request3.Raw.Clone();
    public byte[]? LastSecondResponseBody => _secondResponseBody == null ? null : (byte[])_secondResponseBody.Clone();

    /// <summary>Build original native client C1 and return typed, validated fields.</summary>
    public C1Packet BuildConnect(byte[] consoleId8, byte[] discId5, byte[] image65536, string serial)
    => (C1Packet)DnasPackets.Parse(BuildRequest(consoleId8, discId5, image65536, serial));

    /// <summary>
    /// Process a typed S1/S2/S3 response. Returns null once the final reply
    /// completes the protocol; throws on unexpected sequence or invalid proof.
    /// </summary>
    public DnasMessage? Process(DnasMessage response)
    {
        if (response == null) throw new ArgumentNullException(nameof(response));
        byte[] request = HandleResponse(response.Serialize());
        return request.Length == 0 ? null : DnasPackets.Parse(request);
    }
}
