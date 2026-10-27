using System;
using System.Security.Cryptography;

namespace DNAS;

/// <summary>
/// Standalone artificial DNAS client for local protocol simulation. This
/// class does not open TCP connections or substitute for retail client code.
/// </summary>

public sealed partial class Client
{
    private readonly Func<string, string, ClientEvidence>? _evidenceProvider;
    private readonly Func<string, string, byte[], ClientEvidence>? _imageEvidenceProvider;
    private readonly PS2Random _random;
    private byte[]? _dnasImage;
    private Packet? _request1;
    private Packet? _request2;
    private Packet? _request3;
    private byte[]? _secondResponseBody;
    private (byte flag, byte[] value)? _finalResult;
    private uint _nativeReadyStatus;
    private byte[]? _rsaModulus128;
    private byte[]? _imagePublicModulus128;
    private byte[]? _finalPayload4;

    /// <summary>Configure authority data for a simulated client session.</summary>
    public void SetServerPublicKey(byte[] modulus128)
    {
        Guard.Size(modulus128, 128, nameof(modulus128));
        _rsaModulus128 = (byte[])modulus128.Clone();
    }

    /// <summary>
    /// Configure the optional, client-side image-signature verifier. This key
    /// is independent of the S1 ticket RSA modulus, and must come from the
    /// caller's own client/title data rather than a bundled SDK constant.
    /// </summary>
    public void SetImagePublicKey(byte[] modulus128)
    {
        Guard.Size(modulus128, 128, nameof(modulus128));
        _imagePublicModulus128 = (byte[])modulus128.Clone();
    }

    /// <summary>The final four protocol bytes are supplied by the artificial client's caller.</summary>
    public void SetFinalPayload(byte[] payload4)
    {
        Guard.Size(payload4, 4, nameof(payload4));
        _finalPayload4 = (byte[])payload4.Clone();
    }

    /// <summary>
    /// Standalone client protocol stage. This describes actual local progress,
    /// not whether the retail server has authorized the player.
    /// </summary>
    public enum ExchangeStage : byte
    {
        NotStarted, AwaitFirstReply, AwaitSecondReply, AwaitFinalReply, FinalReceived
    }

    public ExchangeStage Stage => _finalResult.HasValue ? ExchangeStage.FinalReceived
    : _request3 != null ? ExchangeStage.AwaitFinalReply
    : _request2 != null ? ExchangeStage.AwaitSecondReply
    : _request1 != null ? ExchangeStage.AwaitFirstReply : ExchangeStage.NotStarted;

    /// <summary>
    /// The original client's message dispatcher. The normal second response
    /// follows the decoded native readiness predicate, independently of the
    /// research-only measured-status helpers.
    /// </summary>
    public byte[] HandleResponse(byte[] serverReply)
    {
        if (serverReply == null) throw new ArgumentNullException(nameof(serverReply));
        Packet incoming = new Packet(serverReply);
        return Stage switch
        {
            ExchangeStage.AwaitFirstReply when incoming.Operation == Public.ServerConnect => ProcessFirstResponse(serverReply),
            ExchangeStage.AwaitSecondReply when incoming.Operation == Public.ServerProof => ProcessSecondResponse(serverReply),
            ExchangeStage.AwaitFinalReply when incoming.Operation == Public.ServerFinal => FinishFinalResponse(serverReply),
            _ => throw new InvalidOperationException($"Unexpected DNAS operation 0x{incoming.Operation:X8} in client stage {Stage}.")
        };
    }

    private byte[] FinishFinalResponse(byte[] serverReply)
    {
        _ = ProcessFinalResponse(serverReply);
        return Array.Empty<byte>();
    }

    private void RequireStage(ExchangeStage stage)
    {
        if (Stage != stage) throw new InvalidOperationException($"Expected client stage {stage}, got {Stage}.");
    }

    public Client(Func<string, string, ClientEvidence>? evidenceProvider = null)
    {
        _evidenceProvider = evidenceProvider;
        _random = new PS2Random();
    }

    /// <summary>
    /// Research-only injection point for the unrecovered PS2 proof engine. The
    /// SDK's three inputs are preserved; the provider must implement the four
    /// actual PS2 producer algorithms, not load captured ciphertext templates.
    /// </summary>
    public Client(Func<string, string, byte[], ClientEvidence> imageEvidenceProvider)
    {
        _imageEvidenceProvider = imageEvidenceProvider ?? throw new ArgumentNullException(nameof(imageEvidenceProvider));
        _random = new PS2Random();
    }

    /// <summary>
    /// Produces a fresh 308-byte client request from exactly four credentials:
    /// console i.Link ID, disc ID, signed image and game serial. CDVD clock,
    /// the native EDE3 proof material, original LCG and wire envelope are
    /// generated inside the standalone SDK, not replayed from a packet.
    ///
    /// IMPORTANT: the lookup byte array remains a TEMPORARY game-boot
    /// witness; C/D undefined stack padding uses initialized managed memory.
    /// Original caller RNG draw schedule is opcode-verified. Retail server
    /// acceptance of this generalized padding remains to be validated.
    /// </summary>
    public byte[] BuildRequest(byte[] consoleId8, byte[] discDnasId5, byte[] dnasImage, string gameSerial)
    {
        RequireStage(ExchangeStage.NotStarted);
        throw new NotSupportedException("C1 requires the protocol header and lookup ID; use BuildRequest with explicit header, lookup ID, and RNG draw schedule.");
    }

    public byte[] BuildRequest(byte[] consoleId8, byte[] discDnasId5, byte[] dnasImage, string gameSerial, byte[] header40, byte[] lookupId8, NativeProofDrawSchedule drawSchedule)
    {
        return BuildRequestFromSetup(ClientSetup.Create(consoleId8, discDnasId5, dnasImage, gameSerial), header40, lookupId8, drawSchedule);
    }

    /// <summary>
    /// Build a fresh client request from caller-provided protocol header and lookup ID.
    /// Neither field can be inferred from a game serial, so no title is special-cased.
    /// </summary>
    internal byte[] BuildRequestFromSetup(ClientSetup setup, byte[] header40, byte[] lookupId8, NativeProofDrawSchedule drawSchedule)
    {
        RequireStage(ExchangeStage.NotStarted);
        ArgumentNullException.ThrowIfNull(setup);
        Guard.Size(header40, 40, nameof(header40));
        Guard.Size(lookupId8, 8, nameof(lookupId8));
        ArgumentNullException.ThrowIfNull(drawSchedule);

        byte[][] clocks = new byte[4][];
        for (int i = 0; i < clocks.Length; i++) clocks[i] = setup.ReadProofClock8(i);
        NativeProofCore.Material[] materials = DnasProofConstants.CreateMaterials(clocks);
        var (fields, random16) = new NativeClientProofProducer(setup.NewNativeRandom()).GenerateScheduled(setup.Identity, materials, setup.NativeScratchTail3(), setup.NativeScratchTail7(), drawSchedule);
        _dnasImage = (byte[])setup.DnasImage.Clone();
        return BuildFromEvidence(new ClientEvidence(header40, lookupId8, fields, setup.DnasImage), random16);
    }

    /// <summary>
    /// Legacy research entry point: serial, five-byte CDVD DNAS ID, and exact 64 KiB
    /// DNAS image. The image is passed through to the source-evidence producer
    /// and retained for response-1 DES key derivation. No user-supplied RNG.
    /// The common native four-pass proof algorithm is reconstructed and has
    /// a byte-exact original 308-byte request regression. This simpler API
    /// still cannot infer the full i.Link ID, original CDVD clock, native
    /// caller RNG draws, C/D stack tails or header/lookup values from these
    /// three arguments, so a caller must supply an independent evidence producer.
    /// </summary>
    public byte[] BuildRequest(string gameSerial, string dnasID, byte[] imageBytes)
    {
        string serial = Identity.NormalizeGameSerial(gameSerial);
        byte[] discId = Public.ParseDnasId(dnasID);
        if (imageBytes == null || imageBytes.Length != ClientImage.ImageLength) throw new ArgumentException("DNAS image must be exactly 65536 bytes.", nameof(imageBytes));
        string id = BitConverter.ToString(discId);
        byte[] image = (byte[])imageBytes.Clone();
        ClientEvidence evidence = _imageEvidenceProvider?.Invoke(serial, id, (byte[])image.Clone()) ?? _evidenceProvider?.Invoke(serial, id) ?? throw new NotSupportedException("The original PS2 proof-engine instructions and cipher modes are recovered, but the full original key/IV and output-buffer dataflow has not been verified against genuine four-field captures. Serial, disc ID and image bytes do not provide the console's i.Link identity. No synthetic proof will be emitted.");
        _dnasImage = image;
        return BuildFromEvidence(evidence);
    }

    /// <summary>
    /// Constructs the original 308-byte request from an independently derived
    /// native session state. The proof bytes are CALCULATED by the connected
    /// original four-pass engine, not supplied or replayed. The PS2-specific
    /// native material, RNG entry state, header/lookup derivation, 3/7 scratch
    /// tail bytes, and envelope RNG must still come from authentic callers.
    /// This overload does not claim those producers are reconstructed.
    /// </summary>
    public byte[] BuildNativeRequest(ProofInputPlan identity, byte[] dnasImage, NativeProofCore.Material[] materials, NativeProofRandom nativeRng, byte[] scratchTailC3, byte[] scratchTailD7, byte[] header40, byte[] lookupId8, byte[] envelopeRandom16, byte parameter = 2)
    {
        if (dnasImage == null || dnasImage.Length != ClientImage.ImageLength) throw new ArgumentException("DNAS image must contain 65536 bytes.", nameof(dnasImage));
        Guard.Size(header40, 40, nameof(header40));
        Guard.Size(lookupId8, 8, nameof(lookupId8));
        Guard.Size(envelopeRandom16, 16, nameof(envelopeRandom16));
        InitialFields fields = new NativeClientProofProducer(nativeRng).Generate(identity, materials, scratchTailC3, scratchTailD7, parameter);
        _dnasImage = (byte[])dnasImage.Clone();
        _request1 = Protocol.BuildInitialPacket(header40, lookupId8, fields, envelopeRandom16);
        _request2 = null;
        _request3 = null;
        _secondResponseBody = null;
        _finalResult = null;
        _nativeReadyStatus = 0;
        return (byte[])_request1.Raw.Clone();
    }

    /// <summary>
    /// Builds A/B/C/D from the fixed tables in the shared DNAS cipher constants. The four live eight-byte upstream results and untouched C/D
    /// stack tails still require genuine session evidence. This overload
    /// deliberately does not infer those values from game/console identity.
    /// </summary>
    public byte[] BuildNativeRequestFromConstants(ProofInputPlan identity, byte[] dnasImage, byte[][] liveSource8, NativeProofRandom nativeRng, byte[] scratchTailC3, byte[] scratchTailD7, byte[] header40, byte[] lookupId8, byte[] envelopeRandom16, byte parameter = 2)
    {
        NativeProofCore.Material[] banks = DnasProofConstants.CreateMaterials(liveSource8);
        return BuildNativeRequest(identity, dnasImage, banks, nativeRng, scratchTailC3, scratchTailD7, header40, lookupId8, envelopeRandom16, parameter);
    }

    /// <summary>
    /// Constant-backed native request when the final-pass globals are observed
    /// independently at each stage. Fixed tables are always verified against
    /// the exact original DNAS module and the independent RAM table snapshot.
    /// </summary>
    public byte[] BuildNativeRequestFromConstants(ProofInputPlan identity, byte[] dnasImage, byte[][] liveSource8, byte[][] finalSources32, byte[][] finalKeys8, NativeProofRandom nativeRng, byte[] scratchTailC3, byte[] scratchTailD7, byte[] header40, byte[] lookupId8, byte[] envelopeRandom16, byte parameter = 2)
    {
        NativeProofCore.Material[] banks = DnasProofConstants.CreateMaterials(liveSource8, finalSources32, finalKeys8);
        return BuildNativeRequest(identity, dnasImage, banks, nativeRng, scratchTailC3, scratchTailD7, header40, lookupId8, envelopeRandom16, parameter);
    }

    /// <summary>
    /// Builds the entire original first-request ciphertext from a measured
    /// native clock, stage-specific CDVD RTC results, and a
    /// caller draw schedule. Unlike the older explicit-envelope overload,
    /// both proof randomness and the 16-byte wire envelope come from ONE
    /// original native LCG. Initial header/lookup and untouched stack tails
    /// still require original session inputs rather than captured-packet replay.
    /// </summary>
    public byte[] BuildNativeRequestFromConstantsSchedule(ProofInputPlan identity, byte[] dnasImage, byte[][] stageClocks8, byte[] seedClock8, NativeProofDrawSchedule schedule, byte[] scratchTailC3, byte[] scratchTailD7, byte[] header40, byte[] lookupId8, byte parameter = 2)
    {
        if (identity == null) throw new ArgumentNullException(nameof(identity));
        Guard.Size(seedClock8, 8, nameof(seedClock8));
        Guard.Size(dnasImage, ClientImage.ImageLength, nameof(dnasImage));
        NativeProofCore.Material[] banks = DnasProofConstants.CreateMaterials(stageClocks8);
        var (fields, envelopeRandom) = new NativeClientProofProducer(NativeProofRandom.FromCdvdClock(seedClock8))
        .GenerateScheduled(identity, banks, scratchTailC3, scratchTailD7, schedule, parameter);
        _dnasImage = (byte[])dnasImage.Clone();
        return BuildFromEvidence(new ClientEvidence(header40, lookupId8, fields, dnasImage), envelopeRandom);
    }

    /// <summary>
    /// Builds the actual 308-byte PS2 initial request.
    /// Random generation is entirely internal. The original identity-proof formulas
    /// are still under investigation, so those fields require an evidence provider.
    /// </summary>
    public byte[] BuildRequest(string gameSerial, string dnasID)
    {
        string serial = Identity.NormalizeGameSerial(gameSerial);
        string id = BitConverter.ToString(Public.ParseDnasId(dnasID));
        ClientEvidence evidence = _evidenceProvider?.Invoke(serial, id) ?? throw new NotSupportedException("Supply the full DNAS image using BuildRequest(serial, id, image). The original proof engine is still unrecovered.");
        _dnasImage = evidence.DnasImage == null ? null : (byte[])evidence.DnasImage.Clone();
        return BuildFromEvidence(evidence);
    }

    /// <summary>
    /// Generate the first retail-format request from the reconstructed native
    /// A/B/C/D cipher pipeline, then bind it to this client's response state.
    /// Every otherwise unknown value is supplied as independent original DNAS session evidence:
    /// the CDVD identity results, original stage key material, RNG entry state,
    /// C/D scratch tails, header, lookup identifier, envelope RNG bytes, and original DNAS image.
    /// No captured ciphertext, lab key, guessed metadata, or signing shortcut.
    /// This native-core path has NOT yet been proven byte-exact against retail
    /// ciphertext or the original server's proof-acceptance policy.
    /// </summary>
    public byte[] BuildNativeRequest(ProofInputPlan identity, NativeProofCore.Material[] materials, NativeProofRandom nativeRandom, byte[] cScratchTail3, byte[] dScratchTail7, byte[] header40, byte[] lookupId8, byte[] imageBytes, byte[] envelopeRandom16, byte nativeParameter = 2)
    {
        if (identity == null) throw new ArgumentNullException(nameof(identity));
        if (imageBytes == null || imageBytes.Length != ClientImage.ImageLength) throw new ArgumentException("DNAS image must be exactly 65536 bytes.", nameof(imageBytes));
        InitialFields fields = new NativeClientProofProducer(nativeRandom).Generate(identity, materials, cScratchTail3, dScratchTail7, nativeParameter);
        Guard.Size(envelopeRandom16, 16, nameof(envelopeRandom16));
        byte[] request = BuildFromEvidence(new ClientEvidence(header40, lookupId8, fields, imageBytes), envelopeRandom16);
        _dnasImage = (byte[])imageBytes.Clone();
        return request;
    }

    private byte[] BuildFromEvidence(ClientEvidence evidence, byte[]? envelopeRandom16 = null)
    {
        if (evidence == null) throw new ArgumentNullException(nameof(evidence));
        byte[] random16 = envelopeRandom16 == null ? _random.NextBytes(16) : (byte[])envelopeRandom16.Clone();
        _request1 = Protocol.BuildInitialPacket(evidence.Header40, evidence.LookupId8, evidence.Fields, random16);
        _request2 = null;
        _request3 = null;
        _secondResponseBody = null;
        _finalResult = null;
        _nativeReadyStatus = 0;
        return (byte[])_request1.Raw.Clone();
    }
}
