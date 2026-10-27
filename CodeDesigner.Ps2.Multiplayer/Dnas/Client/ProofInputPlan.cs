using System;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>
/// Exact pre-encryption inputs recovered from the PS2's four proof-producing
/// wrappers. This is a preparation snapshot, not an authenticated proof.
/// </summary>
public sealed class ProofInputPlan
{
    public readonly string GameSerial;
    public readonly byte[] DiscId5;
    public readonly byte[] CDVD_READ_24;
    public readonly byte[] CDVD_READ_26;
    public readonly byte[] CDVD_READ_KEY;
    public readonly byte[] A16;
    public readonly byte[] B32;
    public readonly byte[] C5;
    public readonly byte[] D9;

    private ProofInputPlan(string serial, ProofHardwareResults hardware)
    {
        GameSerial = Identity.NormalizeGameSerial(serial);
        if (hardware == null) throw new ArgumentNullException(nameof(hardware));
        CDVD_READ_24 = (byte[])hardware.CDVD_READ_24.Clone();
        CDVD_READ_26 = (byte[])hardware.CDVD_READ_26.Clone();
        CDVD_READ_KEY = (byte[])hardware.CDVD_READ_KEY.Clone();
        DiscId5 = (byte[])CDVD_READ_KEY.Clone();
        A16 = ProofInputs.FromCdvdResults(CDVD_READ_24, CDVD_READ_26);
        B32 = ProofInputs.InitialB32();
        C5 = ProofInputs.FromDiscDnasId(CDVD_READ_KEY);
        D9 = ProofInputs.FromGameSerial(GameSerial);
    }

    /// <summary>
    /// Native proof inputs as recovered from an incoming C1. Only the 16/32/5/9
    /// plaintext inputs can be recovered: neither the complete CDVD ReadKey5,
    /// the original 0x24/0x26 RPC buffers, nor an i.Link ID are invented.
    /// This is client-supplied evidence, NOT independent hardware authorization.
    /// </summary>
    public static ProofInputPlan FromClientProofs(byte[] a16, byte[] b32, byte[] c5, byte[] d9)
        => new ProofInputPlan(a16, b32, c5, d9);

    private ProofInputPlan(byte[] a16, byte[] b32, byte[] c5, byte[] d9)
    {
        Guard.Size(a16, 16, nameof(a16));
        Guard.Size(b32, 32, nameof(b32));
        Guard.Size(c5, 5, nameof(c5));
        Guard.Size(d9, 9, nameof(d9));
        A16 = (byte[])a16.Clone();
        B32 = (byte[])b32.Clone();
        C5 = (byte[])c5.Clone();
        D9 = (byte[])d9.Clone();
        GameSerial = System.Text.Encoding.ASCII.GetString(d9.AsSpan(0, 4)) + "-" + System.Text.Encoding.ASCII.GetString(d9.AsSpan(4, 5));
        // The inverse disc helper only exposes ReadKey[0..4), NOT ReadKey[4].
        // Empty means unavailable rather than manufacturing a fifth byte.
        DiscId5 = Array.Empty<byte>();
        CDVD_READ_KEY = Array.Empty<byte>();
        CDVD_READ_24 = Array.Empty<byte>();
        CDVD_READ_26 = Array.Empty<byte>();
    }

    /// <summary>
    /// Deterministic input construction for debugging the captured PS2 algorithm.
    /// The 0x24 GUID and 0x26 ModelID RPC buffers are kept independently.
    /// 0x26 produces four defined ModelID bytes, while the captured EE helper
    /// copies eight bytes; its unobserved four trailing bytes remain unknown.
    /// </summary>
    public static ProofInputPlan Prepare(string gameSerial, string dnasID, byte[] cdvdRead24, byte[] cdvdRead26)
        => new ProofInputPlan(gameSerial, new ProofHardwareResults(cdvdRead24, cdvdRead26, Public.ParseDnasId(dnasID)));

    public static ProofInputPlan Prepare(string gameSerial, ProofHardwareResults hardware) => new ProofInputPlan(gameSerial, hardware);

    /// <summary>
    /// Derives the original CDVDFSV RPC 0x24 GUID and RPC 0x26 ModelID from
    /// the full eight-byte i.Link identity on the documented normal boot
    /// path. Special boot modes require their actual CDVD RPC results and
    /// should instead call Prepare(serial, ProofHardwareResults).
    /// The five-byte ReadKey result remains a separate disc-specific input.
    /// </summary>
    public static ProofInputPlan PrepareNormalBoot(string gameSerial, byte[] iLinkId8, byte[] discReadKey5)
    {
        Guard.Size(iLinkId8, 8, nameof(iLinkId8));
        Guard.Size(discReadKey5, 5, nameof(discReadKey5));
        return new ProofInputPlan(gameSerial, new ProofHardwareResults(CdvdIdentity.ReadGuid24(iLinkId8), CdvdIdentity.ReadModelId26(iLinkId8), discReadKey5));
    }

    /// <summary>
    /// Original PS2 producer execution order is A,B,C,D. The resulting packet
    /// order is A40,B56,D40,C32. Never accidentally swap the latter two.
    /// </summary>
    public byte[][] InputOrder() => new byte[][] { (byte[])A16.Clone(), (byte[])B32.Clone(), (byte[])C5.Clone(), (byte[])D9.Clone() };

    /// <summary>Captures the decoded proof envelope sizes without inventing ciphertext.</summary>
    public int[] OutputLengths() => new int[] { 40, 56, 32, 40 };
}
