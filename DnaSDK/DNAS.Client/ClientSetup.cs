using System;

namespace DNAS;

/// <summary>
/// Native client's four external authentication inputs, with the remaining
/// hardware/runtime values calculated locally. It does not use PX86, stored
/// packets, per-game proof rules, a signing key, or external evidence providers.
///
/// The RTC value is sampled once when the setup is prepared, as a PS2 CDVD
/// eight-byte BCD clock. Other client operations may request later samples;
/// do not assume all original native calls share the first RTC result.
/// </summary>
public sealed class ClientSetup
{
    public readonly byte[] ConsoleId8;
    public readonly byte[] DiscDnasId5;
    public readonly byte[] DnasImage;
    public readonly string GameSerial;
    public readonly ProofInputPlan Identity;
    public readonly byte[] InitialCdvdClock8;
    public readonly uint InitialRngSeed;
    private readonly bool _fixedClockForTest;
    private readonly byte[] _cScratchTail3;
    private readonly byte[] _dScratchTail7;

    private ClientSetup(byte[] consoleId8, byte[] discDnasId5, byte[] dnasImage, string gameSerial, byte[] initialCdvdClock8, bool fixedClockForTest, byte[] cScratchTail3, byte[] dScratchTail7)
    {
        Guard.Size(consoleId8, 8, nameof(consoleId8));
        Guard.Size(discDnasId5, 5, nameof(discDnasId5));
        Guard.Size(dnasImage, ClientImage.ImageLength, nameof(dnasImage));
        Guard.Size(initialCdvdClock8, 8, nameof(initialCdvdClock8));
        GameSerial = DNAS.Identity.NormalizeGameSerial(gameSerial);
        ConsoleId8 = (byte[])consoleId8.Clone();
        DiscDnasId5 = (byte[])discDnasId5.Clone();
        DnasImage = (byte[])dnasImage.Clone();
        InitialCdvdClock8 = (byte[])initialCdvdClock8.Clone();
        _fixedClockForTest = fixedClockForTest;
        Guard.Size(cScratchTail3, 3, nameof(cScratchTail3));
        Guard.Size(dScratchTail7, 7, nameof(dScratchTail7));
        _cScratchTail3 = (byte[])cScratchTail3.Clone();
        _dScratchTail7 = (byte[])dScratchTail7.Clone();
        Identity = ProofInputPlan.PrepareNormalBoot(GameSerial, ConsoleId8, DiscDnasId5);
        InitialRngSeed = NativeProofRandom.SeedFromCdvdClock(InitialCdvdClock8);
    }

    /// <summary>Exactly four external client inputs; RTC is generated internally.</summary>
    public static ClientSetup Create(byte[] consoleId8, byte[] discDnasId5, byte[] dnasImage, string gameSerial)
        => new ClientSetup(consoleId8, discDnasId5, dnasImage, gameSerial, Clock.FromHostLocalTime(), false, new byte[3], new byte[7]);

    /// <summary>
    /// Test-only deterministic clock injection. The eight clock bytes are not
    /// a fifth authentication credential and are never added to the client API.
    /// </summary>
    internal static ClientSetup CreateForTest(byte[] consoleId8, byte[] discDnasId5, byte[] dnasImage, string gameSerial, byte[] clock8, byte[] cScratchTail3, byte[] dScratchTail7)
        => new ClientSetup(consoleId8, discDnasId5, dnasImage, gameSerial, clock8, true, cScratchTail3, dScratchTail7);

    /// <summary>
    /// Each original producer A/B/C/D calls sceCdReadClock separately at
    /// 0x0052E4FC / 0x0052E7EC / 0x0052ECC4 / 0x0052F1CC. These are distinct
    /// from the earlier RNG-seed read at 0x0052F3D8. Never reuse the seed
    /// clock unconditionally for all four calls in a live client.
    /// </summary>
    internal byte[] ReadProofClock8(int stage)
    {
        if ((uint)stage >= 4) throw new ArgumentOutOfRangeException(nameof(stage));
        return _fixedClockForTest ? (byte[])InitialCdvdClock8.Clone() : Clock.FromHostLocalTime();
    }

    /// <summary>
    /// The native C/D helpers write only 5/9 logical bytes, leaving three/seven
    /// aligned scratch bytes unspecified. The managed SDK uses zero-initialized
    /// storage for these unused bytes. This is NOT a claim that retail stacks
    /// always held zero; the native inverse validates only logical identity.
    /// Test fixtures may supply observed native scratch residues explicitly.
    /// </summary>
    internal byte[] NativeScratchTail3() => (byte[])_cScratchTail3.Clone();
    internal byte[] NativeScratchTail7() => (byte[])_dScratchTail7.Clone();

    public NativeProofRandom NewNativeRandom() => new NativeProofRandom(InitialRngSeed);
}
