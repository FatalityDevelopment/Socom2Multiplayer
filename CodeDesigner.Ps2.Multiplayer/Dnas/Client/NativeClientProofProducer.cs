using System;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>
/// Connected A/B/C/D native-core producer, without packet fixtures, replay,
/// or replacement MACs. Caller provides the genuine native stage materials,
/// RNG entry state, and untouched PS2 scratch-tail bytes. The PS2 input
/// producers and native wrapper arguments must be independently verified in a
/// live trace before this can claim retail proof equivalence.
/// </summary>
public sealed class NativeClientProofProducer
{
    public readonly NativeProofRandom Random;

    public NativeClientProofProducer(NativeProofRandom rng)
    {
        Random = rng ?? throw new ArgumentNullException(nameof(rng));
    }

    /// <summary>
    /// Calls the actual native-core schedule A then B then C then D, but
    /// assembles original first-request order A40/B56/D40/C32. C and D have
    /// implicit bytes beyond their 5/9 logical inputs in uninitialized native
    /// scratch memory. Callers explicitly choose initialized managed padding
    /// or captured stack residue in isolated regression tests.
    /// </summary>
    public InitialFields Generate(ProofInputPlan identity, NativeProofCore.Material[] materials, byte[] cScratchTail3, byte[] dScratchTail7, byte parameter = 2)
    {
        if (identity == null) throw new ArgumentNullException(nameof(identity));
        if (materials == null || materials.Length != 4) throw new ArgumentException("Four original A/B/C/D stage-material banks required.", nameof(materials));
        if (cScratchTail3 == null || cScratchTail3.Length != 3) throw new ArgumentException("Actual native C scratch tail is three bytes.", nameof(cScratchTail3));
        if (dScratchTail7 == null || dScratchTail7.Length != 7) throw new ArgumentException("Actual native D scratch tail is seven bytes.", nameof(dScratchTail7));

        byte[] a = NativeProofCore.Generate(identity.A16, 16, parameter, materials[0], Random).Output;
        byte[] b = NativeProofCore.Generate(identity.B32, 32, parameter, materials[1], Random).Output;
        byte[] c = NativeProofCore.Generate(WithTail(identity.C5, cScratchTail3), 5, parameter, materials[2], Random).Output;
        byte[] d = NativeProofCore.Generate(WithTail(identity.D9, dScratchTail7), 9, parameter, materials[3], Random).Output;
        return new InitialFields(a, b, d, c);
    }

    /// <summary>
    /// Same original cipher stages, but advances the single native RNG through
    /// the caller-side draws reconstructed from the native protected wrappers.
    /// The envelope bytes are generated AFTER all four stages from that SAME
    /// RNG stream. The 3/7 unspecified scratch bytes are supplied explicitly
    /// from managed zero-initialized storage or a deterministic test witness.
    /// </summary>
    public (InitialFields fields, byte[] envelopeRandom16) GenerateScheduled(ProofInputPlan identity, NativeProofCore.Material[] materials, byte[] cScratchTail3, byte[] dScratchTail7, NativeProofDrawSchedule schedule, byte parameter = 2)
    {
        if (identity == null) throw new ArgumentNullException(nameof(identity));
        if (materials == null || materials.Length != 4) throw new ArgumentException("Four original A/B/C/D stage-material banks required.", nameof(materials));
        Guard.Size(cScratchTail3, 3, nameof(cScratchTail3));
        Guard.Size(dScratchTail7, 7, nameof(dScratchTail7));
        if (schedule == null) throw new ArgumentNullException(nameof(schedule));
        Random.Skip(schedule.BeforeFirst);
        byte[] a = NativeProofCore.Generate(identity.A16, 16, parameter, materials[0], Random).Output;
        Random.Skip(schedule.AfterStages[0]);
        byte[] b = NativeProofCore.Generate(identity.B32, 32, parameter, materials[1], Random).Output;
        Random.Skip(schedule.AfterStages[1]);
        byte[] c = NativeProofCore.Generate(WithTail(identity.C5, cScratchTail3), 5, parameter, materials[2], Random).Output;
        Random.Skip(schedule.AfterStages[2]);
        byte[] d = NativeProofCore.Generate(WithTail(identity.D9, dScratchTail7), 9, parameter, materials[3], Random).Output;
        Random.Skip(schedule.AfterStages[3]);
        return (new InitialFields(a, b, d, c), Random.NextBytes(16));
    }

    private static byte[] WithTail(byte[] logical, byte[] tail)
    {
        byte[] bytes = new byte[logical.Length + tail.Length];
        logical.CopyTo(bytes, 0);
        tail.CopyTo(bytes, logical.Length);
        return bytes;
    }
}
