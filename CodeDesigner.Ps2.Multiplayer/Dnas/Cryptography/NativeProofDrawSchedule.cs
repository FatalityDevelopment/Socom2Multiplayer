using System;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>
/// Native RNG consumption outside the four shared proof-core calls.
/// The successful caller's 16/16/32/5/5 draws are now directly recovered
/// from the original protected A helper and A/B/C/D wrappers, verified
/// independently against the original module. Core draws (120/136/112/120)
/// are computed by NativeProofCore. Non-successful paths differ.
/// </summary>
public sealed class NativeProofDrawSchedule
{
    public readonly int BeforeFirst;
    public readonly int[] AfterStages;

    public NativeProofDrawSchedule(int beforeFirst, int[] afterStages)
    {
        if (beforeFirst < 0) throw new ArgumentOutOfRangeException(nameof(beforeFirst));
        if (afterStages == null || afterStages.Length != 4) throw new ArgumentException("Four A/B/C/D caller draw counts are required.", nameof(afterStages));
        for (int i = 0; i < 4; i++) if (afterStages[i] < 0) throw new ArgumentOutOfRangeException(nameof(afterStages));
        BeforeFirst = beforeFirst;
        AfterStages = (int[])afterStages.Clone();
    }
}
