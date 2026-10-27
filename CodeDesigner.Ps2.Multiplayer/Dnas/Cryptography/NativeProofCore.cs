using System;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>
/// The four native cipher operations in the decoded shared proof engine
/// (0x00533AE8..0x00533DA0), including the two DES-derived 32-byte work
/// regions, buffer shuffle and final RNG cleanup. All caller-sourced material
/// is explicit: no packet fixture, substituted key, assumed stack padding,
/// or invented RNG seed enters the producer.
///
/// The first pass enters through 0x005339E0 -> 0x00530840, NOT
/// the distinct inverse adapter at 0x005309E0. The later passes also use
/// 0x00530840 (middle via 0x005309B0).
/// This is a native-core reconstruction, not yet a verified A/B/C/D producer:
/// the caller's original pointers and runtime seed still require tracing.
/// </summary>
public static class NativeProofCore
{
    /// <summary>All six external pointer/material regions referenced by the core, and the shared DNAS
    /// final DES/ECB material used by the last pass. Caller material is 8/32/8/32/32/8.
    /// The global bytes may be mutable at runtime: supply live values, not implicit constants.</summary>
    public sealed class Material
    {
        public readonly byte[] InitialEcbSource32; // t1 at function entry, EE fp+0x48
        public readonly byte[] InitialEcbKey8;     // ninth argument, EE fp+0xE0
        public readonly byte[] FirstBlockSource8;  // t2 at function entry, EE fp+0x4C
        public readonly byte[] FirstBlockKeyIv32; // t3 at function entry, EE fp+0x50
        public readonly byte[] FinalEcbSource32;  // DNAS final-pass DES source
        public readonly byte[] FinalEcbKey8;      // DNAS final-pass DES key

        public Material(byte[] initialEcbSource32, byte[] initialEcbKey8, byte[] firstBlockSource8, byte[] firstBlockKeyIv32, byte[] finalEcbSource32, byte[] finalEcbKey8)
        {
            InitialEcbSource32 = Copy(initialEcbSource32, 32, nameof(initialEcbSource32));
            InitialEcbKey8 = Copy(initialEcbKey8, 8, nameof(initialEcbKey8));
            FirstBlockSource8 = Copy(firstBlockSource8, 8, nameof(firstBlockSource8));
            FirstBlockKeyIv32 = Copy(firstBlockKeyIv32, 32, nameof(firstBlockKeyIv32));
            FinalEcbSource32 = Copy(finalEcbSource32, 32, nameof(finalEcbSource32));
            FinalEcbKey8 = Copy(finalEcbKey8, 8, nameof(finalEcbKey8));
        }
    }

    /// <summary>Intermediate snapshots for native trace comparisons, never reused as an output fixture.</summary>
    public sealed class Trace
    {
        public readonly byte[] Output;
        public readonly byte[] InitialFrame32;
        public readonly byte[] FinalFrame32;
        public readonly byte[] FirstBlock8;
        public readonly byte[] AfterLongPass;
        public readonly byte[] AfterAssembly;
        public readonly byte[] AfterMiddlePass;
        public readonly ulong RngStartState;
        public readonly ulong RngEndState;
        public readonly int RngDraws;
        public readonly byte[] FirstWork8;
        public readonly byte[] SecondWork8;

        internal Trace(byte[] output, byte[] initialFrame, byte[] finalFrame, byte[] firstBlock, byte[] longPass, byte[] assembled, byte[] middle, ulong start, ulong end, int draws, byte[] first8, byte[] second8)
        {
            Output = output;
            InitialFrame32 = initialFrame;
            FinalFrame32 = finalFrame;
            FirstBlock8 = firstBlock;
            AfterLongPass = longPass;
            AfterAssembly = assembled;
            AfterMiddlePass = middle;
            RngStartState = start;
            RngEndState = end;
            RngDraws = draws;
            FirstWork8 = first8;
            SecondWork8 = second8;
        }
    }

    /// <summary>
    /// The raw input span includes the padded tail, because decoded MIPS copies only
    /// the logical input length. The untouched stack bytes following C5/D9 are not
    /// proven to be zero. Requiring an explicit tail avoids manufacturing those bytes.
    /// </summary>
    public static Trace Generate(byte[] inputWithPaddedTail, int logicalInputBytes, byte finalParameter, Material material, NativeProofRandom rng)
    {
        if (material == null) throw new ArgumentNullException(nameof(material));
        if (rng == null) throw new ArgumentNullException(nameof(rng));
        if (logicalInputBytes < 0 || logicalInputBytes > int.MaxValue - 31) throw new ArgumentOutOfRangeException(nameof(logicalInputBytes));
        int padded = (logicalInputBytes + 7) & ~7;
        if (inputWithPaddedTail == null || inputWithPaddedTail.Length != padded)
            throw new ArgumentException("Pass the actual native padded span, not a guessed zero-filled tail.", nameof(inputWithPaddedTail));
        int length = checked(padded + 24);
        ulong start = rng.State;
        var (first, second) = rng.CreateSharedEngineWorkAreas(finalParameter);
        byte[] scratch = new byte[length];
        first.CopyTo(scratch, 0);
        second.CopyTo(scratch, 8);

        // 0x533BE4 enters 0x5339E0 -> 0x530840, the forward native wrapper.
        // Save all four caller-sourced key and IV blocks *before* touching the destination.
        byte[] firstBlock = DES.Encrypt3(material.FirstBlockSource8, material.FirstBlockKeyIv32.AsSpan(0, 24).ToArray(), material.FirstBlockKeyIv32.AsSpan(24, 8).ToArray());
        firstBlock.CopyTo(scratch, 16);
        // 0x533C08..0x533C24 copies the logical bytes, not the rounded length.
        // The caller supplies any originally existing bytes in the untouched tail.
        inputWithPaddedTail.AsSpan().CopyTo(scratch.AsSpan(24));

        // 0x533C34: 0x530500 (DES/ECB) creates fp[0..32).
        byte[] firstFrame = DES.Encrypt(material.InitialEcbSource32, material.InitialEcbKey8);
        // 0x533C74: 0x530840 processes scratch[8..length) in place.
        EncryptInPlace(scratch, 8, length - 8, firstFrame, 24, 8, 16, 0);
        byte[] afterLong = (byte[])scratch.Clone();

        // 0x533C88..0x533D00: [scratch0..8, scratch16.., scratch8..16].
        byte[] output = NativeProofAssembly.AssembleAfterLongPass(scratch, length);
        byte[] afterAssembly = (byte[])output.Clone();

        // 0x533D20 enters 0x5309B0 -> 0x530840. The adapter remaps
        // K3 to output[0..8), NOT output[24..32). All key/IV data is snapshotted.
        byte[] middleKey = Join(output.AsSpan(0, 8), output.AsSpan(16, 8), output.AsSpan(0, 8));
        byte[] middleIv = output.AsSpan(8, 8).ToArray();
        byte[] middle = DES.Encrypt3(output.AsSpan(24, length - 24).ToArray(), middleKey, middleIv);
        middle.CopyTo(output, 24);
        byte[] afterMiddle = (byte[])output.Clone();

        // 0x533D5C: 0x530500 creates fp[32..64) from the native globals.
        // 0x533D90: 0x530840 uses fp+32, +48, +40 and IV at +56.
        byte[] finalFrame = DES.Encrypt(material.FinalEcbSource32, material.FinalEcbKey8);
        EncryptInPlace(output, 8, length - 8, finalFrame, 0, 16, 8, 24);

        // 0x533DB8, 0x533E18, 0x533E68 scrub length, 32, 32 bytes.
        // Preserve exact shared RNG advancement; no per-stage reseeding.
        rng.NextBytes(length);
        rng.NextBytes(32);
        rng.NextBytes(32);
        return new Trace(output, firstFrame, finalFrame, firstBlock, afterLong, afterAssembly, afterMiddle, start, rng.State, 16 + length + 64, first, second);
    }

    private static void EncryptInPlace(byte[] data, int offset, int length, byte[] frame, int k1, int k2, int k3, int iv)
    {
        byte[] key = Join(frame.AsSpan(k1, 8), frame.AsSpan(k2, 8), frame.AsSpan(k3, 8));
        byte[] vector = frame.AsSpan(iv, 8).ToArray();
        DES.Encrypt3(data.AsSpan(offset, length).ToArray(), key, vector).CopyTo(data, offset);
    }

    private static byte[] Join(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c)
    {
        byte[] result = new byte[24];
        a.CopyTo(result.AsSpan(0, 8));
        b.CopyTo(result.AsSpan(8, 8));
        c.CopyTo(result.AsSpan(16, 8));
        return result;
    }

    private static byte[] Copy(byte[] input, int size, string name)
    {
        if (input == null || input.Length != size) throw new ArgumentException("Expected exactly " + size + " bytes.", name);
        return (byte[])input.Clone();
    }
}
