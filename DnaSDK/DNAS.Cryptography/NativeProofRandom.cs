// Related protocol definitions maintained together.
namespace DNAS
{
using System;

/// <summary>
/// The original DNAS module's clock-seeded 64-bit random generator. The seed
/// assembly is reconstructed from EE 0x0052F3D8..0x0052F444, including the
/// call through 0x0052F358 which zero-extends the resulting 32-bit seed.
/// The recurrence and byte extraction are reconstructed from 0x0052F370 and
/// its 0x001A1150 / 0x001A0C18 / 0x001A1330 floating-point conversion path.
/// This does not, by itself, generate or verify an encrypted proof envelope.
/// </summary>

public sealed class NativeProofRandom
{
    private const ulong Multiplier = 0x5851F42D4C957F2DUL;
    public ulong State;

    public NativeProofRandom(ulong state) { State = state; }

    /// <summary>
    /// Takes the eight raw sceCdCLOCK bytes returned to EE 0x0018F6E0.
    /// This consumes bytes, not a DateTime: no host clock or time-zone
    /// substitution occurs. Indices 1,2,3,5 (BCD time fields) become
    /// the seed's bytes from most significant to least significant.
    /// </summary>
    public static uint SeedFromCdvdClock(ReadOnlySpan<byte> clock8)
    {
        if (clock8.Length != 8) throw new ArgumentException("Expected eight original CDVD clock bytes.", nameof(clock8));
        return ((uint)clock8[1] << 24) | ((uint)clock8[2] << 16) | ((uint)clock8[3] << 8) | clock8[5];
    }

    public static NativeProofRandom FromCdvdClock(ReadOnlySpan<byte> clock8) => new(SeedFromCdvdClock(clock8));

    /// <summary>Recreates one 0x0052F370 random draw and its 8-bit conversion.</summary>
    public byte NextByte()
    {
        State = unchecked(State * Multiplier + 1);
        // Original returns ((state >> 32) & 0x7FFFFFFF). The caller converts
        // that to double, multiplies by 2^-31 and 256, then truncates to byte.
        return (byte)(State >> 55);
    }

    public byte[] NextBytes(int count)
    {
        if (count < 0) throw new ArgumentOutOfRangeException(nameof(count));
        byte[] result = new byte[count];
        for (int i = 0; i < count; i++) result[i] = NextByte();
        return result;
    }

    /// <summary>Advance the original RNG through known caller-side draws without allocating a buffer.</summary>
    public void Skip(int draws)
    {
        if (draws < 0) throw new ArgumentOutOfRangeException(nameof(draws));
        for (int i = 0; i < draws; i++) NextByte();
    }

    /// <summary>
    /// Reconstructs only the two 8-byte RNG work areas made at 0x00533B28
    /// and 0x00533B90. At 0x00533B70..0x00533B84, byte zero of the FIRST
    /// work area is replaced with (4*byte + common-engine final parameter)
    /// modulo 256. The SECOND work area is not modified here.
    /// Caller must provide the original state at entry; earlier RNG draws
    /// from other routines are not inferred or skipped automatically.
    /// </summary>
    /// <summary>
    /// Emulates RNG consumption for one SUCCESSFUL original proof-core call.
    /// Decoded EE 0x533B28/0x533B90 draws 16 bytes before encryption.
    /// Epilogue 0x533DB8 draws outputCapacity more bytes into a temporary
    /// staging area, then 0x533E18 and 0x533E68 each draw 32 bytes to
    /// overwrite two local work areas. These epilogue draws change the RNG
    /// state seen by subsequent producers A/B/C/D.
    ///
    /// This models the successful path's random-byte schedule only; the
    /// cipher operations and any RNG calls outside this proof routine are
    /// not inferred. The caller supplies the ACTUAL RNG entry state.
    /// </summary>
    public NativeProofStageRandomTrace TraceSuccessfulStage(int inputBytes, int outputCapacity, byte parameter)
    {
        if (inputBytes < 0 || inputBytes > int.MaxValue - 31) throw new ArgumentOutOfRangeException(nameof(inputBytes));
        int required = ((inputBytes + 7) & ~7) + 24;
        if (outputCapacity < required) throw new ArgumentOutOfRangeException(nameof(outputCapacity), "Original engine rejects insufficient output capacity before generating its two work areas.");
        ulong start = State;
        var (first, second) = CreateSharedEngineWorkAreas(parameter);
        byte[] stagingScrub = NextBytes(outputCapacity);
        byte[] lowerScrub = NextBytes(32);
        byte[] upperScrub = NextBytes(32);
        return new NativeProofStageRandomTrace(start, State, inputBytes, outputCapacity, first, second, stagingScrub, lowerScrub, upperScrub);
    }

    public (byte[] first8, byte[] second8) CreateSharedEngineWorkAreas(byte parameter)
    {
        byte[] first = NextBytes(8);
        first[0] = unchecked((byte)((first[0] << 2) + parameter));
        byte[] second = NextBytes(8);
        return (first, second);
    }
}

/// <summary>Trace of original proof-core RNG draws and its successful-path buffer cleanup.</summary>
}

namespace DNAS
{
using System;

/// <summary>
/// The original DNAS module's clock-seeded 64-bit random generator. The seed
/// assembly is reconstructed from EE 0x0052F3D8..0x0052F444, including the
/// call through 0x0052F358 which zero-extends the resulting 32-bit seed.
/// The recurrence and byte extraction are reconstructed from 0x0052F370 and
/// its 0x001A1150 / 0x001A0C18 / 0x001A1330 floating-point conversion path.
/// This does not, by itself, generate or verify an encrypted proof envelope.
/// </summary>

public sealed class NativeProofStageRandomTrace
{
    public readonly ulong StartState;
    public readonly ulong EndState;
    public readonly int InputBytes;
    public readonly int OutputCapacity;
    public readonly int DrawCount;
    public readonly byte[] First8;
    public readonly byte[] Second8;
    public readonly byte[] StagingScrub;
    public readonly byte[] LocalLowScrub32;
    public readonly byte[] LocalHighScrub32;

    public NativeProofStageRandomTrace(ulong start, ulong end, int inputBytes, int capacity, byte[] first8, byte[] second8, byte[] staging, byte[] low, byte[] high)
    {
        StartState = start;
        EndState = end;
        InputBytes = inputBytes;
        OutputCapacity = capacity;
        DrawCount = 16 + capacity + 64;
        First8 = first8;
        Second8 = second8;
        StagingScrub = staging;
        LocalLowScrub32 = low;
        LocalHighScrub32 = high;
    }
}
}

