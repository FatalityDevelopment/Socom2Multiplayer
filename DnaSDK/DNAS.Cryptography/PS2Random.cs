using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace DNAS;

/// <summary>
/// The byte generator observed in the PS2 DNAS routine.
/// Each new client seeds it independently; callers do not provide emulator RAM or a PS2 RNG state.
/// The original SDK's seed-source logic is not yet recovered, so the standalone implementation
/// seeds the observed LCG using operating-system entropy. This does not alter the wire format.
/// </summary>
internal sealed class PS2Random
{
    private ulong _state;

    internal PS2Random()
    {
        Span<byte> seed = stackalloc byte[8];
        RandomNumberGenerator.Fill(seed);
        _state = BinaryPrimitives.ReadUInt64LittleEndian(seed);
    }

    // Deterministic witness support for internal regression tests only.
    internal PS2Random(ulong seed) { _state = seed; }

    internal byte[] NextBytes(int count) => Protocol.LcgBytes(ref _state, count);
}
