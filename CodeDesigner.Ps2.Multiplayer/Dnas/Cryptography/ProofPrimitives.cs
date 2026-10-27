using System;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>
/// Byte operations recovered directly from the PS2 proof-engine helpers.
/// These are individual verified primitives, not a complete proof generator.
/// </summary>
public static class ProofPrimitives
{
    /// <summary>
    /// 0x0052F5F0–0x0052F628: XOR exactly eight bytes from source into
    /// destination, modifying the destination and returning its eight bytes.
    /// The original routine returns the destination pointer on success.
    /// </summary>
    public static byte[] Xor8(byte[] source8, byte[] destination8)
    {
        if (source8 == null || source8.Length != 8) throw new ArgumentException("The source must contain eight bytes.", nameof(source8));
        if (destination8 == null || destination8.Length != 8) throw new ArgumentException("The destination must contain eight bytes.", nameof(destination8));
        for (int i = 0; i < 8; i++) destination8[i] ^= source8[i];
        return destination8;
    }
}
