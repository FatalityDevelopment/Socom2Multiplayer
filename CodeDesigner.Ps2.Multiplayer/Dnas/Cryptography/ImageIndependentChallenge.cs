using System;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>
/// Hashes the exact DNAS image ranges consumed by the PS2 when deriving the
/// first server reply's DES challenge key. Offsets are relative to the image
/// buffer beginning at EE 0x005498DC, not to an ELF/ISO file header.
/// </summary>
/// <summary>
/// Image-independent first-reply challenge supported by the original PS2 client.
/// Challenge A bytes 0..3 are SHA-1 input lengths; when all are zero, all
/// three effective SHA-1 operations hash the empty sequence, regardless of
/// the image or the offsets in A[4..7]. The resulting DES key is thus
/// calculable by any server without possession of a game-specific image.
/// This preserves the DES ciphertext/response check, but it does NOT prove
/// possession or validity of the client's DNAS image.
/// </summary>

public static class ImageIndependentChallenge
{
    /// <summary>Original retail client confirmed to process the all-zero A.</summary>
    public static byte[] NewChallengeA() => new byte[8];

    /// <summary>Optional diagnostic: random image offsets but zero image lengths.</summary>
    public static byte[] NewRandomOffsetChallengeA()
    {
        byte[] challenge = new byte[8];
        RandomNumberGenerator.Fill(challenge.AsSpan(4, 4));
        return challenge;
    }

    public static byte[] DeriveKey(byte[] challenge8A)
    {
        Guard.Size(challenge8A, 8, nameof(challenge8A));
        if (challenge8A[0] != 0 || challenge8A[1] != 0 || challenge8A[2] != 0 || challenge8A[3] != 0)
            throw new CryptographicException("Image-independent DNAS S1 requires zero-length Challenge A image ranges.");
        // The original routine XORs the last THREE 20-byte digests. For zero
        // lengths, SHA1(empty) XOR SHA1(empty) XOR SHA1(empty) = SHA1(empty).
        byte[] digest = SHA1.HashData(ReadOnlySpan<byte>.Empty);
        byte[] key8 = new byte[8];
        for (int i = 0; i < 8; i++) key8[i] = (byte)(digest[i] ^ digest[i + 8] ^ (i < 4 ? digest[i + 16] : 0));
        return key8;
    }
}
