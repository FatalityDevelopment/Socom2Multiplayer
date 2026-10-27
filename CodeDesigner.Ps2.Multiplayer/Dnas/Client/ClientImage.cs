using System;
using System.Security.Cryptography;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>
/// Client-side DNAS disc-image operations. No RSA key or other title-specific
/// material is included in the SDK. This class is never used to authenticate
/// an incoming request on the server.
/// </summary>
public static class ClientImage
{
    public const int RequiredPrefixLength = 0x1A7;
    public const int ImageLength = 0x10000;
    public const int SignedRegionLength = 0xFCC0;
    public const int SignatureOffset = 0xFCC0;
    public const int SignatureLength = 0x80;
    public const int UnknownTailOffset = 0xFD40;
    public const int UnknownTailLength = 0x2C0;
    public const int RecordedDiscDataOffset = 0xFC80;
    public const int RecordedDiscDataLength = 0x40;

    /// <summary>
    /// Optionally validate a complete client image using an explicitly supplied
    /// RSA public modulus. Image-signing keys are client/title data and must
    /// never be compiled into shared DNAS cryptography or server configuration.
    /// </summary>
    public static bool VerifySignature(byte[] image, byte[] modulus128)
    {
        Guard.Size(image, ImageLength, nameof(image));
        Guard.Size(modulus128, 128, nameof(modulus128));

        byte[] signature = GetSignatureRecord(image);
        byte[] block;

        try
        {
            block = RSA.PublicOperation(signature, modulus128);
        }
        catch (ArgumentException)
        {
            return false;
        }

        // Observed 128-byte image-signature record: 00 01, 105 FF bytes,
        // a zero separator, then a raw 20-byte SHA-1 digest.
        if (block[0] != 0x00 || block[1] != 0x01 || block[107] != 0x00) return false;
        for (int i = 2; i < 107; i++)
        {
            if (block[i] != 0xFF) return false;
        }

        byte[] digest = ComputeSignedRegionSha1(image);
        return CryptographicOperations.FixedTimeEquals(block.AsSpan(108, 20), digest);
    }

    /// <summary>Calculate the SHA-1 digest of the observed signed image region.</summary>
    public static byte[] ComputeSignedRegionSha1(byte[] image)
    {
        Guard.Size(image, ImageLength, nameof(image));
        return SHA1.HashData(image.AsSpan(0, SignedRegionLength));
    }

    /// <summary>Extract the signature carried by the supplied client image.</summary>
    public static byte[] GetSignatureRecord(byte[] image)
    {
        Guard.Size(image, ImageLength, nameof(image));
        return image.AsSpan(SignatureOffset, SignatureLength).ToArray();
    }

    /// <summary>
    /// Derive the S1 DES key from the received eight-byte Challenge A and the
    /// caller-supplied image bytes. The lengths and offsets come from A, not a
    /// hard-coded title or a historical response.
    /// </summary>
    public static byte[] DeriveFirstReplyKey(byte[] image, byte[] challenge8A)
    {
        Guard.Size(challenge8A, 8, nameof(challenge8A));

        int requiredPrefix = Math.Max(challenge8A[5] + challenge8A[1], Math.Max(challenge8A[6] + challenge8A[2], challenge8A[7] + challenge8A[3]));
        if (image == null || image.Length < requiredPrefix)
        {
            throw new ArgumentException("The image does not contain all Challenge A-selected SHA-1 ranges.", nameof(image));
        }

        byte[] accumulated = SHA1.HashData(image.AsSpan(challenge8A[5], challenge8A[1]));
        byte[] third = SHA1.HashData(image.AsSpan(challenge8A[6], challenge8A[2]));
        byte[] fourth = SHA1.HashData(image.AsSpan(challenge8A[7], challenge8A[3]));

        for (int i = 0; i < 20; i++)
        {
            accumulated[i] ^= (byte)(third[i] ^ fourth[i]);
        }

        byte[] key8 = new byte[8];
        for (int i = 0; i < key8.Length; i++)
        {
            key8[i] = (byte)(accumulated[i] ^ accumulated[i + 8] ^ (i < 4 ? accumulated[i + 16] : 0));
        }

        return key8;
    }
}
