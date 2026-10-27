using System;
using System.Security.Cryptography;

namespace DNAS;

/// <summary>
/// Optional signed-image validation for the artificial client. The signing
/// authority is caller-supplied; no game's public key is built into DnaSDK.
/// This class has no role in the live DNAS server.
/// </summary>
public static class NativeClientReadiness
{
    public static bool VerifyImage(byte[] image, byte[] modulus128)
    {
        return image != null && image.Length == ClientImage.ImageLength && ClientImage.VerifySignature(image, modulus128);
    }

    public static uint Initialize(byte[] image, byte[] modulus128)
    {
        if (!VerifyImage(image, modulus128)) throw new CryptographicException("The supplied client image did not validate under the specified RSA public modulus.");
        return 1;
    }
}
