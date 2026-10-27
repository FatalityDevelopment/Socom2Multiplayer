using System;
using System.Security.Cryptography;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>
/// The decrypted inputs used to construct one S1 response.
/// The RSA operand is the original server-issued signed record, not a TLS key.
/// All arrays are copied so callers cannot change a challenge after it is issued.
/// </summary>
public sealed class FirstResponseData
{
    public readonly byte[] ResponseHeader40;
    public readonly byte[] Challenge8A;
    public readonly byte[] DesCiphertext16;
    public readonly byte[] Challenge8B;
    public readonly byte[] RsaOperand128;
    // Optional offline public-key diagnostic. Never needed to transmit S1.
    public readonly byte[]? RsaModulus128;
    public readonly byte[] Nested32;
    public readonly byte[] Tail96;

    public FirstResponseData(byte[] responseHeader40, byte[] challenge8A, byte[] desCiphertext16, byte[] challenge8B, byte[] rsaOperand128, byte[] nested32, byte[] tail96, byte[]? rsaModulus128 = null)
    {
        Guard.Size(responseHeader40, 40, nameof(responseHeader40));
        Guard.Size(challenge8A, 8, nameof(challenge8A));
        Guard.Size(desCiphertext16, 16, nameof(desCiphertext16));
        Guard.Size(challenge8B, 8, nameof(challenge8B));
        Guard.Size(rsaOperand128, 128, nameof(rsaOperand128));
        Guard.Size(nested32, 32, nameof(nested32));
        Guard.Size(tail96, 96, nameof(tail96));

        if (rsaModulus128 != null) Guard.Size(rsaModulus128, 128, nameof(rsaModulus128));

        ResponseHeader40 = (byte[])responseHeader40.Clone();
        Challenge8A = (byte[])challenge8A.Clone();
        DesCiphertext16 = (byte[])desCiphertext16.Clone();
        Challenge8B = (byte[])challenge8B.Clone();
        RsaOperand128 = (byte[])rsaOperand128.Clone();
        RsaModulus128 = rsaModulus128 == null ? null : (byte[])rsaModulus128.Clone();
        Nested32 = (byte[])nested32.Clone();
        Tail96 = (byte[])tail96.Clone();
    }

    /// <summary>
    /// Construct an S1 record with an explicitly supplied original RSA signing key.
    /// This optional producer is not used by the ticket-backed live server.
    /// No private key is bundled with DnaSDK.
    /// </summary>
    public static FirstResponseData WithSigner(byte[] responseHeader40, byte[] challenge8A, byte[] desCiphertext16, byte[] challenge8B, byte[] message117, byte[] modulus128, byte[] privateExponent, byte[] nested32, byte[] tail96)
    {
        Guard.Size(message117, 117, nameof(message117));
        Guard.Size(modulus128, 128, nameof(modulus128));

        byte[] operand = RSA.SignType1(message117, modulus128, privateExponent);
        byte[] verifiedMessage = RSA.VerifyServerOperand(operand, modulus128);

        if (!CryptographicOperations.FixedTimeEquals(verifiedMessage, message117))
            throw new CryptographicException("Signing exponent did not generate a valid original RSA record.");

        return new FirstResponseData(responseHeader40, challenge8A, desCiphertext16, challenge8B, operand, nested32, tail96, modulus128);
    }

    /// <summary>
    /// Uses the original image-independent Challenge A calculation and an explicitly
    /// supplied RSA signing exponent to produce both cryptographic S1 fields.
    /// </summary>
    public static FirstResponseData WithOriginalAuthority(byte[] responseHeader40, byte[] challenge8A, byte[] expectedClient16, byte[] challenge8B, byte[] message117, byte[] modulus128, byte[] privateExponent, byte[] nested32, byte[] tail96)
    {
        Guard.Size(expectedClient16, 16, nameof(expectedClient16));

        byte[] key8 = ImageIndependentChallenge.DeriveKey(challenge8A);
        byte[] encrypted16 = DES.Encrypt(expectedClient16, key8);
        return WithSigner(responseHeader40, challenge8A, encrypted16, challenge8B, message117, modulus128, privateExponent, nested32, tail96);
    }
}
