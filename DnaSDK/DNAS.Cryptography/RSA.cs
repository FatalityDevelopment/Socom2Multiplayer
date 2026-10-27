using System;
using System.Numerics;

namespace DNAS;

/// <summary>Raw RSA public operation and observed PKCS#1 v1.5 type-1 block extraction.</summary>
public static class RSA
{
    public static byte[] PublicOperation(byte[] operand128, byte[] modulus128, int exponent = Public.RsaExponent)
    {
        Guard.Size(operand128, 128, nameof(operand128));
        Guard.Size(modulus128, 128, nameof(modulus128));
        BigInteger n = new BigInteger(modulus128, isUnsigned: true, isBigEndian: true);
        BigInteger x = new BigInteger(operand128, isUnsigned: true, isBigEndian: true);
        if (n.GetBitLength() < 1017 || n.IsEven || x >= n || exponent < 3 || (exponent & 1) == 0)
            throw new ArgumentException("RSA public key or operand out of range.");
        return ToFixed(BigInteger.ModPow(x, exponent, n), 128);
    }

    public static byte[] ExtractType1(byte[] block128, int requiredMessageLength = 117)
    {
        Guard.Size(block128, 128, nameof(block128));
        if (block128[0] != 0 || block128[1] != 1) throw new FormatException("Invalid RSA type-1 block marker.");
        int i = 2;
        while (i < block128.Length && block128[i] == 0xFF) i++;
        if (i < 10 || i == 128 || block128[i] != 0) throw new FormatException("Invalid RSA type-1 padding.");
        byte[] message = block128.AsSpan(i + 1).ToArray();
        if (requiredMessageLength >= 0 && message.Length != requiredMessageLength)
            throw new FormatException($"Expected {requiredMessageLength} bytes in RSA type-1 message.");
        return message;
    }

    public static byte[] VerifyServerOperand(byte[] signedOperand128, byte[] modulus128, int exponent = Public.RsaExponent)
        => ExtractType1(PublicOperation(signedOperand128, modulus128, exponent));

    /// <summary>Signs 117-byte type-1 content with an EXPLICIT, matching private exponent. None is bundled.</summary>
    public static byte[] SignType1(byte[] message117, byte[] modulus128, byte[] privateExponent)
    {
        Guard.Size(message117, 117, nameof(message117));
        Guard.Size(modulus128, 128, nameof(modulus128));
        if (privateExponent == null || privateExponent.Length == 0) throw new ArgumentException("Explicit private exponent required.", nameof(privateExponent));
        byte[] block = new byte[128];
        block[1] = 1;
        Array.Fill(block, (byte)0xFF, 2, 8);
        Buffer.BlockCopy(message117, 0, block, 11, 117);
        BigInteger n = new BigInteger(modulus128, true, true);
        BigInteger d = new BigInteger(privateExponent, true, true);
        BigInteger m = new BigInteger(block, true, true);
        if (n.GetBitLength() < 1017 || n.IsEven || d <= 1 || m >= n) throw new ArgumentException("Invalid private key material.");
        return ToFixed(BigInteger.ModPow(m, d, n), 128);
    }

    internal static byte[] ToFixed(BigInteger number, int length)
    {
        byte[] data = number.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (data.Length > length) throw new OverflowException("RSA output wider than modulus.");
        byte[] result = new byte[length];
        Buffer.BlockCopy(data, 0, result, length - data.Length, data.Length);
        return result;
    }
}
