using System;
using System.Security.Cryptography;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>Single DES and three-key EDE DES, ECB/CBC, without implicit padding.</summary>
public static class DES
{
    public static byte[] WithOddParity(byte[] key)
    {
        Guard.Size(key, 8, nameof(key));
        byte[] result = new byte[8];
        for (int i = 0; i < 8; i++)
        {
            byte value = (byte)(key[i] & 0xFE);
            int parity = System.Numerics.BitOperations.PopCount((uint)value) & 1;
            result[i] = (byte)(value | (parity ^ 1));
        }
        return result;
    }

    public static byte[] Encrypt(byte[] data, byte[] key8, byte[]? iv8 = null) => Transform(data, key8, iv8, false);
    public static byte[] Decrypt(byte[] data, byte[] key8, byte[]? iv8 = null) => Transform(data, key8, iv8, true);
    public static byte[] Encrypt3(byte[] data, byte[] key24, byte[]? iv8 = null) => Transform(data, key24, iv8, false);
    public static byte[] Decrypt3(byte[] data, byte[] key24, byte[]? iv8 = null) => Transform(data, key24, iv8, true);

    private static byte[] Transform(byte[] data, byte[] key, byte[]? iv, bool decrypt)
    {
        if (data == null || data.Length % 8 != 0) throw new ArgumentException("Data must be 8-byte aligned.", nameof(data));
        if (key == null || (key.Length != 8 && key.Length != 24)) throw new ArgumentException("Expected an 8-byte DES or 24-byte 3DES key.", nameof(key));
        if (iv != null) Guard.Size(iv, 8, nameof(iv));
        using SymmetricAlgorithm algorithm = key.Length == 8 ? System.Security.Cryptography.DES.Create() : System.Security.Cryptography.TripleDES.Create();
        algorithm.Key = (byte[])key.Clone();
        algorithm.Mode = iv == null ? CipherMode.ECB : CipherMode.CBC;
        algorithm.Padding = PaddingMode.None;
        if (iv != null) algorithm.IV = (byte[])iv.Clone();
        using ICryptoTransform worker = decrypt ? algorithm.CreateDecryptor() : algorithm.CreateEncryptor();
        return worker.TransformFinalBlock(data, 0, data.Length);
    }

    /// <summary>Observed 20-byte XOR and eight-byte fold at EE 0x00532568..0x005325E8.</summary>
    public static byte[] FoldChallengeKey(byte[] first20, byte[] second20)
    {
        Guard.Size(first20, 20, nameof(first20));
        Guard.Size(second20, 20, nameof(second20));
        byte[] mixed = new byte[20];
        for (int i = 0; i < 20; i++) mixed[i] = (byte)(first20[i] ^ second20[i]);
        byte[] result = new byte[8];
        for (int i = 0; i < 8; i++) result[i] = (byte)(mixed[i] ^ mixed[i + 8] ^ (i < 4 ? mixed[i + 16] : 0));
        return result;
    }
}
