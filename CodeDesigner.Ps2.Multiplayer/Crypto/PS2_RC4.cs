using System.Security.Cryptography;

namespace CodeDesigner.Ps2.Multiplayer.Crypto;

/// <summary>
/// PS2 Medius custom RC4 stream cipher — per-packet stateless design.
/// Ported directly from Horizon Private Server's RT.Cryptography/RC/PS2_RC4.cs.
///
/// Algorithm:
///   - Init table reversed: S[i] = 255 - i
///   - Hash scramble pass (cipherIndex += 5, 256 iterations) before key schedule
///   - Key schedule: cipherIndex += 3, keyIndex wraps at 64
///   - Encrypt: x += 5, y += S[x], swap, xor with S[(S[x]+S[y])&0xFF], y-feedback on plain
///   - Decrypt: y += 5, x += S[y], swap, xor with S[(S[x]+S[y])&0xFF], x-feedback on plain
///   - 4-byte hash = SHA1(plaintext)[0..3] with CipherContext in top 3 bits of byte[3]
/// </summary>
public static class PS2_RC4
{
    private const int STATE_LENGTH = 256;
    private const int KEY_LENGTH   = 0x40;  // 64 bytes

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /// <summary>Generate a cryptographically random 64-byte session key.</summary>
    public static byte[] GenerateKey()
    {
        var key = new byte[KEY_LENGTH];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    /// <summary>
    /// Decrypt a packet payload in-place.
    /// If hash is all-zero (invalid), data is left unchanged (plaintext pass-through).
    /// </summary>
    public static void Decrypt(byte[] workingKey, byte[] hash, Span<byte> data)
    {
        if (!IsHashValid(hash))
            return;   // plaintext — no decryption, matching Horizon behaviour

        var  engineState = new byte[STATE_LENGTH];
        int  x = 0, y = 0;
        SetKey(engineState, ref x, ref y, workingKey, hash);

        var dataBuf = data.ToArray();
        DecryptCore(engineState, ref x, ref y, dataBuf, 0, dataBuf.Length, dataBuf, 0);
        dataBuf.CopyTo(data);
    }

    /// <summary>
    /// Encrypt <paramref name="plaintext"/> and return ciphertext + 4-byte hash.
    /// </summary>
    public static void Encrypt(byte[] workingKey, CipherContext context, byte[] plaintext,
        out byte[] cipher, out byte[] hash)
    {
        hash   = ComputeHash(plaintext, context);
        cipher = new byte[plaintext.Length];

        var  engineState = new byte[STATE_LENGTH];
        int  x = 0, y = 0;
        SetKey(engineState, ref x, ref y, workingKey, hash);
        EncryptCore(engineState, ref x, ref y, plaintext, 0, plaintext.Length, cipher, 0);
    }

    // -------------------------------------------------------------------------
    // Key initialisation — mirrors Horizon's SetKey exactly
    // -------------------------------------------------------------------------

    private static void SetKey(byte[] engineState, ref int x, ref int y, byte[] key, byte[]? hash)
    {
        x = 0;
        y = 0;

        int keyIndex    = 0;
        int li          = 0;
        int cipherIndex = 0;
        int idIndex     = 0;

        // Step 1: reversed init table (Horizon: engineState[i] = (STATE_LENGTH - 1) - i)
        for (int i = 0; i < STATE_LENGTH; i++)
            engineState[i] = (byte)((STATE_LENGTH - 1) - i);

        // Step 2: hash scramble pass — Horizon checks only (hash != null && hash.Length == 4)
        if (hash != null && hash.Length == 4)
        {
            do
            {
                int v1 = hash[idIndex];
                idIndex = (idIndex + 1) & 3;

                byte temp = engineState[cipherIndex];
                v1  += li;
                li   = (temp + v1) & 0xFF;

                engineState[cipherIndex] = engineState[li];
                engineState[li]          = temp;

                cipherIndex = (cipherIndex + 5) & 0xFF;
            } while (cipherIndex != 0);

            // Reset for key schedule
            keyIndex    = 0;
            li          = 0;
            cipherIndex = 0;
            idIndex     = 0;
        }

        // Step 3: key schedule (cipherIndex += 3, keyIndex wraps at 64)
        do
        {
            int keyByte = key[keyIndex];
            keyByte    += li;
            keyIndex   += 1;
            keyIndex   &= 0x3F;

            int  cipherByte  = engineState[cipherIndex];
            byte cipherValue = (byte)(cipherByte & 0xFF);

            cipherByte += keyByte;
            li          = cipherByte & 0xFF;

            byte t0 = engineState[li];
            engineState[cipherIndex] = t0;
            engineState[li]          = cipherValue;

            cipherIndex += 3;
            cipherIndex &= 0xFF;
        } while (cipherIndex != 0);
    }

    // -------------------------------------------------------------------------
    // Encrypt core — mirrors Horizon's private Encrypt method
    // -------------------------------------------------------------------------

    private static void EncryptCore(byte[] s, ref int x, ref int y,
        byte[] input, int inOff, int length, byte[] output, int outOff)
    {
        for (int i = 0; i < length; i++)
        {
            x = (x + 5) & 0xFF;
            y = (y + s[x]) & 0xFF;

            // Swap
            byte temp = s[x]; s[x] = s[y]; s[y] = temp;

            // XOR with keystream
            output[i + outOff] = (byte)(input[i + inOff] ^ s[(s[x] + s[y]) & 0xFF]);

            // PS2 y-feedback on plaintext
            y = (s[input[i + inOff]] + y) & 0xFF;
        }
    }

    // -------------------------------------------------------------------------
    // Decrypt core — mirrors Horizon's private Decrypt method
    // -------------------------------------------------------------------------

    private static void DecryptCore(byte[] s, ref int x, ref int y,
        byte[] input, int inOff, int length, byte[] output, int outOff)
    {
        for (int i = 0; i < length; i++)
        {
            y = (y + 5) & 0xFF;

            int  v0 = s[y];
            byte a2 = (byte)(v0 & 0xFF);
            v0     += x;
            x       = (byte)(v0 & 0xFF);

            v0      = s[x];
            s[y]    = (byte)(v0 & 0xFF);
            s[x]    = a2;

            byte a0 = input[i + inOff];
            v0 += a2;
            v0 &= 0xFF;
            int v1 = s[v0];

            a0 ^= (byte)v1;
            output[i + outOff] = a0;

            // PS2 x-feedback on recovered plaintext
            v1 = s[a0] + x;
            x  = v1 & 0xFF;
        }
    }

    // -------------------------------------------------------------------------
    // Hash helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Compute the 4-byte packet hash: SHA1(plaintext)[0..3] with cipher context
    /// encoded in the top 3 bits of byte[3].
    /// </summary>
    public static byte[] ComputeHash(byte[] data, CipherContext context)
    {
        var sha    = SHA1.HashData(data);
        var result = new byte[4];
        Array.Copy(sha, result, 4);
        result[3] = (byte)((result[3] & 0x1F) | (((byte)context & 7) << 5));
        return result;
    }

    /// <summary>A hash of all-zeros (or only context bits) means "plaintext, no decryption".</summary>
    public static bool IsHashValid(byte[]? hash)
    {
        if (hash == null || hash.Length < 4)
            return false;

        return !(hash[0] == 0 && hash[1] == 0 && hash[2] == 0 && (hash[3] & 0x1F) == 0);
    }
}

/// <summary>
/// Cipher context values encoded in the top 3 bits of the packet hash byte[3].
/// Values match Horizon Private Server's RT.Cryptography/ICipher.cs CipherContext enum.
/// </summary>
public enum CipherContext : byte
{
    ID_00             = 0,
    RcServerSession   = 1,   // RC_SERVER_SESSION
    ID_02             = 2,
    RcClientSession   = 3,   // RC_CLIENT_SESSION — session key used for client traffic
    ID_04             = 4,
    ID_05             = 5,
    ID_06             = 6,
    RsaAuth           = 7,   // RSA_AUTH — used for CRYPTKEY_PEER handshake
}
