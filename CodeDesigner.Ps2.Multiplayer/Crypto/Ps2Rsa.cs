using System.Numerics;
using System.Security.Cryptography;

namespace CodeDesigner.Ps2.Multiplayer.Crypto;

/// <summary>
/// PS2 Medius RSA — 512-bit key with public exponent 17.
/// Matches Horizon Private Server's RT.Cryptography/RSA/PS2_RSA.cs.
/// Uses System.Numerics.BigInteger (no BouncyCastle dependency).
/// </summary>
public class Ps2Rsa
{
    private static readonly BigInteger DefaultE = 17;

    /// <summary>
    /// The server's fixed RSA-512 keypair — hardcoded from Horizon's ServerSettings.DefaultKey.
    /// The PS2 firmware encrypts CLIENT_CRYPTKEY_PUBLIC with this public key (E=17, N_server).
    /// The server uses D_server to decrypt it and recover the PS2's per-session public key.
    /// </summary>
    public static readonly Ps2Rsa ServerKey = new Ps2Rsa(
        BigInteger.Parse("10315955513017997681600210131013411322695824559688299373570246338038100843097466504032586443986679280716603540690692615875074465586629501752500179100369237"),
        DefaultE,
        BigInteger.Parse("4854567300243763614870687120476899445974505675147434999327174747312047455575182761195687859800492317495944895566174677168271650454805328075020357360662513")
    );

    public BigInteger N { get; }
    public BigInteger E { get; }
    public BigInteger D { get; }

    public Ps2Rsa(BigInteger n, BigInteger e, BigInteger d)
    {
        N = n;
        E = e;
        D = d;
    }

    /// <summary>
    /// Generate a new 512-bit RSA keypair with E=17.
    /// Picks two random 256-bit primes p,q where gcd(E, (p-1)(q-1)) == 1,
    /// then computes D = E^-1 mod λ(N).
    /// </summary>
    public static Ps2Rsa GenerateKeyPair()
    {
        BigInteger p, q, n, phi, d;
        do
        {
            p = GeneratePrime(256);
            q = GeneratePrime(256);
            n = p * q;
            phi = (p - 1) * (q - 1);
        }
        while (n.GetBitLength() != 512 || BigInteger.GreatestCommonDivisor(DefaultE, phi) != 1);

        d = ModInverse(DefaultE, phi);
        return new Ps2Rsa(n, DefaultE, d);
    }

    /// <summary>
    /// Create an encryption-only RSA from the PS2's per-session public key N.
    /// <paramref name="ps2NBytes"/> must be the RSA-decrypted plaintext from
    /// <see cref="ServerKey"/>.Decrypt — 64 bytes in little-endian format.
    /// D is set to E — server only needs to encrypt, not decrypt, with this key.
    /// </summary>
    public static Ps2Rsa FromClientPublicKey(byte[] ps2NBytes)
    {
        // Decrypted N_ps2 bytes come out of Ps2Rsa.Decrypt as LE (via ToLE).
        // Read them back as LE, matching Horizon's Key.Reverse() → BigInteger(1, reversed).
        var n = FromLE(ps2NBytes);
        return new Ps2Rsa(n, DefaultE, DefaultE);
    }

    /// <summary>Get the public key N as a 64-byte little-endian array.</summary>
    public byte[] GetPublicKey() => ToLE(N, 64);

    /// <summary>
    /// Generate a random 64-byte value m such that m &lt; N (as a 512-bit LE integer).
    /// Required before RSA-encrypting: if m &gt;= N, m^E mod N is not a bijection and
    /// the PS2 cannot recover m with its private key.
    /// </summary>
    public static byte[] GenerateMessageLessThan(BigInteger n)
    {
        // A client controls N; a tiny one would make the rejection loop below spin forever.
        if (n < MinClientModulus)
            throw new ArgumentOutOfRangeException(nameof(n), "Client RSA modulus is too small.");

        // Clear the bits above N's length so each draw is below N at least half the time.
        int bits = (int)n.GetBitLength();
        var buf = new byte[64];
        do
        {
            RandomNumberGenerator.Fill(buf);
            for (int bit = bits; bit < 512; bit++)
                buf[bit / 8] &= (byte)~(1 << (bit % 8));
        }
        while (FromLE(buf) >= n);
        return buf;
    }

    /// <summary>Smallest client modulus accepted: a real PS2 session key is a full 512-bit N.</summary>
    private static readonly BigInteger MinClientModulus = BigInteger.One << 500;

    /// <summary>True when <paramref name="ps2NBytes"/> (LE) is a 64-byte modulus large enough to key a session with.</summary>
    public static bool IsUsableClientModulus(byte[] ps2NBytes)
        => ps2NBytes.Length == 64 && FromLE(ps2NBytes) >= MinClientModulus;

    /// <summary>RSA encrypt: cipher = m^E mod N</summary>
    public byte[] Encrypt(byte[] input)
        => ToLE(BigInteger.ModPow(FromLE(input), E, N), input.Length);

    /// <summary>RSA decrypt: plain = c^D mod N</summary>
    public byte[] DecryptRaw(byte[] input)
        => ToLE(BigInteger.ModPow(FromLE(input), D, N), input.Length);

    /// <summary>
    /// Decrypt with hash verification (matches Horizon PS2_RSA.Decrypt).
    /// If hash is invalid/zero, passes through as plaintext.
    /// </summary>
    public bool Decrypt(byte[] input, byte[] hash, out byte[] plain)
    {
        plain = new byte[input.Length];

        if (!PS2_RC4.IsHashValid(hash))
        {
            Array.Copy(input, 0, plain, 0, input.Length);
            return true;
        }

        var ctx        = (CipherContext)(hash[3] >> 5);
        var plainInt   = BigInteger.ModPow(FromLE(input), D, N);
        var plainBytes = ToLE(plainInt, input.Length);
        Array.Copy(plainBytes, plain, plainBytes.Length);

        var ourHash = PS2_RC4.ComputeHash(plain, ctx);
        if (ourHash.SequenceEqual(hash))
            return true;

        // Try adding N (for values larger than N but < 2^512)
        plainBytes = ToLE(plainInt + N, input.Length);
        Array.Copy(plainBytes, plain, plainBytes.Length);
        ourHash = PS2_RC4.ComputeHash(plain, ctx);

        return ourHash.SequenceEqual(hash);
    }

    // -- LE ↔ BigInteger helpers --

    /// <summary>Read unsigned LE bytes into a positive BigInteger.</summary>
    private static BigInteger FromLE(byte[] le)
    {
        // BigInteger ctor is LE and uses 2's complement; append 0 byte to stay positive
        var buf = new byte[le.Length + 1];
        le.CopyTo(buf, 0);
        return new BigInteger(buf);
    }

    /// <summary>Write a positive BigInteger as LE bytes, zero-padded to minLen.</summary>
    private static byte[] ToLE(BigInteger b, int minLen)
    {
        var bytes = b.ToByteArray(); // LE, 2's complement
        // Strip trailing zero sign byte if present
        int len = bytes.Length;
        if (len > 1 && bytes[len - 1] == 0) len--;
        if (len < minLen)
        {
            var result = new byte[minLen];
            Array.Copy(bytes, result, len);
            return result;
        }
        return bytes[..Math.Min(len, minLen)];
    }

    // -- Prime generation --

    private static BigInteger GeneratePrime(int bits)
    {
        var rng   = RandomNumberGenerator.Create();
        var bytes = new byte[bits / 8 + 1]; // +1 for sign byte
        while (true)
        {
            rng.GetBytes(bytes, 0, bits / 8);
            bytes[bits / 8] = 0; // positive sign
            bytes[bits / 8 - 1] |= 0x80; // ensure high bit set → full bit-length
            bytes[0] |= 1; // ensure odd

            var candidate = new BigInteger(bytes);
            if (IsProbablePrime(candidate, 20))
                return candidate;
        }
    }

    private static bool IsProbablePrime(BigInteger n, int k)
    {
        if (n < 2) return false;
        if (n == 2 || n == 3) return true;
        if (n.IsEven) return false;

        // Write n-1 as 2^r · d
        var d = n - 1;
        int r = 0;
        while (d.IsEven) { d >>= 1; r++; }

        var rng   = RandomNumberGenerator.Create();
        var nBytes = n.ToByteArray();

        for (int i = 0; i < k; i++)
        {
            BigInteger a;
            do
            {
                var buf = new byte[nBytes.Length];
                rng.GetBytes(buf);
                buf[^1] &= 0x7F; // positive
                a = new BigInteger(buf);
            } while (a < 2 || a >= n - 2);

            var x = BigInteger.ModPow(a, d, n);
            if (x == 1 || x == n - 1) continue;

            bool found = false;
            for (int j = 0; j < r - 1; j++)
            {
                x = BigInteger.ModPow(x, 2, n);
                if (x == n - 1) { found = true; break; }
            }
            if (!found) return false;
        }
        return true;
    }

    private static BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        BigInteger g = BigInteger.GreatestCommonDivisor(a, m);
        if (g != 1) throw new ArithmeticException("No modular inverse");

        // Extended Euclidean
        BigInteger t = 0, newT = 1, r = m, newR = a;
        while (newR != 0)
        {
            var q = BigInteger.DivRem(r, newR, out var rem);
            (t, newT) = (newT, t - q * newT);
            r = newR;
            newR = rem;
        }
        return (t % m + m) % m;
    }
}
