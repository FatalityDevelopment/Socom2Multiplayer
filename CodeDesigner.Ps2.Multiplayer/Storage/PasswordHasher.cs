using System.Security.Cryptography;
using System.Text;

namespace CodeDesigner.Ps2.Multiplayer.Storage;

/// <summary>
/// Salted PBKDF2 password hashes, stored as <c>pbkdf2$&lt;iterations&gt;$&lt;salt b64&gt;$&lt;hash b64&gt;</c>.
/// Older snapshots hold unsalted SHA-1 hex; those still verify and are flagged for upgrade on the next login.
/// </summary>
public static class PasswordHasher
{
    private const string Prefix     = "pbkdf2$";
    private const int    Iterations = 100_000;
    private const int    SaltBytes  = 16;
    private const int    HashBytes  = 32;

    public static string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var hash = Derive(password, salt, Iterations);
        return $"{Prefix}{Iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    /// <summary>
    /// Check <paramref name="password"/> against <paramref name="stored"/>. An empty stored hash (an account made by
    /// ticket login or the debug API) never matches. <paramref name="needsUpgrade"/> is true for a legacy SHA-1 match.
    /// </summary>
    public static bool Verify(string password, string stored, out bool needsUpgrade)
    {
        needsUpgrade = false;
        if (string.IsNullOrEmpty(stored)) return false;

        if (!stored.StartsWith(Prefix, StringComparison.Ordinal))
        {
            var legacy = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));
            bool ok = CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(legacy.ToLowerInvariant()), Encoding.ASCII.GetBytes(stored.ToLowerInvariant()));
            needsUpgrade = ok;
            return ok;
        }

        var parts = stored.Split('$');
        if (parts.Length != 4 || !int.TryParse(parts[1], out int iterations) || iterations <= 0) return false;
        try
        {
            var salt     = Convert.FromBase64String(parts[2]);
            var expected = Convert.FromBase64String(parts[3]);
            var actual   = Derive(password, salt, iterations, expected.Length);
            needsUpgrade = iterations < Iterations;
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (FormatException) { return false; }
    }

    private static byte[] Derive(string password, byte[] salt, int iterations, int length = HashBytes)
        => Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, length);
}
