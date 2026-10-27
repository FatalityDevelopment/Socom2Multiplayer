using System;

namespace DNAS;

/// <summary>
/// Shared values established by the standard DNAS wire protocol.
/// These are not a per-title RSA ticket, modulus, image, or TLS credential.
/// </summary>
public static class DnasProtocolConstants
{
    // The plaintext inside S1's nested 32-byte request-bound 3DES field.
    // All 138 decoded standard S1 responses in the DNASRep US/EU/GAI
    // corpus (modes 0x08, 0x10, 0x18) contained these exact 32 bytes.
    // Mutating this plaintext was rejected by an unchanged retail client.
    // The plaintext is constant; its transmitted ciphertext is NOT:
    // the nested CBC key and IV are derived from each individual C1.
    private static readonly byte[] S1InnerPlaintext32 = Convert.FromHexString(
        "E080764EF5C10C9736D6E3E94C23022F4F09E0B7C614C2409A79A35CD7C4B7B7");

    /// <summary>Returns an independent copy of the standard S1 inner plaintext.</summary>
    public static byte[] GetS1InnerPlaintext32() => (byte[])S1InnerPlaintext32.Clone();
}
