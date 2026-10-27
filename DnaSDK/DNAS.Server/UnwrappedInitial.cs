using System;
using System.Security.Cryptography;

namespace DNAS;

/// <summary>
/// Decoded C1 envelope and its four encrypted identity proofs. The validity
/// flags reflect checks on the original envelope padding and trailer.
/// </summary>

public sealed class UnwrappedInitial
{
    public readonly InitialFields Fields;
    public readonly byte[] Random16;
    public readonly byte[] OriginalPlaintext;
    public readonly bool ZeroPaddingValid;
    public readonly bool FixedTrailerValid;
    public UnwrappedInitial(InitialFields fields, byte[] random16, byte[] originalPlaintext, bool zeros, bool trailer)
    {
        Fields = fields;
        Random16 = random16;
        OriginalPlaintext = originalPlaintext;
        ZeroPaddingValid = zeros;
        FixedTrailerValid = trailer;
    }
}

