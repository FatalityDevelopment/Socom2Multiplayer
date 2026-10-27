using System;
using System.Security.Cryptography;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>
/// Four encrypted identity fields plus original initial header/lookup evidence.
/// The SDK also has a connected native producer; this class remains available
/// when historical upstream runtime/session inputs have not been recovered.
/// </summary>

public sealed class ClientEvidence
{
    public readonly byte[] Header40;
    public readonly byte[] LookupId8;
    public readonly InitialFields Fields;
    public readonly byte[]? DnasImage;

    public ClientEvidence(byte[] header40, byte[] lookupId8, InitialFields fields, byte[]? dnasImage = null)
    {
        Guard.Size(header40, 40, nameof(header40));
        Guard.Size(lookupId8, 8, nameof(lookupId8));
        Fields = fields ?? throw new ArgumentNullException(nameof(fields));
        Header40 = (byte[])header40.Clone();
        LookupId8 = (byte[])lookupId8.Clone();
        if (dnasImage != null && dnasImage.Length < ClientImage.RequiredPrefixLength) throw new ArgumentException("DNAS image is too short.", nameof(dnasImage));
        DnasImage = dnasImage == null ? null : (byte[])dnasImage.Clone();
    }
}

