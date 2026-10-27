namespace TLS;

/// <summary>Certificate paths and identity used by the TLS transport layer.</summary>
public sealed class TlsServerSettings
{
    public string? Pfx, PfxPassword, CertPem, KeyPem, CaCer;
    public string TlsHost = "gate1.us.dnas.playstation.org";
}
