using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>
/// Loads the gateway certificate, its matching RSA private key, and the issuer
/// certificate required by the original TLS client. TLS credentials are transport
/// resources; they are independent of DNAS RSA authentication tickets.
/// </summary>
public static class TlsCredentials
{
    public static X509Certificate2 LoadPublicCertificatePem(string path)
    {
        using StreamReader input = File.OpenText(path);
        object parsed = new PemReader(input).ReadObject() ?? throw new InvalidDataException($"Empty X.509 PEM: {path}");
        if (parsed is not Org.BouncyCastle.X509.X509Certificate certificate)
            throw new InvalidDataException($"Expected an X.509 CERTIFICATE PEM: {path}");

        return new X509Certificate2(certificate.GetEncoded());
    }

    public static (X509Certificate2 certificate, AsymmetricKeyParameter? privateKey) LoadCertificate(TlsServerSettings options)
    {
        // An explicitly configured certificate always takes precedence.
        if (options.Pfx != null)
            return (new X509Certificate2(options.Pfx, options.PfxPassword, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet), null);

        // The original PEM identity is required for retail-compatible TLS.
        // Resolve its three files together so Program also sends the CA chain.
        if (options.CertPem == null)
            UseBundledCertificate(options);

        if (options.KeyPem == null)
            throw new InvalidOperationException("A TLS certificate requires its corresponding RSA private key (--key-pem).");

        using StreamReader input = File.OpenText(options.KeyPem);
        object parsed = new PemReader(input).ReadObject() ?? throw new InvalidDataException($"Empty TLS RSA key PEM: {options.KeyPem}");
        AsymmetricKeyParameter key = parsed switch
        {
            AsymmetricCipherKeyPair pair => pair.Private,
            AsymmetricKeyParameter parameter when parameter.IsPrivate => parameter,
            _ => throw new InvalidDataException("Expected an unencrypted RSA private key PEM.")
        };

        if (key is not Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters)
            throw new InvalidDataException("TLS requires an RSA private key.");

        return (LoadPublicCertificatePem(options.CertPem), key);
    }

    private static void UseBundledCertificate(TlsServerSettings options)
    {
        // The caller owns its existing .csproj: assets may be in the source tree
        // instead of copied into bin/Debug or bin/Release. Search from both the
        // working directory and executable directory, walking up to repo root.
        foreach (string start in new[] { Environment.CurrentDirectory, AppContext.BaseDirectory })
        {
            DirectoryInfo? ancestor = new DirectoryInfo(start);
            for (int depth = 0; depth < 7 && ancestor != null; depth++, ancestor = ancestor.Parent)
            {
                foreach (string subfolder in new[] { "TCP.TLS/Certificates", "Certificates" })
                {
                    string folder = Path.Combine(ancestor.FullName, subfolder);
                    string certificate = Path.Combine(folder, "cert-us.pem");
                    string privateKey = Path.Combine(folder, "cert-us-key.pem");
                    string issuer = Path.Combine(folder, "ca-cert.pem");

                    if (!File.Exists(certificate) || !File.Exists(privateKey) || !File.Exists(issuer))
                        continue;

                    options.CertPem = certificate;
                    options.KeyPem = privateKey;
                    if (options.CaCer == null)
                        options.CaCer = issuer;

                    Console.WriteLine("[TLS] Loaded existing gateway certificate, RSA private key, and CA chain.");
                    return;
                }
            }
        }

        // Do not generate a self-signed substitute: the retail client rejects
        // it with TLS certificate_unknown(46) before a DNAS C1 can be processed.
        throw new FileNotFoundException("Required TLS assets were not found. Restore TCP.TLS/Certificates/cert-us.pem, cert-us-key.pem and ca-cert.pem, or supply --cert-pem, --key-pem and --ca-cer explicitly. No test certificate will be generated.");
    }
}
