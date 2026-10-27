using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;


using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace TLS;

/// <summary>Historical SSLv2-format ClientHello / TLS 1.0 / RSA-3DES transport used by legacy PS2 software.
/// Only use on a deliberately isolated retro-compatibility endpoint. TLS 1.0/3DES is obsolete.</summary>
public static class LegacyTls
{
    public static async Task<Stream?> TryAcceptAsync(Stream networkStream, X509Certificate2 certificate, AsymmetricKeyParameter? bouncyCastlePrivateKey = null, X509Certificate2? caCertificate = null, Action<string>? logger = null, CancellationToken ct = default)
    {
        if (networkStream == null) throw new ArgumentNullException(nameof(networkStream));
        if (certificate == null) throw new ArgumentNullException(nameof(certificate));
        try
        {
            var (adaptedStream, _, rawSsl2Hello) = await Ssl2Adapter.WrapAsync(networkStream, ct).ConfigureAwait(false);
            var crypto = new BcTlsCrypto(new SecureRandom());
            var protocol = new TlsServerProtocol(adaptedStream);
            var server = new LegacyTlsServer(crypto, certificate, bouncyCastlePrivateKey, caCertificate, logger, rawSsl2Hello, protocol);
            await Task.Run(() => protocol.Accept(server), ct).ConfigureAwait(false);
            logger?.Invoke("TLS 1.0 handshake established; passing decrypted stream to HTTP/DNAS.");
            return protocol.Stream;
        }
        catch (TlsFatalAlertReceived ex)
        {
            logger?.Invoke($"Client terminated TLS negotiation: {ex.Message}");
            return null;
        }
        catch (TlsFatalAlert ex)
        {
            logger?.Invoke($"TLS handshake failed: {ex.Message}");
            return null;
        }
        catch (InvalidDataException ex)
        {
            logger?.Invoke($"Invalid legacy ClientHello: {ex.Message}");
            return null;
        }
        catch (IOException ex)
        {
            logger?.Invoke($"Connection ended during TLS handshake: {ex.Message}");
            return null;
        }
    }
}
