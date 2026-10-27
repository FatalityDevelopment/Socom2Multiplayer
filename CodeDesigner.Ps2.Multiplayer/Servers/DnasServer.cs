using System.Net;
using System.Net.Sockets;
using CodeDesigner.Ps2.Multiplayer.Config;
using DNAS;
using Microsoft.Extensions.Logging;
using TCP.Server;
using TLS;

namespace CodeDesigner.Ps2.Multiplayer.Servers;

/// <summary>
/// DNAS — Dynamic Network Authentication System gateway, served by DnaSDK
/// (https://github.com/FatalityDevelopment/DnaSDK) running in this process.
///
/// The PS2 contacts gate1.*.dnas.playstation.org:443 (DnsServer points it here). DnaSDK negotiates the
/// console's legacy SSLv2-hello / TLS 1.0 / 3DES connection and runs the live six-message DNAS exchange:
/// fresh challenges and session state per console, with only the original RSA-signed ticket reused.
///
/// Sources, same as the old capture-replay server:
///   • Certificates/ — dnas.crt + dnas.key if present, else the community cert for DnasRegion
///     (cert-us / cert-eu / cert-jp .pem + -key.pem), always with ca-cert.pem as the issuer.
///   • Data/&lt;region&gt;/packets/&lt;lookup&gt;_&lt;operation&gt; (DnasRepositoryUrl) — the captured S1 for a title's
///     C1 supplies its signed ticket. DnasRegion is searched first, then the other regions.
/// Tickets taken from the packets are cached in &lt;DnasRsaDirectory&gt;/Signatures/&lt;SERIAL&gt;.BIN.
/// </summary>
public class DnasServer
{
    private readonly MultiplayerConfig   _config;
    private readonly ILogger<DnasServer> _log;

    public DnasServer(MultiplayerConfig config, ILogger<DnasServer> log)
    {
        _config = config;
        _log    = log;
    }

    public Task StartAsync(CancellationToken ct)
    {
        if (_config.DnasHttpsPort <= 0)
        {
            _log.LogInformation("[DNAS] Disabled (DnasHttpsPort=0)");
            return Task.CompletedTask;
        }

        string dataDir    = string.IsNullOrWhiteSpace(_config.DataDirectory)
            ? Path.Combine(AppContext.BaseDirectory, "data")
            : _config.DataDirectory;
        string rsaDir     = OrDefault(_config.DnasRsaDirectory, Path.Combine(dataDir, "dnas", "RSA"));
        string captureDir = OrDefault(_config.DnasCaptureDirectory, Path.Combine(dataDir, "dnas", "PacketLogs"));
        string packets    = OrDefault(_config.DnasRepositoryUrl, "Data");

        try
        {
            var sessions = DnasServerFactory.Create(new DnasServerConfiguration
            {
                TicketRoot      = rsaDir,
                RepositoryUrl   = packets,
                PreferredRegion = _config.DnasRegion,
            });

            var tls = ResolveCertificates();
            var (certificate, privateKey) = TlsCredentials.LoadCertificate(tls);
            var authority = File.Exists(tls.CaCer) ? TlsCredentials.LoadPublicCertificatePem(tls.CaCer!) : null;
            if (authority == null)
                _log.LogWarning("[DNAS] No CA certificate at {Path} — the PS2 rejects a leaf-only chain", tls.CaCer);

            var server = new TcpServer(IPAddress.Parse(_config.BindAddress), _config.DnasHttpsPort,
                new DnasServerProcessor(sessions), certificate, privateKey, authority, captureDir);

            _log.LogInformation("[DNAS] DnaSDK gateway on {Addr}:{Port} (region={Region}) cert={Cert} packets={Packets}",
                _config.BindAddress, _config.DnasHttpsPort, _config.DnasRegion, tls.CertPem, packets);
            _log.LogInformation("[DNAS] Tickets={Rsa} captures={Captures}", rsaDir, captureDir);
            if (!packets.StartsWith("https://", StringComparison.OrdinalIgnoreCase) &&
                !Directory.Exists(Path.Combine(AppContext.BaseDirectory, packets)) && !Directory.Exists(packets))
                _log.LogWarning("[DNAS] Packet directory {Packets} not found — titles without a cached ticket will fail DNAS", packets);

            _ = RunAsync(server, ct);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "[DNAS] Failed to start the DnaSDK gateway — DNAS logins will fail");
        }
        return Task.CompletedTask;
    }

    // DnaSDK's listener stops itself when the token is cancelled.
    public void Stop() { }

    private async Task RunAsync(TcpServer server, CancellationToken ct)
    {
        try
        {
            await server.RunAsync(ct);
        }
        catch (SocketException ex)
        {
            _log.LogWarning("[DNAS] Cannot bind HTTPS on port {Port} ({Msg}). " +
                            "Run as root or use: sudo setcap 'cap_net_bind_service=+ep' <binary>",
                _config.DnasHttpsPort, ex.Message);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "[DNAS] DnaSDK gateway stopped");
        }
    }

    /// <summary>Same lookup order as the original DNAS server: configured paths, dnas.crt/.key, then the region cert.</summary>
    private TlsServerSettings ResolveCertificates()
    {
        string certPath = ResolvePath(_config.DnasCertPath, "Certificates", "dnas.crt");
        string keyPath  = ResolvePath(_config.DnasKeyPath,  "Certificates", "dnas.key");

        // Fallback: the community certs matching the configured region
        if (!File.Exists(certPath))
        {
            var regionCert = RegionCertName(_config.DnasRegion);
            certPath = ResolvePath("", "Certificates", regionCert + ".pem");
            keyPath  = ResolvePath("", "Certificates", regionCert + "-key.pem");
        }

        return new TlsServerSettings
        {
            CertPem = certPath,
            KeyPem  = keyPath,
            CaCer   = ResolvePath(_config.DnasCaPath, "Certificates", "ca-cert.pem"),
        };
    }

    private static string RegionCertName(string region) => region switch
    {
        "eu-gw"  => "cert-eu",
        "gai-gw" => "cert-jp",
        _        => "cert-us",
    };

    private static string ResolvePath(string configured, string subDir, string defaultFile)
    {
        if (!string.IsNullOrWhiteSpace(configured))
            return configured;

        var candidate = Path.Combine(AppContext.BaseDirectory, subDir, defaultFile);
        if (File.Exists(candidate)) return candidate;
        return Path.Combine(subDir, defaultFile);
    }

    private static string OrDefault(string value, string fallback) =>
        string.IsNullOrWhiteSpace(value) ? fallback : value;
}
