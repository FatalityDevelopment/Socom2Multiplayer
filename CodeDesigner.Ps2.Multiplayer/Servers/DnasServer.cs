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
/// Tickets live in &lt;DnasRsaDirectory&gt;/Signatures/&lt;SERIAL&gt;.BIN. The ones bundled under Dnas/Signatures
/// (SOCOM II SCUS-97275) are copied there on start; any other title's ticket is fetched from DNASrep on its
/// first login and cached.
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
        string certDir    = Path.Combine(AppContext.BaseDirectory, "Certificates");

        try
        {
            InstallBundledTickets(rsaDir);

            var sessions = DnasServerFactory.Create(new DnasServerConfiguration
            {
                TicketRoot    = rsaDir,
                RepositoryUrl = string.IsNullOrWhiteSpace(_config.DnasRepositoryUrl) ? null : _config.DnasRepositoryUrl,
            });

            var tls = new TlsServerSettings
            {
                CertPem = OrDefault(_config.DnasCertPath, Path.Combine(certDir, "cert-us.pem")),
                KeyPem  = OrDefault(_config.DnasKeyPath,  Path.Combine(certDir, "cert-us-key.pem")),
                CaCer   = OrDefault(_config.DnasCaPath,   Path.Combine(certDir, "ca-cert.pem")),
            };
            var (certificate, privateKey) = TlsCredentials.LoadCertificate(tls);
            var authority = TlsCredentials.LoadPublicCertificatePem(tls.CaCer);

            var server = new TcpServer(IPAddress.Parse(_config.BindAddress), _config.DnasHttpsPort,
                new DnasServerProcessor(sessions), certificate, privateKey, authority, captureDir);

            _log.LogInformation("[DNAS] DnaSDK gateway on {Addr}:{Port} cert={Subject} tickets={Rsa} captures={Captures}",
                _config.BindAddress, _config.DnasHttpsPort, certificate.Subject, rsaDir, captureDir);

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

    /// <summary>Copies tickets shipped with the server into the (writable) ticket root, never overwriting.</summary>
    private void InstallBundledTickets(string rsaDir)
    {
        string bundled = Path.Combine(AppContext.BaseDirectory, "Dnas", "Signatures");
        if (!Directory.Exists(bundled)) return;

        string target = Path.Combine(rsaDir, "Signatures");
        Directory.CreateDirectory(target);
        foreach (string file in Directory.EnumerateFiles(bundled, "*.BIN"))
        {
            string dest = Path.Combine(target, Path.GetFileName(file));
            if (File.Exists(dest)) continue;
            File.Copy(file, dest);
            _log.LogInformation("[DNAS] Installed bundled ticket {File}", dest);
        }
    }

    private static string OrDefault(string value, string fallback) =>
        string.IsNullOrWhiteSpace(value) ? fallback : value;
}
