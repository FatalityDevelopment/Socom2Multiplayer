using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using DNAS;
using TCP.Server;
using TLS;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        try
        {
            ServerOptions options = ServerOptions.Parse(args);
            if (options.ShowHelp)
            {
                ServerOptions.Help();
                return 0;
            }

            // DNAS sessions span separate TLS connections and belong to the processor.
            DnasServerProcessor processor = CreateProtocolProcessor(options);

            // Certificate selection belongs to the TLS layer, not DNAS.
            TlsServerSettings tlsSettings = CreateTlsSettings(options);

            var credentials = TlsCredentials.LoadCertificate(tlsSettings);
            using X509Certificate2? certificate = credentials.certificate;
            using X509Certificate2? authority = tlsSettings.CaCer == null
                ? null
                : TlsCredentials.LoadPublicCertificatePem(tlsSettings.CaCer);

            DescribeTlsCertificate(certificate);
            Console.WriteLine($"[NETWORK] DnaSDK listening on {options.Bind}:{options.Port}");
            Console.WriteLine("[SECURITY] TLS 1.0/3DES is obsolete. Restrict this service to your emulator/test LAN.");

            using CancellationTokenSource shutdown = new();
            ConsoleCancelEventHandler cancelHandler = (_, eventArgs) =>
            {
                eventArgs.Cancel = true;
                shutdown.Cancel();
            };

            Console.CancelKeyPress += cancelHandler;
            try
            {
                TcpServer listener = new(options.Bind, options.Port, processor, certificate, credentials.privateKey, authority, options.CaptureDir);

                await listener.RunAsync(shutdown.Token);
                return 0;
            }
            finally
            {
                Console.CancelKeyPress -= cancelHandler;
            }
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine("[ERROR] " + exception);
            return 1;
        }
    }

    private static DnasServerProcessor CreateProtocolProcessor(ServerOptions options)
    {
        DnasServerConfiguration configuration = new()
        {
            ConsoleHex = options.ConsoleHex,
            DiscHex = options.DiscHex,
            Serial = options.Serial,
            TicketRoot = options.TicketRoot,
            RepositoryUrl = options.RepositoryUrl
        };

        DnasSessionRegistry sessions = DnasServerFactory.Create(configuration);
        return new DnasServerProcessor(sessions);
    }

    private static TlsServerSettings CreateTlsSettings(ServerOptions options)
    {
        return new TlsServerSettings
        {
            Pfx = options.Pfx,
            PfxPassword = options.PfxPassword,
            CertPem = options.CertPem,
            KeyPem = options.KeyPem,
            CaCer = options.CaCer,
            TlsHost = options.TlsHost
        };
    }

    private static void DescribeTlsCertificate(X509Certificate2? certificate)
    {
        if (certificate == null)
            return;

        Console.WriteLine($"[TLS] Subject={certificate.Subject}; Issuer={certificate.Issuer}");
        Console.WriteLine($"[TLS] Valid {certificate.NotBefore:yyyy-MM-dd} to {certificate.NotAfter:yyyy-MM-dd}");

        if (DateTime.Now > certificate.NotAfter)
            Console.WriteLine("[TLS] WARNING: certificate expired.");

        byte[] fingerprint = SHA256.HashData(certificate.RawData);
        Console.WriteLine($"[TLS] SHA-256={Convert.ToHexString(fingerprint)}");
    }
}
