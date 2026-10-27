using System;
using System.Linq;
using System.Net;
using DNAS;

namespace TCP.Server;

/// <summary>Command-line configuration for the live HTTPS/DNAS service.</summary>
public sealed class ServerOptions
{
    private const string DefaultTlsHost = "gate1.us.dnas.playstation.org";

    public IPAddress Bind = IPAddress.Any;
    public int Port = Public.HttpsPort;
    public string? Pfx, PfxPassword, CertPem, KeyPem, CaCer, CaptureDir = "PacketLogs";
    public string? ConsoleHex, DiscHex, Serial;
    public string TicketRoot = "RSA";
    public string? RepositoryUrl;
    public string TlsHost = DefaultTlsHost;
    public bool ShowHelp;

    public static ServerOptions Parse(string[] args)
    {
        ServerOptions options = new();

        for (int i = 0; i < args.Length; i++)
        {
            string argument = args[i].ToLowerInvariant();
            if (argument is "--help" or "-h")
            {
                options.ShowHelp = true;
                return options;
            }

            if (++i == args.Length)
                throw new ArgumentException($"Missing value for {args[i - 1]}.");

            string value = args[i];
            switch (argument)
            {
                case "--bind": options.Bind = IPAddress.Parse(value); break;
                case "--port": options.Port = int.Parse(value); break;
                case "--pfx": options.Pfx = value; break;
                case "--pfx-password": options.PfxPassword = value; break;
                case "--cert-pem": options.CertPem = value; break;
                case "--key-pem": options.KeyPem = value; break;
                case "--ca-cer": options.CaCer = value; break;
                case "--capture-dir": options.CaptureDir = value; break;
                case "--console-id": options.ConsoleHex = value; break;
                case "--disc-id": options.DiscHex = value; break;
                case "--serial": options.Serial = value; break;
                case "--rsa-dir": options.TicketRoot = value; break;
                case "--dnasrep-url": options.RepositoryUrl = value; break;
                case "--tls-hostname": options.TlsHost = value; break;
                default: throw new ArgumentException($"Unrecognized option {argument}.");
            }
        }

        if (options.Port is < 1 or > 65535)
            throw new ArgumentException("Port must be in 1..65535.");

        int pinned = (options.ConsoleHex == null ? 0 : 1) + (options.DiscHex == null ? 0 : 1) + (options.Serial == null ? 0 : 1);
        if (pinned != 0 && pinned != 3)
            throw new ArgumentException("Identity pinning requires --console-id, --disc-id and --serial together.");

        if (options.TlsHost.Length == 0 || options.TlsHost.Length > 253 || options.TlsHost.Any(character => !(char.IsLetterOrDigit(character) || character == '-' || character == '.')))
            throw new ArgumentException("--tls-hostname must be a DNS hostname.");

        if ((options.CertPem == null) != (options.KeyPem == null))
            throw new ArgumentException("--cert-pem and --key-pem must both be supplied.");

        if (options.Pfx != null && options.CertPem != null)
            throw new ArgumentException("Choose either a PFX or PEM certificate pair.");

        return options;
    }

    public static void Help()
    {
        Console.WriteLine("DnaSDK HTTPS/DNAS server");
        Console.WriteLine("  DnaSDK.exe --bind 0.0.0.0 --port 443 --capture-dir PacketLogs");
        Console.WriteLine("  DnaSDK.exe --cert-pem cert.pem --key-pem key.pem --ca-cer ca.pem");
        Console.WriteLine("  DnaSDK.exe --pfx certificate.pfx --pfx-password PASSWORD");
        Console.WriteLine("  Tickets: --rsa-dir RSA [--dnasrep-url REPOSITORY_ROOT]");
        Console.WriteLine("  TLS: --tls-hostname NAME (default gate1.us.dnas.playstation.org)");
        Console.WriteLine("  Optional identity pinning: --console-id HEX8 --disc-id HEX5 --serial SERIAL");
        Console.WriteLine("  The bundled gateway PEM certificate chain is loaded unless another identity is supplied.");
        Console.WriteLine("  DNAS sessions persist across separate HTTPS connections.");
    }
}
