using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace CodeDesigner.Ps2.Multiplayer.Config;

/// <summary>
/// Resolves <see cref="MultiplayerConfig.ServerIp"/> = "auto" at startup. Consoles are handed this IP for every
/// follow-up connection (MAS, MLS, DME, NAT), so it must be the address they can reach from outside.
/// </summary>
public static class ServerIpResolver
{
    private static readonly string[] WhatsMyIpServices =
    {
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
    };

    public static async Task ResolveAsync(MultiplayerConfig config, ILogger log, CancellationToken ct)
    {
        if (!string.IsNullOrWhiteSpace(config.ServerIp) &&
            !config.ServerIp.Equals("auto", StringComparison.OrdinalIgnoreCase))
            return;

        string? ip = !string.IsNullOrWhiteSpace(config.PublicHostname)
            ? await FromHostnameAsync(config.PublicHostname, log, ct)
            : await FromWhatsMyIpAsync(log, ct) ?? FirstLocalIPv4();

        config.ServerIp = ip ?? throw new InvalidOperationException(
            $"ServerIp is 'auto' but no public IP could be determined (PublicHostname='{config.PublicHostname}').");
        log.LogInformation("[Config] ServerIp auto-resolved to {Ip}", config.ServerIp);
    }

    /// <summary>
    /// Resolve the deployment's own FQDN. The DNS record can lag a freshly created container group, so retry
    /// for a few minutes; failing hard lets the container restart policy try again.
    /// </summary>
    private static async Task<string?> FromHostnameAsync(string host, ILogger log, CancellationToken ct)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromMinutes(3);
        while (true)
        {
            try
            {
                var addr = (await Dns.GetHostAddressesAsync(host, AddressFamily.InterNetwork, ct)).FirstOrDefault();
                if (addr != null) return addr.ToString();
            }
            catch (SocketException ex)
            {
                log.LogWarning("[Config] Resolving {Host} failed ({Msg}), retrying", host, ex.Message);
            }
            if (DateTime.UtcNow > deadline) return null;
            await Task.Delay(TimeSpan.FromSeconds(5), ct);
        }
    }

    private static async Task<string?> FromWhatsMyIpAsync(ILogger log, CancellationToken ct)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        foreach (var url in WhatsMyIpServices)
        {
            try
            {
                var text = (await http.GetStringAsync(url, ct)).Trim();
                if (IPAddress.TryParse(text, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork)
                    return text;
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                log.LogWarning("[Config] {Url} failed: {Msg}", url, ex.Message);
            }
        }
        return null;
    }

    private static string? FirstLocalIPv4() =>
        Dns.GetHostAddresses(Dns.GetHostName())
            .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a))
            ?.ToString();
}
