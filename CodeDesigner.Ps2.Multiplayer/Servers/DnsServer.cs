using System.Net;
using System.Net.Sockets;
using CodeDesigner.Ps2.Multiplayer.Config;
using Microsoft.Extensions.Logging;

namespace CodeDesigner.Ps2.Multiplayer.Servers;

/// <summary>
/// Minimal DNS server that intercepts DNAS hostname lookups.
///
/// The PS2 DNAS client resolves gate1.*.dnas.playstation.org before opening
/// its HTTPS connection.  This server listens on UDP port 53 and:
///   • Answers any A-record query for *.dnas.playstation.org with ServerIp, or with the address of
///     ExternalDnasServer when DNAS is hosted elsewhere.
///   • Answers *.pdonline.scea.com (Medius) with ServerIp.
///   • Forwards all other queries to the system resolver and relays the reply.
///
/// Wire format (RFC 1035):
///   [ID:2][Flags:2][QDCount:2][ANCount:2][NSCount:2][ARCount:2]
///   [Question: QNAME (labels), QTYPE:2, QCLASS:2]
///   [Answer RRs ...]
///
/// Default port: 53  (override with DnsDnasPort in config)
/// </summary>
public class DnsServer
{
    private readonly MultiplayerConfig   _config;
    private readonly ILogger<DnsServer>  _log;
    private UdpClient?                   _udp;
    private CancellationToken            _ct;

    // Well-known upstream resolver to forward non-DNAS queries.
    private static readonly IPEndPoint Upstream = new(IPAddress.Parse("8.8.8.8"), 53);

    // ExternalDnasServer may be a hostname whose address changes; re-resolve it at most once a minute.
    private static readonly TimeSpan ExternalDnasTtl = TimeSpan.FromMinutes(1);
    private string?  _externalDnasIp;
    private DateTime _externalDnasResolvedAt;

    public DnsServer(MultiplayerConfig config, ILogger<DnsServer> log)
    {
        _config = config;
        _log    = log;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Lifecycle
    // ─────────────────────────────────────────────────────────────────────────

    public Task StartAsync(CancellationToken ct)
    {
        _ct = ct;
        try
        {
            _udp = new UdpClient(new IPEndPoint(IPAddress.Parse(_config.BindAddress), _config.DnsDnasPort));
        }
        catch (SocketException ex)
        {
            _log.LogWarning("[DNS] Cannot bind to {Addr}:{Port} ({Msg}). " +
                            "Try running as root/administrator or use iptables to redirect port 53.",
                _config.BindAddress, _config.DnsDnasPort, ex.Message);
            return Task.CompletedTask;
        }

        if (_config.UsesExternalDnas)
            _log.LogInformation("[DNS] Listening on {Addr}:{Port} (UDP) — *.dnas.playstation.org → external DNAS {Dnas}, *.pdonline.scea.com → {Ip}",
                _config.BindAddress, _config.DnsDnasPort, _config.ExternalDnasServer, _config.ServerIp);
        else
            _log.LogInformation("[DNS] Listening on {Addr}:{Port} (UDP) — intercepting *.dnas.playstation.org + *.pdonline.scea.com → {Ip}",
                _config.BindAddress, _config.DnsDnasPort, _config.ServerIp);

        _ = ReceiveLoopAsync(ct);
        return Task.CompletedTask;
    }

    public void Stop()
    {
        try { _udp?.Close(); } catch { /* ignore */ }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Receive loop
    // ─────────────────────────────────────────────────────────────────────────

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var result = await _udp!.ReceiveAsync(ct);
                _ = HandleQueryAsync(result, ct);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                _log.LogWarning("[DNS] Receive error: {Msg}", ex.Message);
                await Task.Delay(100, ct).ConfigureAwait(false);
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Per-query handler
    // ─────────────────────────────────────────────────────────────────────────

    private async Task HandleQueryAsync(UdpReceiveResult result, CancellationToken ct)
    {
        var buf    = result.Buffer;
        var client = result.RemoteEndPoint;

        try
        {
            if (buf.Length < 12)
            {
                _log.LogDebug("[DNS] Query from {Ep} too short ({Len} bytes, need 12)", client, buf.Length);
                return;
            }

            string? qname = ParseQName(buf, 12, out int afterQname);
            if (qname == null || afterQname + 4 > buf.Length)
            {
                _log.LogDebug("[DNS] Malformed query from {Ep}: invalid QNAME", client);
                return;
            }

            ushort qtype  = (ushort)((buf[afterQname]     << 8) | buf[afterQname + 1]);
            // ushort qclass = (ushort)((buf[afterQname + 2] << 8) | buf[afterQname + 3]); // unused

            bool isDnas      = qname.EndsWith(".dnas.playstation.org", StringComparison.OrdinalIgnoreCase)
                            || qname.Equals("dnas.playstation.org",    StringComparison.OrdinalIgnoreCase);
            bool isIntercept = isDnas
                            || qname.EndsWith(".pdonline.scea.com",    StringComparison.OrdinalIgnoreCase)
                            || qname.Equals("pdonline.scea.com",       StringComparison.OrdinalIgnoreCase);

            // Check user-defined custom hostname → IP mappings.
            string? customIp = null;
            if (!isIntercept && qtype == 1 /* A */)
            {
                foreach (var (host, ip) in _config.DnsMappings)
                {
                    if (qname.Equals(host, StringComparison.OrdinalIgnoreCase) ||
                        qname.EndsWith("." + host, StringComparison.OrdinalIgnoreCase))
                    {
                        customIp = ip;
                        break;
                    }
                }
            }

            _log.LogDebug("[DNS] Query from {Ep}: {Name} type={Type} intercept={Intercept} customIp={CustomIp}",
                client, qname, qtype, isIntercept, customIp ?? "-");

            byte[] reply;
            if (isDnas && qtype == 1 /* A */ && _config.UsesExternalDnas)
            {
                var dnasIp = await ResolveExternalDnasAsync(ct);
                if (dnasIp != null)
                {
                    reply = BuildAResponse(buf, qname, dnasIp);
                    _log.LogInformation("[DNS] {Name} → {Ip} (external DNAS {Server})", qname, dnasIp, _config.ExternalDnasServer);
                }
                else
                {
                    reply = BuildRefused(buf, afterQname + 4);
                    _log.LogWarning("[DNS] {Name}: external DNAS {Server} did not resolve — refused", qname, _config.ExternalDnasServer);
                }
            }
            else if (isIntercept && qtype == 1 /* A */)
            {
                reply = BuildAResponse(buf, qname, _config.ServerIp);
                _log.LogInformation("[DNS] {Name} → {Ip} (intercept)", qname, _config.ServerIp);
            }
            else if (customIp != null)
            {
                reply = BuildAResponse(buf, qname, customIp);
                _log.LogInformation("[DNS] {Name} → {Ip} (custom mapping)", qname, customIp);
            }
            else if (_config.DnsForwardUnknown)
            {
                reply = await ForwardAsync(buf, ct);
                _log.LogDebug("[DNS] Forwarded {Name}", qname);
            }
            else
            {
                // Public deployment: never act as an open resolver.
                reply = BuildRefused(buf, afterQname + 4);
                _log.LogDebug("[DNS] Refused {Name} (forwarding disabled)", qname);
            }

            if (reply.Length > 0)
                await _udp!.SendAsync(reply, reply.Length, client);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            _log.LogWarning("[DNS] Error handling query from {Ep}: {Msg}", client, ex.Message);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DNS wire-format helpers
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Parse a DNS QNAME starting at <paramref name="offset"/> in <paramref name="buf"/>.
    /// Returns the dotted name and sets <paramref name="afterName"/> to the byte
    /// immediately following the zero-length terminator.
    /// Returns null if the buffer is malformed.
    /// </summary>
    private static string? ParseQName(byte[] buf, int offset, out int afterName)
    {
        afterName = offset;
        var parts = new List<string>();

        while (offset < buf.Length)
        {
            int len = buf[offset];
            if (len == 0)
            {
                afterName = offset + 1;
                return string.Join('.', parts);
            }

            // Pointer (compression) — not expected in queries but handle gracefully
            if ((len & 0xC0) == 0xC0)
            {
                afterName = offset + 2;
                return string.Join('.', parts); // incomplete but safe
            }

            offset++;
            if (offset + len > buf.Length) return null;

            parts.Add(System.Text.Encoding.ASCII.GetString(buf, offset, len));
            offset += len;
        }

        return null;
    }

    /// <summary>
    /// Build a minimal DNS A-record response for a single IP address.
    /// </summary>
    private static byte[] BuildAResponse(byte[] query, string qname, string ipStr)
    {
        if (!IPAddress.TryParse(ipStr, out var ip)) return Array.Empty<byte>();

        byte[] ipBytes = ip.MapToIPv4().GetAddressBytes();

        using var ms = new MemoryStream();

        // ── Header ────────────────────────────────────────────────────────────
        ms.Write(query, 0, 2);                       // ID (echo)
        ms.WriteByte(0x81); ms.WriteByte(0x80);      // Flags: QR=1 RD=1 RA=1
        ms.WriteByte(0x00); ms.WriteByte(0x01);      // QDCOUNT = 1
        ms.WriteByte(0x00); ms.WriteByte(0x01);      // ANCOUNT = 1
        ms.WriteByte(0x00); ms.WriteByte(0x00);      // NSCOUNT = 0
        ms.WriteByte(0x00); ms.WriteByte(0x00);      // ARCOUNT = 0

        // ── Question section (copy from query bytes 12 onward until end of QNAME) ─
        // We re-encode from the parsed name to be safe.
        WriteQName(ms, qname);
        ms.WriteByte(0x00); ms.WriteByte(0x01);      // QTYPE  = A
        ms.WriteByte(0x00); ms.WriteByte(0x01);      // QCLASS = IN

        // ── Answer section ────────────────────────────────────────────────────
        // Name: pointer back to offset 12 (the question's QNAME)
        ms.WriteByte(0xC0); ms.WriteByte(0x0C);      // pointer → offset 12
        ms.WriteByte(0x00); ms.WriteByte(0x01);      // TYPE  = A
        ms.WriteByte(0x00); ms.WriteByte(0x01);      // CLASS = IN
        ms.WriteByte(0x00); ms.WriteByte(0x00);      // TTL (high)
        ms.WriteByte(0x00); ms.WriteByte(0x3C);      // TTL = 60 s
        ms.WriteByte(0x00); ms.WriteByte(0x04);      // RDLENGTH = 4
        ms.Write(ipBytes, 0, 4);                     // RDATA = IPv4

        return ms.ToArray();
    }

    /// <summary>REFUSED (RCODE 5) reply echoing the query's ID, RD bit and question section.</summary>
    private static byte[] BuildRefused(byte[] query, int questionEnd)
    {
        var reply = new byte[questionEnd];
        Array.Copy(query, reply, questionEnd);
        reply[2] = (byte)(0x80 | (query[2] & 0x01));   // QR=1, opcode 0, RD copied
        reply[3] = 0x05;                                 // RA=0, RCODE=REFUSED
        reply[4] = 0x00; reply[5] = 0x01;                // QDCOUNT = 1
        reply[6] = reply[7] = reply[8] = reply[9] = reply[10] = reply[11] = 0;
        return reply;
    }

    private static void WriteQName(Stream ms, string name)
    {
        foreach (var label in name.Split('.'))
        {
            var bytes = System.Text.Encoding.ASCII.GetBytes(label);
            ms.WriteByte((byte)bytes.Length);
            ms.Write(bytes, 0, bytes.Length);
        }
        ms.WriteByte(0); // root label
    }

    // ─────────────────────────────────────────────────────────────────────────
    // External DNAS
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>IPv4 address of <see cref="MultiplayerConfig.ExternalDnasServer"/> (an IP, or a hostname resolved
    /// through the system resolver and cached for a minute). Null if it doesn't resolve.</summary>
    private async Task<string?> ResolveExternalDnasAsync(CancellationToken ct)
    {
        var server = _config.ExternalDnasServer.Trim();
        if (IPAddress.TryParse(server, out var literal))
            return literal.MapToIPv4().ToString();

        if (_externalDnasIp != null && DateTime.UtcNow - _externalDnasResolvedAt < ExternalDnasTtl)
            return _externalDnasIp;

        try
        {
            var addresses = await Dns.GetHostAddressesAsync(server, AddressFamily.InterNetwork, ct);
            if (addresses.Length > 0)
            {
                _externalDnasIp         = addresses[0].ToString();
                _externalDnasResolvedAt = DateTime.UtcNow;
            }
        }
        catch (Exception ex) when (ex is SocketException or ArgumentException)
        {
            _log.LogWarning("[DNS] Cannot resolve external DNAS {Server}: {Msg}", server, ex.Message);
        }
        // A stale address beats none if the lookup fails transiently.
        return _externalDnasIp;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Forwarder
    // ─────────────────────────────────────────────────────────────────────────

    private static async Task<byte[]> ForwardAsync(byte[] query, CancellationToken ct)
    {
        try
        {
            using var fwd = new UdpClient();
            await fwd.SendAsync(query, query.Length, Upstream);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(3));

            var result = await fwd.ReceiveAsync(cts.Token);
            return result.Buffer;
        }
        catch
        {
            return Array.Empty<byte>();
        }
    }
}
