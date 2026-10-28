using System.Net;
using System.Net.Sockets;
using System.Text;
using CodeDesigner.Ps2.Multiplayer.Config;
using CodeDesigner.Ps2.Multiplayer.Models;
using CodeDesigner.Ps2.Multiplayer.Protocol;
using Microsoft.Extensions.Logging;

namespace CodeDesigner.Ps2.Multiplayer.Servers;

/// <summary>
/// Localhost-only debug API for testing lobby mods without extra consoles. Disabled unless
/// <see cref="MultiplayerConfig.DebugApiPort"/> is set; always binds 127.0.0.1.
///
/// GET /worlds                                    DME worlds, their clients and fake clients
/// GET /fake/join?world=W[&amp;index=K][&amp;ip=A.B.C.D][&amp;layout=v108|4|8]
///                                                reserve slot K (first free if omitted) and send
///                                                SERVER_CONNECT_NOTIFY for it to every joined client
/// GET /fake/leave?world=W&amp;index=K[&amp;layout=v108|4|8]   SERVER_DISCONNECT_NOTIFY + release
/// GET /fake/inbox?world=W[&amp;clear=1]             app payloads real clients sent to fake clients (To -1 = broadcast)
/// GET /clients                                   lobby (MLS) clients: connection id, account, endpoint
/// GET /rooms                                     briefing rooms: players in each (status, game), games listed, community
/// GET /lobby/join?name=N[&amp;room=0x44|US EAST]     put a virtual player in a briefing room (shows in the room's
///                                                player list / count / FindPlayer on a real console)
/// GET /lobby/leave?name=N                        remove a virtual player
/// GET /peek?client=C&amp;addr=0x..&amp;len=N            read client EE memory (RAW_MEMORY cheat query)
/// GET /poke?client=C&amp;addr=0x..&amp;hex=..            write client EE memory (SERVER_MEMORY_POKE)
/// GET /raw?world=W&amp;type=0x08&amp;hex=0100...         raw RT frame to every joined client
/// GET /app?world=W&amp;from=K&amp;hex=...                  app payload relayed as if DME client K sent it
///
/// Every request must carry an <c>X-Debug-Token</c> header (the value of <see cref="MultiplayerConfig.DebugApiToken"/>
/// when one is set, otherwise any value) and a localhost Host header. A web page can't add a custom header to a
/// cross-site request, so this stops a page open in the operator's browser from driving /poke or /raw.
///   curl -H "X-Debug-Token: secret" "http://127.0.0.1:PORT/clients"
///
/// Notify layouts: v108 (default, what SOCOM II accepts) = [index:2][ip:16][key:64] / [index:2][ip:16];
/// 4 = [index:2][scertId:2], 8 = 4 + [ip:4] — both rejected by the client (it drops out of the game).
/// W is the DME world id (see /worlds); omit it when exactly one world has joined clients.
/// </summary>
public class DebugApiServer
{
    private readonly MultiplayerConfig _config;
    private readonly ILogger<DebugApiServer> _log;
    private readonly MlsServer _mls;
    private TcpListener? _listener;

    public DebugApiServer(MultiplayerConfig config, MlsServer mls, ILogger<DebugApiServer> log)
    {
        _mls    = mls;
        _config = config;
        _log    = log;
    }

    public Task StartAsync(CancellationToken ct)
    {
        if (_config.DebugApiPort <= 0) return Task.CompletedTask;

        _listener = new TcpListener(IPAddress.Loopback, _config.DebugApiPort);
        _listener.Start();
        _log.LogWarning("[DEBUG] Debug API listening on 127.0.0.1:{Port} (fake DME clients enabled)", _config.DebugApiPort);
        _ = AcceptLoopAsync(ct);
        return Task.CompletedTask;
    }

    public void Stop()
    {
        try { _listener?.Stop(); } catch { /* ignore */ }
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        int failures = 0;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var client = await _listener!.AcceptTcpClientAsync(ct);
                failures = 0;
                _ = HandleClientAsync(client, ct);
            }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "[DEBUG] Accept failed");
                try { await Task.Delay(Math.Min(2000, 50 << Math.Min(failures++, 6)), ct); }
                catch (OperationCanceledException) { break; }
            }
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        using var _ = client;
        try
        {
            var stream = client.GetStream();
            using var readTimeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            readTimeout.CancelAfter(TimeSpan.FromSeconds(5));
            var head = await ReadHeadAsync(stream, readTimeout.Token);
            var lines = head.Split("\r\n");
            var requestLine = lines[0];
            var parts = requestLine.Split(' ');
            string body;
            int code = 200;
            try
            {
                Authorize(lines);
                body = parts.Length >= 2
                    ? await HandleMemoryAsync(parts[1], ct) ?? Handle(parts[1])
                    : throw new ArgumentException("bad request");
            }
            catch (UnauthorizedAccessException ex)
            {
                code = 403;
                body = ex.Message;
            }
            catch (Exception ex) when (ex is ArgumentException or FormatException or OverflowException)
            {
                code = 400;
                body = ex.Message;
            }
            _log.LogInformation("[DEBUG] {Request} -> {Code} {Body}", requestLine, code, body.Replace('\n', ' '));
            var reason = code switch { 200 => "OK", 403 => "Forbidden", _ => "Bad Request" };
            var msg = $"HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\n" +
                      $"Content-Length: {Encoding.ASCII.GetByteCount(body)}\r\nConnection: close\r\n\r\n{body}";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(msg), ct);
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException)
        {
            // client went away (or never finished its request)
        }
    }

    /// <summary>Read the request line and headers (up to the blank line, at most 8 KiB).</summary>
    private static async Task<string> ReadHeadAsync(NetworkStream stream, CancellationToken ct)
    {
        var buf = new byte[8192];
        int len = 0;
        while (len < buf.Length)
        {
            int read = await stream.ReadAsync(buf.AsMemory(len), ct);
            if (read == 0) break;
            len += read;
            int end = Encoding.ASCII.GetString(buf, 0, len).IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (end >= 0) return Encoding.ASCII.GetString(buf, 0, end);
        }
        return Encoding.ASCII.GetString(buf, 0, len);
    }

    /// <summary>Require a localhost Host (defeats DNS rebinding) and the X-Debug-Token header (defeats cross-site requests).</summary>
    private void Authorize(string[] requestLines)
    {
        string? host = null, token = null;
        foreach (var line in requestLines.Skip(1))
        {
            int colon = line.IndexOf(':');
            if (colon <= 0) continue;
            var name  = line[..colon].Trim();
            var value = line[(colon + 1)..].Trim();
            if (name.Equals("Host", StringComparison.OrdinalIgnoreCase)) host = value;
            else if (name.Equals("X-Debug-Token", StringComparison.OrdinalIgnoreCase)) token = value;
        }

        var hostName = host == null ? null
            : host.StartsWith('[') ? host[..(host.IndexOf(']') + 1)]
            : host.Split(':')[0];
        if (hostName is not ("127.0.0.1" or "localhost" or "[::1]"))
            throw new UnauthorizedAccessException("Host must be 127.0.0.1 or localhost");

        if (token == null)
            throw new UnauthorizedAccessException("missing X-Debug-Token header");
        if (_config.DebugApiToken.Length > 0 &&
            !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(token), Encoding.UTF8.GetBytes(_config.DebugApiToken)))
            throw new UnauthorizedAccessException("wrong X-Debug-Token");
    }

    /// <summary>
    /// Lobby-client memory endpoints (MLS connection): /clients, /peek?client=&amp;addr=&amp;len=,
    /// /poke?client=&amp;addr=&amp;hex=. Returns null for any other path.
    /// </summary>
    private async Task<string?> HandleMemoryAsync(string target, CancellationToken ct)
    {
        var path = target.Split('?')[0];
        var q = ParseQuery(target);
        switch (path)
        {
            case "/clients":
            {
                var list = _mls.LobbyClients();
                return list.Count == 0 ? "(no lobby clients)"
                    : string.Join('\n', list.Select(c => $"{c.ConnectionId} {(c.Account.Length > 0 ? c.Account : "(not logged in)")} {c.Endpoint}"));
            }
            case "/peek":
            {
                var conn = _mls.ResolveClient(q.GetValueOrDefault("client"));
                uint addr = (uint)ParseLong(Required(q, "addr"));
                int len = (int)ParseLong(q.GetValueOrDefault("len", "4"));
                if (len <= 0 || len > 0x10000) throw new ArgumentException("len must be 1..65536");
                var data = await _mls.PeekAsync(conn, addr, len, TimeSpan.FromSeconds(5), ct);
                return Convert.ToHexString(data);
            }
            case "/poke":
            {
                var conn = _mls.ResolveClient(q.GetValueOrDefault("client"));
                uint addr = (uint)ParseLong(Required(q, "addr"));
                var data = Convert.FromHexString(Required(q, "hex"));
                if (data.Length == 0) throw new ArgumentException("hex is empty");
                if (!await _mls.PokeAsync(conn, addr, data, ct)) throw new ArgumentException("client is gone");
                return $"poked {data.Length} byte(s) at 0x{addr:X8}";
            }
            case "/rooms":
                return _mls.RoomsReport();
            case "/lobby/join":
                return _mls.VirtualPlayerJoin(Required(q, "name"), q.GetValueOrDefault("room"));
            case "/lobby/leave":
                return _mls.VirtualPlayerLeave(Required(q, "name"));
            case "/chat":
            {
                var conn = _mls.ResolveClient(q.GetValueOrDefault("client"));
                string from = q.GetValueOrDefault("name", "BOT");
                int n = await _mls.InjectChatAsync(conn, from, Required(q, "text"), (int)ParseLong(q.GetValueOrDefault("account", "0")), ct);
                return $"lobby chat from '{from}' sent to {n} player(s)";
            }
            default:
                return null;
        }
    }

    private static long ParseLong(string s)
        => s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? Convert.ToInt64(s[2..], 16)
            : long.TryParse(s, out var n) ? n : throw new ArgumentException($"not a number: {s}");

    private static string Handle(string target)
    {
        var path = target.Split('?')[0];
        var q = ParseQuery(target);

        switch (path)
        {
            case "/worlds":
                return string.Join("\n", DmeWorld.All.Select(Describe)) is { Length: > 0 } s ? s : "(no worlds)";

            case "/fake/join":
            {
                var world = ResolveWorld(q);
                int? want = q.TryGetValue("index", out var idx) ? ParseInt(idx) : null;
                var index = world.ReserveFake(want) ?? throw new ArgumentException($"slot {want?.ToString() ?? "(any)"} not free");
                int sent = world.SendToJoined(RT_MSG_TYPE.RT_MSG_SERVER_CONNECT_NOTIFY, NotifyPayload(index, q, connect: true));
                return $"fake client {index} joined {world}, notified {sent}";
            }

            case "/fake/leave":
            {
                var world = ResolveWorld(q);
                int index = ParseInt(Required(q, "index"));
                if (!world.ReleaseFake(index)) throw new ArgumentException($"{index} is not a fake client");
                int sent = world.SendToJoined(RT_MSG_TYPE.RT_MSG_SERVER_DISCONNECT_NOTIFY, NotifyPayload(index, q, connect: false));
                return $"fake client {index} left {world}, notified {sent}";
            }

            case "/fake/inbox":
            {
                var world = ResolveWorld(q);
                var items = world.FakeInbox.ToArray();
                if (q.ContainsKey("clear")) world.FakeInbox.Clear();
                return items.Length == 0 ? "(empty)" : string.Join("\n", items.Select(m =>
                    $"{m.At:HH:mm:ss.fff} {m.From}->{m.To} [{m.Payload.Length}] {Convert.ToHexString(m.Payload)}"));
            }

            case "/raw":
            {
                var world = ResolveWorld(q);
                var type = (RT_MSG_TYPE)ParseInt(Required(q, "type"));
                int sent = world.SendToJoined(type, Convert.FromHexString(q.GetValueOrDefault("hex", "")));
                return $"{type} sent to {sent} client(s) in {world}";
            }

            case "/app":
            {
                var world = ResolveWorld(q);
                int from = ParseInt(Required(q, "from"));
                int sent = world.ForwardAppFrom(from, Convert.FromHexString(Required(q, "hex")));
                return $"app payload from {from} relayed to {sent} client(s) in {world}";
            }

            default:
                throw new ArgumentException("unknown path; try /clients, /rooms, /lobby/join, /lobby/leave, /chat, /peek, /poke, /worlds, /fake/join, /fake/leave, /fake/inbox, /raw, /app");
        }
    }

    /// <summary>
    /// layout v108 (default): connect = [index:2][ip:16 str][key:64], disconnect = [index:2][ip:16 str] — what
    /// the SOCOM II DME client accepts. layouts 4 / 8 ([index:2][scertId:2](+[ip:4])) are kept for comparison;
    /// the client rejects them and drops out of the game.
    /// </summary>
    private static byte[] NotifyPayload(int index, Dictionary<string, string> q, bool connect)
    {
        var layout = q.GetValueOrDefault("layout", "v108");
        var ip     = q.GetValueOrDefault("ip", "127.0.0.1");
        if (layout == "v108")
            return connect
                ? DmeClientState.BuildConnectNotify(index, ip, Crypto.Ps2Rsa.ServerKey.GetPublicKey())
                : DmeClientState.BuildDisconnectNotify(index, ip);

        int scert = q.TryGetValue("scert", out var s) ? ParseInt(s) : 0x100 + index;
        var payload = new List<byte> { (byte)index, (byte)(index >> 8), (byte)scert, (byte)(scert >> 8) };
        if (layout == "8") payload.AddRange(IPAddress.Parse(ip).GetAddressBytes());
        else if (layout != "4") throw new ArgumentException("layout must be v108, 4 or 8");
        return payload.ToArray();
    }

    private static DmeWorld ResolveWorld(Dictionary<string, string> q)
    {
        if (q.TryGetValue("world", out var w))
            return DmeWorld.GetById(ParseInt(w)) ?? throw new ArgumentException($"no DME world {w}");

        var active = DmeWorld.All.Where(x => x.Clients.Values.Any(c => c.HasJoined)).ToList();
        return active.Count == 1 ? active[0]
            : throw new ArgumentException($"{active.Count} worlds have joined clients; pass world=<id>");
    }

    private static string Describe(DmeWorld w)
    {
        var real  = w.Clients.Values.OrderBy(c => c.DmeId)
            .Select(c => $"{c.DmeId}:acct{c.AccountId}{(c.HasJoined ? "" : "(reserved)")}");
        var fakes = w.FakeIds.OrderBy(i => i).Select(i => $"{i}:fake");
        return $"{w} real=[{string.Join(", ", real)}] fake=[{string.Join(", ", fakes)}]";
    }

    private static string Required(Dictionary<string, string> q, string key)
        => q.TryGetValue(key, out var v) ? v : throw new ArgumentException($"missing {key}=");

    private static int ParseInt(string s)
        => s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? Convert.ToInt32(s[2..], 16)
            : int.TryParse(s, out var n) ? n : throw new ArgumentException($"not a number: {s}");

    private static Dictionary<string, string> ParseQuery(string target)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        int qi = target.IndexOf('?');
        if (qi < 0) return result;
        foreach (var pair in target[(qi + 1)..].Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var kv = pair.Split('=', 2);
            result[Uri.UnescapeDataString(kv[0])] = kv.Length > 1 ? Uri.UnescapeDataString(kv[1]) : "";
        }
        return result;
    }
}
