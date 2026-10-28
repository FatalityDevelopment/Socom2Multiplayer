using System.Collections.Concurrent;
using CodeDesigner.Ps2.Multiplayer.Models;
using CodeDesigner.Ps2.Multiplayer.Protocol;
using CodeDesigner.Ps2.Multiplayer.Storage;
using Microsoft.Extensions.Logging;

namespace CodeDesigner.Ps2.Multiplayer.Servers;

/// <summary>
/// Debug-API memory access to a logged-in lobby client: peek = RAW_MEMORY cheat queries (reply matched by
/// sequence id in <see cref="HandleCheatQueryResponseAsync"/>), poke = SERVER_MEMORY_POKE writes. Used by
/// <see cref="DebugApiServer"/> (localhost only) and Mods/server/socom_server.py.
/// </summary>
public partial class MlsServer
{
    /// <summary>Largest RAW_MEMORY read per query (the scanner uses the same cap).</summary>
    public const int MaxPeekChunk = 1024;

    private static readonly ConcurrentDictionary<(string Conn, int Seq), TaskCompletionSource<byte[]>> PendingPeeks = new();

    /// <summary>Connected lobby clients: connection id, account name (empty before login), remote endpoint.</summary>
    public IReadOnlyList<(string ConnectionId, string Account, string Endpoint)> LobbyClients() =>
        Clients.Values
            .Where(c => c.Client.Connected)
            .Select(c => (c.State.ConnectionId, c.State.AccountName ?? "", c.State.RemoteEndpoint))
            .ToList();

    /// <summary>
    /// Find a client by account name (case-insensitive) or connection id; with no selector, the only
    /// logged-in client. Throws <see cref="ArgumentException"/> with a usable message otherwise.
    /// </summary>
    public string ResolveClient(string? selector)
    {
        var all = Clients.Values.Where(c => c.Client.Connected).ToList();
        if (string.IsNullOrWhiteSpace(selector))
        {
            var loggedIn = all.Where(c => c.State.IsLoggedIn).ToList();
            return loggedIn.Count == 1 ? loggedIn[0].State.ConnectionId
                : throw new ArgumentException($"{loggedIn.Count} logged-in lobby clients; pass client=<account or connection id>");
        }
        var hit = all.FirstOrDefault(c => c.State.ConnectionId == selector);
        if (hit.State == null)
            hit = all.FirstOrDefault(c => string.Equals(c.State.AccountName, selector, StringComparison.OrdinalIgnoreCase));
        return hit.State?.ConnectionId ?? throw new ArgumentException($"no lobby client '{selector}'");
    }

    /// <summary>Read <paramref name="length"/> bytes of the client's EE memory (split into 1 KB queries).</summary>
    public async Task<byte[]> PeekAsync(string connectionId, uint address, int length, TimeSpan timeout, CancellationToken ct)
    {
        if (!Clients.TryGetValue(connectionId, out var c)) throw new ArgumentException($"client {connectionId} is gone");
        var result = new byte[length];
        for (int off = 0; off < length; off += MaxPeekChunk)
        {
            int n = Math.Min(MaxPeekChunk, length - off);
            int seq = c.State.NextCheatSeq();
            var waiter = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            PendingPeeks[(connectionId, seq)] = waiter;
            try
            {
                await SendPacketAsync(c.Client, ScertPacket.CreateRawMemoryQuery(seq, address + (uint)off, n), c.State, ct);
                var data = await waiter.Task.WaitAsync(timeout, ct);
                Buffer.BlockCopy(data, 0, result, off, Math.Min(n, data.Length));
            }
            catch (TimeoutException)
            {
                throw new ArgumentException($"no reply for 0x{address + (uint)off:X8}+{n} within {timeout.TotalSeconds:0.#}s");
            }
            finally
            {
                PendingPeeks.TryRemove((connectionId, seq), out _);
            }
        }
        return result;
    }

    /// <summary>
    /// Lobby / game-lobby chat "from" any name: a ChatFwdMessage (Broadcast) sent to every session in the same
    /// Medius world as <paramref name="connectionId"/> (that player included). Lobby chat is Medius, not DME, so
    /// fake players can only talk there through the server. Returns the number of recipients.
    /// </summary>
    public async Task<int> InjectChatAsync(string connectionId, string fromName, string text, int fromAccountId, CancellationToken ct)
    {
        if (!Clients.TryGetValue(connectionId, out var c)) throw new ArgumentException($"client {connectionId} is gone");
        var fwd = new MediusWriter();
        fwd.WritePadding(MediusConstants.MESSAGEID_MAXLEN);
        fwd.WritePadding(3);
        fwd.Write(fromAccountId);
        fwd.WriteString(fromName, NameLen);
        fwd.Write((int)MediusChatMessageType.Broadcast);
        fwd.WriteString(text, ChatLen);
        var body = fwd.ToArray();

        var recipients = Clients.Values.Where(x => x.Client.Connected && x.State.IsSessionEstablished
                                                   && x.State.WorldId == c.State.WorldId).ToList();
        foreach (var (rState, rTcp) in recipients)
            await SendMediusAsync(rTcp, MediusPacket.BuildLobby(MediusLobbyMessageId.ChatFwdMessage, body), rState, ct);
        return recipients.Count;
    }

    // ── Briefing rooms: who is where, and virtual players for testing the room lists on one console ──────────

    /// <summary>Configured briefing rooms as store channels (seeded if needed), using the first connected or allowed AppId.</summary>
    private List<MediusChannel> DebugRooms()
    {
        int appId = Clients.Values.Select(c => c.State.AppId).FirstOrDefault(a => a != 0);
        if (appId == 0) appId = _config.AllowedAppIds.FirstOrDefault();
        return GetBriefingRoomChannels(appId);
    }

    /// <summary>
    /// One line per briefing room (id, name, players) followed by the players in it (name, status, game) and the
    /// live games listed there; then the players on the community screen (world 1).
    /// </summary>
    public string RoomsReport()
    {
        var rooms = DebugRooms();
        var online = _presence.Snapshot();
        var sb = new System.Text.StringBuilder();
        string Player((int AccountId, PresenceRegistry.Presence State, bool IsVirtual) p)
        {
            var acct = _store.GetAccountById(p.AccountId);
            string where = p.State.Status == MediusPlayerStatus.MediusPlayerInGameWorld ? $" in game 0x{p.State.GameWorldId:X} '{p.State.GameName}'" : "";
            return $"    {acct?.AccountName ?? "?"} (acct {p.AccountId}) {p.State.Status}{where}{(p.IsVirtual ? " [virtual]" : "")}";
        }

        foreach (var room in rooms)
        {
            var players = online.Where(p => p.State.LobbyWorldId == room.ChannelId).ToList();
            sb.AppendLine($"room 0x{room.ChannelId:X} {room.ChannelName}: {players.Count}/{room.MaxPlayers} players");
            foreach (var p in players.OrderBy(p => _store.GetAccountById(p.AccountId)?.AccountName)) sb.AppendLine(Player(p));
            foreach (var g in _store.GetGames(room.AppId).Where(g => g.LobbyChannelId == room.ChannelId))
            {
                var w = g.DmeWorldId is int wid ? DmeWorld.GetById(wid) : null;
                sb.AppendLine($"    game 0x{g.GameId:X} '{g.GameName}' host {g.HostName}: {w?.ConnectedCount ?? g.PlayerCount}/{g.MaxPlayers}" +
                              (w is { SpectatorCount: > 0 } ? $" ({w.SpectatorCount} spectating)" : "") + (g.IsLocked ? " [password]" : "") +
                              (g.IsSpectatorLocked ? " [spectator password]" : ""));
            }
            foreach (var kv in _defaultGameWorlds.Where(kv => kv.Key >> 8 == room.ChannelId && DmeWorld.GetById(kv.Value.WorldId) == kv.Value && kv.Value.ConnectedCount > 0))
            {
                int index = (kv.Key & 0xFF) - 2;
                string name = index >= 0 && index < _config.DefaultGames.Count ? _config.DefaultGames[index].Name : "?";
                sb.AppendLine($"    default game 0x{kv.Key:X} '{name}': {kv.Value.ConnectedCount}/{DefaultGameMaxPlayers}" +
                              (kv.Value.SpectatorCount > 0 ? $" ({kv.Value.SpectatorCount} spectating)" : ""));
            }
        }

        var community = online.Where(p => rooms.All(r => r.ChannelId != p.State.LobbyWorldId)).ToList();
        sb.AppendLine($"community (world 1): {community.Count} players");
        foreach (var p in community) sb.AppendLine(Player(p));
        return sb.ToString().TrimEnd();
    }

    /// <summary>
    /// Put a virtual player (an account created on demand) into a briefing room so the room's player list, player
    /// count and FindPlayer show it to a real console. <paramref name="room"/> is a MediusWorldID or room name.
    /// </summary>
    public string VirtualPlayerJoin(string name, string? room)
    {
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("name= is required");
        var rooms = DebugRooms();
        var target = string.IsNullOrWhiteSpace(room) ? rooms.FirstOrDefault()
            : rooms.FirstOrDefault(r => string.Equals(r.ChannelName, room, StringComparison.OrdinalIgnoreCase))
              ?? (TryParseAddr(room, out uint id) ? rooms.FirstOrDefault(r => r.ChannelId == (int)id) : null);
        if (target == null) throw new ArgumentException($"no briefing room '{room}'; rooms: {string.Join(", ", rooms.Select(r => $"0x{r.ChannelId:X} {r.ChannelName}"))}");

        var account = _store.GetOrCreateAccount(name.Trim(), string.Empty, out _);
        // A password means a real player owns the name; a virtual player would hijack its presence.
        if (account.PasswordHash.Length > 0)
            throw new ArgumentException($"'{account.AccountName}' is a real player's account");
        if (_presence.IsOnline(account.AccountId) && !_presence.IsVirtual(account.AccountId))
            throw new ArgumentException($"'{account.AccountName}' is a real online player");
        _presence.AddVirtual(account.AccountId, target.ChannelId, target.ChannelName);
        _log.LogInformation("[DEBUG] Virtual player '{Name}' (acct {Id}) placed in room 0x{Room:X} {RoomName}",
            account.AccountName, account.AccountId, target.ChannelId, target.ChannelName);
        return $"'{account.AccountName}' (acct {account.AccountId}) is now in room 0x{target.ChannelId:X} {target.ChannelName}";
    }

    /// <summary>Remove a virtual player placed with <see cref="VirtualPlayerJoin"/>.</summary>
    public string VirtualPlayerLeave(string name)
    {
        var account = _store.GetAccountByName(name?.Trim() ?? "") ?? throw new ArgumentException($"no account '{name}'");
        if (!_presence.RemoveVirtual(account.AccountId)) throw new ArgumentException($"'{account.AccountName}' is not a virtual player");
        _log.LogInformation("[DEBUG] Virtual player '{Name}' removed", account.AccountName);
        return $"'{account.AccountName}' left";
    }

    /// <summary>Write <paramref name="data"/> into the client's EE memory with SERVER_MEMORY_POKE (512-byte chunks).</summary>
    public Task<bool> PokeAsync(string connectionId, uint address, byte[] data, CancellationToken ct) =>
        InjectIntoClientAsync(connectionId, address, data, hookAddr: null, entryAddr: null, chunkSize: 512, ct);
}
