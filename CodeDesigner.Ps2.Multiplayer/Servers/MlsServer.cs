using System.Net.Sockets;
using System.Text.Json;
using CodeDesigner.Ps2.Multiplayer.Config;
using CodeDesigner.Ps2.Multiplayer.Crypto;
using CodeDesigner.Ps2.Multiplayer.Models;
using CodeDesigner.Ps2.Multiplayer.Protocol;
using CodeDesigner.Ps2.Multiplayer.Storage;
using Microsoft.Extensions.Logging;

namespace CodeDesigner.Ps2.Multiplayer.Servers;

/// <summary>
/// MLS — Medius Lobby Server.
/// Clients connect here after authenticating on MAS.
/// Provides channel listing, game creation/joining, chat, buddy lists, etc.
///
/// Default port: 10073 (TCP)
/// </summary>
public partial class MlsServer : BaseMediusTcpServer
{
    private readonly MultiplayerConfig       _config;
    private readonly InMemoryStorage    _store;
    private readonly PresenceRegistry   _presence;
    private readonly ILogger<MlsServer> _log;

    // MLS connections that registered presence for an account (ConnectionId → AccountId).
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, int> _presenceByConnection = new();

    public MlsServer(MultiplayerConfig config, InMemoryStorage store, PresenceRegistry presence, AdminSettings admin,
        ILogger<MlsServer> log)
        : base(log, config)
    {
        _config    = config;
        _store     = store;
        _presence  = presence;
        _admin     = admin;
        _log       = log;
        ServerName = "MLS";
        admin.BansChanged += bans => KickBanned(bans, _store);
    }

    private readonly AdminSettings _admin;

    /// <summary>
    /// Bind this MLS connection to its account. MLS never sees the login itself: the client presents the MAS
    /// session key as the access key of its CLIENT_CONNECT_TCP (MAS AccountLoginResponse / JoinChannel set it),
    /// and MAS registered that key at login. Also registers the account as online in the connection's lobby.
    /// </summary>
    private MediusAccount? ResolveAccount(MediusClientState state)
    {
        if (state.AccountId is int known) return _store.GetAccountById(known);

        var account = _store.GetAccountBySession(state.AccessKey);
        if (account == null) return null;
        if (account.IsBanned || _admin.Bans.FindAccount(account.AccountName) != null)
        {
            _log.LogWarning("[MLS] Connection {Conn} presented a session of banned account '{Name}' — ignored",
                state.ConnectionId, account.AccountName);
            return null;
        }

        state.AccountId   = account.AccountId;
        state.AccountName = account.AccountName;
        if (_presenceByConnection.TryAdd(state.ConnectionId, account.AccountId))
        {
            var room = state.WorldId is int w ? _store.GetChannelById(w) : null;
            _presence.Connected(account.AccountId, room?.ChannelId ?? state.WorldId ?? 0, room?.ChannelName ?? "Community");
        }
        _log.LogInformation("[MLS] Connection {Conn} is account {Id} '{Name}' (world 0x{World:X})",
            state.ConnectionId, account.AccountId, account.AccountName, state.WorldId ?? 0);
        return account;
    }

    private FileSystemWatcher? _injectWatcher;

    public Task StartAsync(CancellationToken ct)
    {
        StartInjectDropWatcher(ct);
        _ = RunMaintenanceLoopAsync(ct);
        return StartAsync(_config.BindAddress, _config.MlsPort, ct);
    }

    /// <summary>A JoinGame reservation the console never connects to the DME with is released after this.</summary>
    internal static readonly TimeSpan ReservationTtl = TimeSpan.FromSeconds(60);

    /// <summary>An empty game world (and its game-list row) is removed this long after its last player left.</summary>
    internal static readonly TimeSpan EmptyWorldGrace = TimeSpan.FromSeconds(60);

    private async Task RunMaintenanceLoopAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(10));
        try
        {
            while (await timer.WaitForNextTickAsync(ct))
            {
                try { SweepGames(); }
                catch (Exception ex) { _log.LogError(ex, "[MLS] Game sweep failed"); }
            }
        }
        catch (OperationCanceledException) { /* shutdown */ }
    }

    /// <summary>
    /// Release stale DME reservations, destroy empty game worlds, and drop games (with their host reports and
    /// vote-out bans) whose world is gone. Runs every 10 s; also called from tests.
    /// </summary>
    internal void SweepGames()
    {
        foreach (var world in DmeWorld.Sweep(ReservationTtl, EmptyWorldGrace))
            _log.LogInformation("[MLS] {World} swept: empty for {S}s", world, EmptyWorldGrace.TotalSeconds);

        foreach (var g in _store.AllGames.ToList())
        {
            var gw = g.DmeWorldId is int wid ? DmeWorld.GetById(wid) : null;
            if ((gw == null || gw.MediusWorldId != g.GameId) && DateTime.UtcNow - g.CreatedAt > EmptyWorldGrace)
                RemoveGame(g, "DME world gone");
        }

        var liveWorlds = DmeWorld.All.Select(w => w.MediusWorldId).ToHashSet();
        foreach (var id in _worldReports.Keys)
            if (!liveWorlds.Contains(id)) _worldReports.TryRemove(id, out _);
        foreach (var (id, bans) in _gameBans)
        {
            foreach (var (acct, until) in bans)
                if (until <= DateTime.UtcNow) bans.TryRemove(acct, out _);
            if (bans.IsEmpty) _gameBans.TryRemove(id, out _);
        }
    }

    /// <summary>Remove a player game and everything keyed by its MediusWorldID.</summary>
    private void RemoveGame(MediusGame game, string reason)
    {
        if (!_store.RemoveGame(game.GameId)) return;
        _worldReports.TryRemove(game.GameId, out _);
        _gameBans.TryRemove(game.GameId, out _);
        _log.LogInformation("[MLS] Game 0x{Id:X} '{Name}' removed ({Reason})", game.GameId, game.GameName, reason);
    }

    // Fire the SCERT session-established callback right after the old-proto handshake so
    // configured binary injections go out as soon as the player reaches the lobby.
    protected override bool PushDataAfterConnectComplete => true;

    // REQUIRED on-hardware: the 29-byte SALTED CreateSaltedCheatQuery anti-cheat heartbeat keeps the community
    // screen alive. With it ON the client reaches the community screen and holds ~60-90s; with it OFF the client
    // disconnects almost immediately on login. The CADENCE doesn't matter much (15s and a reactive ~2/s ping-pong
    // both held ~60-90s), so we keep a calm 15s timer (CheatHeartbeatInterval) — no spam. The client accepts the
    // query and replies with a salted-MD5 hash. NOTE: a SEPARATE IOP-side watchdog still cuts the session at
    // ~60-90s regardless of cheat cadence — that's the remaining wall, not this heartbeat.
    protected override bool LobbyCheatHeartbeat => true;

    /// <summary>A player has reached the lobby — push any configured binary injections.</summary>
    protected override async Task OnSessionEstablishedAsync(MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        // SOCOM II's online-code download: retail pushed 610 plaintext SERVER_MEMORY_POKEs (~52 KB of code at
        // 0x000A0000 + hook pokes) on the lobby connection ~2.5 s after login, before the community screen
        // (universe-community-screen.pcap). The client ships without that code, so without it the lobby
        // times out ("Disconnected from Network"). Lobby connection only — a briefing-room reconnect already
        // has the code in RAM.
        if (!IsRoomConnection(state))
            await ReplayPokeStreamAsync(tcp, _config.LobbyPokeStreamFile, ct);

        await SendConfiguredInjectionsAsync(tcp, ct);

        // Lobby memory scanner (idle unless cheat-scan.json enables it).
        _ = RunCheatScanLoopAsync(state, tcp, ct);
    }

    /// <summary>
    /// True when this MLS connection was opened for a briefing room — the reconnect after JoinChannel, whose
    /// CLIENT_CONNECT_TCP TargetWorldId is the room's MediusWorldID. The lobby connection targets world 1
    /// (MAS AccountLoginResponse), which is never a channel.
    /// </summary>
    private bool IsRoomConnection(MediusClientState state) =>
        state.WorldId is int world && _store.GetChannelById(world) != null;

    // ── On-demand injection: watch a drop folder for *.json manifests ─────────
    private void StartInjectDropWatcher(CancellationToken ct)
    {
        var folder = _config.InjectDropFolder;
        if (string.IsNullOrWhiteSpace(folder)) return;
        try
        {
            Directory.CreateDirectory(folder);
            _injectWatcher = new FileSystemWatcher(folder, "*.json") { EnableRaisingEvents = true };
            _injectWatcher.Created += (_, e) => _ = HandleInjectManifestAsync(e.FullPath, ct);
            _log.LogInformation("[MLS] Watching inject drop folder: {Folder}", folder);
        }
        catch (Exception ex)
        {
            _log.LogWarning("[MLS] Could not start inject drop watcher on '{Folder}': {Msg}", folder, ex.Message);
        }
    }

    private async Task HandleInjectManifestAsync(string path, CancellationToken ct)
    {
        try
        {
            // The file may still be being written when the event fires — retry briefly.
            byte[] bytes = Array.Empty<byte>();
            for (int i = 0; i < 10; i++)
            {
                try { bytes = await File.ReadAllBytesAsync(path, ct); if (bytes.Length > 0) break; }
                catch (IOException) { await Task.Delay(100, ct); }
            }
            var inj = JsonSerializer.Deserialize<BinaryInjection>(bytes,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (inj == null || !TryParseAddr(inj.LoadAddress, out uint loadAddr))
            {
                _log.LogWarning("[MLS] Inject manifest '{P}': missing/invalid LoadAddress", Path.GetFileName(path));
                return;
            }

            // Resolve the .bin relative to the manifest first, then the usual locations.
            string binPath = inj.File;
            if (!File.Exists(binPath))
                binPath = Path.Combine(Path.GetDirectoryName(path) ?? ".", inj.File);
            if (!File.Exists(binPath))
            {
                _log.LogWarning("[MLS] Inject manifest '{P}': bin not found '{F}'", Path.GetFileName(path), inj.File);
                return;
            }

            uint? hookAddr  = TryParseAddr(inj.HookAddress, out uint h) ? h : null;
            uint? entryAddr = TryParseAddr(inj.EntryPoint, out uint e) ? e : null;
            var blob = await File.ReadAllBytesAsync(binPath, ct);

            int n = await InjectIntoAllAsync(loadAddr, blob, hookAddr, entryAddr, inj.ChunkSize, ct);
            _log.LogInformation("[MLS] On-demand inject '{N}' -> {Count} client(s)",
                string.IsNullOrEmpty(inj.Name) ? Path.GetFileName(binPath) : inj.Name, n);

            // Consume the manifest so it doesn't re-fire.
            try { File.Delete(path); } catch { /* ignore */ }
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            _log.LogWarning("[MLS] Inject manifest '{P}' failed: {Msg}", Path.GetFileName(path), ex.Message);
        }
    }

    protected override Task OnClientDisconnectedAsync(MediusClientState state)
    {
        // Remove player from whatever channel/game they were in
        if (state.CurrentChannelId.HasValue)
        {
            var ch = _store.GetChannelById(state.CurrentChannelId.Value);
            if (state.AccountId.HasValue) ch?.RemovePlayer(state.AccountId.Value);
        }
        if (state.CurrentGameId.HasValue)
        {
            var game = _store.GetGameById(state.CurrentGameId.Value);
            if (state.AccountId.HasValue) game?.RemovePlayer(state.AccountId.Value);
        }
        if (_presenceByConnection.TryRemove(state.ConnectionId, out int accountId))
            _presence.Disconnected(accountId);
        return Task.CompletedTask;
    }

    // =========================================================================
    // Medius message dispatch
    // =========================================================================

    protected override async Task HandleMediusMessageAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        ResolveAccount(state);

        if (packet.MessageClass == NetMessageClass.MessageClassLobby)
        {
            var typeId = (MediusLobbyMessageId)packet.MessageType;
            _log.LogDebug("[MLS] Lobby msg: {Type}", typeId);

            // Friends, ignore list, ladder rankings and clans (MlsServer.Social.cs).
            if (await TryHandleSocialAsync(typeId, packet, state, tcp, ct))
                return;

            switch (typeId)
            {
                case MediusLobbyMessageId.SessionBegin:
                    await HandleSessionBeginAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.AccountLogout:
                    await HandleAccountLogoutAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.GetAnnouncementsResponse:
                    break; // client-side only

                case MediusLobbyMessageId.GetAnnouncements:
                case MediusLobbyMessageId.GetAllAnnouncements:
                    await HandleGetAnnouncementsAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.ChannelList:
                case MediusLobbyMessageId.ChannelList_ExtraInfo0:
                    await HandleChannelListAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.JoinChannel:
                    await HandleJoinChannelAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.GameList:
                case MediusLobbyMessageId.GameList_ExtraInfo0:
                    await HandleGameListAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.CreateGameRequest0:
                case MediusLobbyMessageId.CreateGame1:
                    await HandleCreateGameAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.JoinGameRequest0:
                case MediusLobbyMessageId.JoinGame:
                    await HandleJoinGameAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.PlayerInfo:
                    await HandlePlayerInfoAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.GameInfo0:
                    await HandleGameInfoAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.WorldReport0:
                    HandleWorldReport0(packet, state);
                    break;

                case MediusLobbyMessageId.PlayerReport:
                    // In-game player stats report (282 B, retail sends it too) — one-way, no reply.
                    _log.LogDebug("[MLS] PlayerReport received (one-way)");
                    break;

                case MediusLobbyMessageId.EndGameReport:
                    HandleEndGameReport(packet, state);
                    break;

                case MediusLobbyMessageId.TextFilter:
                    await HandleTextFilterAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.UpdateUserState:
                    HandleUpdateUserState(packet, state);
                    break;

                case MediusLobbyMessageId.GetWorldSecurityLevel:
                    await HandleGetWorldSecurityLevelAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.GetMyIP:
                    await HandleGetMyIpAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.GetLocations:
                    await HandleGetLocationsAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.PickLocation:
                    await HandlePickLocationAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.VersionServer:
                    await HandleVersionServerAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.SetGameListFilter0:
                    await HandleSetGameListFilterAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.AccountUpdateStats:
                    await HandleAccountUpdateStatsAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.UpdateLadderStats:
                    await HandleUpdateLadderStatsAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.FileListFiles:
                    await HandleFileListFilesAsync(packet, state, tcp, ct);
                    break;

                // ── Community-screen init batch ─────────────────────────────
                // After the EULA/community screen the client fires its lobby-init
                // queries (buddy list, ignore list, clans, ladders, Policy). It waits
                // for replies to ALL of them; if any go unanswered it times out and
                // tears down every socket ("Disconnected from network"). We answer
                // each with the minimal valid Medius response (msgId echo + status +
                // empty list), framed exactly like the working MAS handlers.
                case MediusLobbyMessageId.Policy:
                    await HandlePolicyAsync(packet, state, tcp, ct);
                    break;

                // Friends, ignore list, ladders and clans are answered in MlsServer.Social.cs (TryHandleSocialAsync).
                case MediusLobbyMessageId.GetClanMemberList:
                    await HandleGetClanMemberListPlainAsync(packet, state, tcp, ct);
                    break;

                // ── Requests the SOCOM II client sends that used to go unanswered (MlsServer.Lobby.cs) ──
                // Each one was found in the r0004 client's Medius sender table (CodeDesigner.Ps2.Bridge/Resources/
                // Dumps/r0004.bin) with live callers; an unanswered request times out ~15 s later and can raise
                // the "Disconnected" screen, and ClearGameListFilter0 is the first link of the game-list refresh.
                case MediusLobbyMessageId.ClearGameListFilter0:
                    await HandleClearGameListFilterAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.FindWorldByName:
                    await HandleFindWorldByNameAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.GetTotalUsers:
                case MediusLobbyMessageId.GetTotalGames:
                case MediusLobbyMessageId.GetTotalChannels:
                    await HandleGetTotalsAsync(typeId, packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.SessionEnd:
                    await HandleSessionEndAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.SetLocalizationParams:
                    // Same header-only ack MAS sends (retail: 30 B on the wire).
                    await SendStatusAsync(packet, state, tcp, MediusLobbyMessageId.SetLocalizationParamsResponse, MediusCallbackStatus.MediusSuccess, ct);
                    break;

                default:
                    _log.LogInformation("[MLS] Unhandled lobby msg 0x{Type:X2} ({Name}, {Len} B)", packet.MessageType, (MediusLobbyMessageId)packet.MessageType, packet.Payload.Length);
                    break;
            }
        }
        else if (packet.MessageClass == NetMessageClass.MessageClassLobbyExt)
        {
            var typeId = (MediusLobbyExtMessageId)packet.MessageType;
            _log.LogDebug("[MLS] LobbyExt msg: {Type}", typeId);

            switch (typeId)
            {
                case MediusLobbyExtMessageId.GetUniverse_ExtraInfo:
                    await HandleGetUniverseAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyExtMessageId.ChannelList_ExtraInfo:
                    await HandleChannelListExtAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyExtMessageId.GameList_ExtraInfo:
                case MediusLobbyExtMessageId.GameList_ExtraInfoResponse:
                    await HandleGameListExtAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyExtMessageId.CreateGame:
                    await HandleCreateGameAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyExtMessageId.GenericChatMessage:
                    await HandleGenericChatAsync(packet, state, ct);
                    break;

                case MediusLobbyExtMessageId.UtilGetServerVersion:
                    await HandleUtilGetServerVersionAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyExtMessageId.DnasSignaturePost:
                    break; // ignore DNAS

                case MediusLobbyExtMessageId.WorldReport:
                    break; // server-to-server, ignore from client

                case MediusLobbyExtMessageId.VoteToBanPlayerRequest:
                    // Layout unknown (not in horizon) — logged in full so a vote-out on hardware shows it.
                    _log.LogInformation("[MLS] VoteToBanPlayerRequest from {Me} ({Len} B): {Hex}",
                        state.AccountName, packet.Payload.Length, Convert.ToHexString(packet.Payload));
                    break;

                case MediusLobbyExtMessageId.AddToBuddyListConfirmation:
                    await HandleAddToBuddyListConfirmationAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyExtMessageId.GetBuddyInvitations:
                    // Community-screen batch (23 B, MessageID only). Retail answered 74 B (create_Masquarr).
                    await HandleGetBuddyInvitationsAsync(packet, state, tcp, ct);
                    break;

                default:
                    _log.LogDebug("[MLS] Unhandled lobbyExt msg 0x{Type:X2}", packet.MessageType);
                    break;
            }
        }
    }

    // =========================================================================
    // Handlers
    // =========================================================================

    private async Task HandleSessionBeginAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        state.SessionKey = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(8));
        state.Status     = PlayerStatus.InChatWorld;
        // Later requests on this connection may present this key (e.g. JoinChannel falls back to it), so it has to
        // resolve to the same account as the connection's MAS key.
        if (ResolveAccount(state) is { } account)
            _store.RegisterSession(state.SessionKey, account.AccountId);

        var w = new MediusWriter();
        if (_config.WireFixes.MlsHeaderEcho)
        {
            // The MAS SessionBeginResponse layout: header | SessionKey[17] | pad3.
            WriteMlsHeader(w, packet, MediusCallbackStatus.MediusSuccess);
            w.WriteString(state.SessionKey, MediusConstants.SESSIONKEY_MAXLEN);
            w.WritePadding(3);
        }
        else
        {
            w.Write((int)MediusCallbackStatus.MediusSuccess);
            w.WriteString(state.SessionKey, 64);
        }

        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.SessionBeginResponse, w.ToArray()), ct);
    }

    private async Task HandleAccountLogoutAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        state.Status = PlayerStatus.Disconnected;
        _store.RevokeSession(state.AccessKey);
        _store.RevokeSession(state.SessionKey);
        if (_presenceByConnection.TryRemove(state.ConnectionId, out int loggedOut))
            _presence.Disconnected(loggedOut);
        state.AccountId   = null;
        state.AccountName = string.Empty;
        var w = new MediusWriter();
        if (_config.WireFixes.MlsHeaderEcho) WriteMlsHeader(w, packet, MediusCallbackStatus.MediusSuccess);
        else w.Write((int)MediusCallbackStatus.MediusSuccess);
        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.AccountLogoutResponse, w.ToArray()), ct);
    }

    private async Task HandleGetAnnouncementsAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        // ServerNews first, then any extra Announcements — one list row each, EndOfList on the last.
        var items = new[] { _config.ServerNews }.Concat(_config.Announcements)
            .Where(a => !string.IsNullOrWhiteSpace(a)).ToList();
        if (items.Count == 0) items.Add(string.Empty);

        // GetAnnouncementsResponse = header | AnnouncementID | Announcement[1000] | EndOfList | pad3 — horizon
        // layout, 1038 B on the wire exactly like the retail acceptEULA reply. The old reply carried a 256-byte
        // text + an extra int (298 B), so the client read EndOfList at +0x408 from PAST our payload — leftover
        // receive-buffer bytes: non-zero = fine, zero = it waited for another announcement that never came and
        // the request timed out on the news screen (the intermittent community disconnect).
        const int AnnouncementLen = 1000;
        for (int i = 0; i < items.Count; i++)
        {
            var w = new MediusWriter();
            WriteMlsHeader(w, packet, MediusCallbackStatus.MediusSuccess);
            w.Write(i + 1);                                  // 0x1C AnnouncementID
            w.WriteString(items[i], AnnouncementLen);        // 0x20 Announcement[1000]
            w.Write((byte)(i == items.Count - 1 ? 1 : 0));   // 0x408 EndOfList
            w.WritePadding(3);
            await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.GetAnnouncementsResponse, w.ToArray()), state, ct);
        }
    }

    private async Task HandleGetUniverseAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        // Universe variable info — send a minimal response
        var w = new MediusWriter();
        if (_config.WireFixes.MlsHeaderEcho) WriteMlsHeader(w, packet, MediusCallbackStatus.MediusSuccess);
        else w.Write((int)MediusCallbackStatus.MediusSuccess);
        w.Write((byte)1);  // End of list
        w.WriteString(_config.UniverseName, 64);
        w.WriteString(_config.EffectivePatchUrl, 128);

        await SendMediusAsync(tcp, MediusPacket.BuildLobbyExt(MediusLobbyExtMessageId.UniverseStatusList_ExtraInfoResponse, w.ToArray()), ct);
    }

    private async Task HandleChannelListAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        // ChannelList is the first community-screen init message — mark this connection as the community
        // connection so PlayerInfo polls on it get answered (the watchdog fix), while the login-batch
        // connection's PlayerInfo stays silent (answering it breaks the community transition).
        state.CommunityReached = true;

        // Reply with the response type that MATCHES the request: ChannelList_ExtraInfo0 (0xEC)
        // must be answered with ChannelList_ExtraInfoResponse (0xED), not the basic
        // ChannelListResponse (0x2C). Old-proto correlates a reply to its request by the echoed
        // messageID — the previous handler omitted the echo AND used the wrong type, so the
        // client's ChannelList_ExtraInfo0 transaction never completed and the community-screen
        // watchdog eventually timed out ("Disconnected from Network").
        var responseType = packet.MessageType == (byte)MediusLobbyMessageId.ChannelList_ExtraInfo0
            ? MediusLobbyMessageId.ChannelList_ExtraInfoResponse
            : MediusLobbyMessageId.ChannelListResponse;

        // The 0xEC→0xED channel list IS the online BRIEFING-room list: the client's 0xEC sender
        // (EE 0x003FD470) registers the RoomList callback (0x003009B0) for the reply. One 0xED per room;
        // the client only commits the list when an entry's EndOfList byte is set.
        var rooms = GetBriefingRoomChannels(state.AppId);
        bool retailLayout = responseType == MediusLobbyMessageId.ChannelList_ExtraInfoResponse
            && !string.Equals(_config.BriefingRoomListFormat, "Legacy", StringComparison.OrdinalIgnoreCase);

        for (int i = 0; i < rooms.Count; i++)
        {
            var ch = rooms[i];
            bool isLast = i == rooms.Count - 1;

            byte[] body = retailLayout
                ? BuildChannelListExtraInfoEntry(packet, ch, isLast)
                : BuildChannelListEntry(packet, ch, isLast);

            await SendMediusAsync(tcp, MediusPacket.BuildLobby(responseType, body), ct);
        }
    }

    /// <summary>
    /// Basic ChannelListResponse (0x2C) entry — small legacy layout from the 3b4ee8f baseline.
    /// </summary>
    private static byte[] BuildChannelListEntry(MediusPacket packet, MediusChannel ch, bool isLast)
    {
        var w = new MediusWriter();
        WriteMlsHeader(w, packet, MediusCallbackStatus.MediusSuccess);  // msgId echo + pad + status
        w.Write((byte)(isLast ? 1 : 0));  // EndOfList
        w.Write(ch.ChannelId);
        w.WriteString(ch.ChannelName, 64);
        w.Write(ch.PlayerCount);
        w.Write(ch.MaxPlayers);
        return w.ToArray();
    }

    /// <summary>
    /// ChannelList_ExtraInfoResponse (0xED) entry in the layout SOCOM II v108 actually parses — 0x70 bytes,
    /// reverse-engineered from the retail client's RoomList callback (EE 0x003009B0). It copies the payload
    /// into its room object (12-byte header + this struct) and commits the list only when EndOfList is set:
    ///   0x00 MessageID(21) + pad(3) | 0x18 StatusCode | 0x1C MediusWorldID (must be ≥0)
    ///   0x20 PlayerCount (u16) | 0x22 MaxPlayers (u16) | 0x24 SecurityLevel | 0x28 packed GenericField
    ///   0x2C LobbyName(64) | 0x6C EndOfList | 0x6D pad(3)
    /// Not Horizon's 0x80 layout (name@0x3C, EndOfList@0x7C) — that one dropped the client on hardware.
    /// </summary>
    private byte[] BuildChannelListExtraInfoEntry(MediusPacket packet, MediusChannel ch, bool isLast)
    {
        var w = new MediusWriter();
        WriteMlsHeader(w, packet, MediusCallbackStatus.MediusSuccess);  // 0x00 MessageID + pad + StatusCode
        w.Write(ch.ChannelId);              // 0x1C MediusWorldID
        // Online presence, not ch.PlayerCount: JoinChannel adds the player on the connection the client then
        // drops for the room hop, which removed them again (every room showed 0 players).
        w.Write((ushort)RoomPlayerCount(ch.ChannelId));    // 0x20 PlayerCount
        w.Write((ushort)ch.MaxPlayers);     // 0x22 MaxPlayers
        w.Write(ch.SecurityLevel);          // 0x24 SecurityLevel
        w.Write(ch.GenericField1);          // 0x28 rank bitmask (byte0) / display order (byte3)
        w.WriteString(ch.ChannelName, 64);  // 0x2C LobbyName
        w.Write((byte)(isLast ? 1 : 0));    // 0x6C EndOfList
        w.WritePadding(3);                  // 0x6D pad → total 0x70
        return w.ToArray();
    }

    /// <summary>
    /// Configured briefing rooms as store channels, seeded on first use with their MediusWorldIDs so
    /// JoinChannel resolves them, ordered per <see cref="MultiplayerConfig.BriefingRoomSortOrder"/>.
    /// </summary>
    private List<MediusChannel> GetBriefingRoomChannels(int appId)
    {
        var rooms = (_config.BriefingRooms ?? new List<BriefingRoomConfig>())
            .Where(r => !string.IsNullOrWhiteSpace(r.Name))
            .ToList();
        if (rooms.Count == 0) rooms = BriefingRoomConfig.RetailDefaults();
        if (string.Equals(_config.BriefingRoomSortOrder, "Alphabetical", StringComparison.OrdinalIgnoreCase))
            rooms.Sort((a, b) => StringComparer.OrdinalIgnoreCase.Compare(a.Name, b.Name));

        return rooms.Select(r =>
        {
            var ch = _store.GetOrCreateChannel(r.WorldId, r.Name, appId, r.MaxPlayers);
            // The room may have been seeded before any console connected (stats page, debug API) with AppId 0.
            if (ch.AppId == 0 && appId != 0) ch.AppId = appId;
            ch.SecurityLevel = r.SecurityLevel;
            ch.Password      = r.Password ?? string.Empty;
            ch.GenericField1 = unchecked((int)r.GenericField);
            return ch;
        }).ToList();
    }

    private async Task HandleChannelListExtAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var channels = _store.GetChannels(state.AppId).ToList();
        if (channels.Count == 0)
            channels.Add(_store.GetOrCreateDefaultChannel(state.AppId));

        for (int i = 0; i < channels.Count; i++)
        {
            var ch = channels[i];
            bool isLast = i == channels.Count - 1;

            var w = new MediusWriter();
            if (_config.WireFixes.MlsHeaderEcho) WriteMlsHeader(w, packet, MediusCallbackStatus.MediusSuccess);
            else w.Write((int)MediusCallbackStatus.MediusSuccess);
            w.Write((byte)(isLast ? 1 : 0));
            w.Write(ch.ChannelId);
            w.WriteString(ch.ChannelName, 64);
            w.Write(ch.PlayerCount);
            w.Write(ch.MaxPlayers);
            w.Write(ch.GenericField1);
            w.Write(ch.GenericField2);
            w.Write(ch.GenericField3);

            // Without the fix the reply goes out under the REQUEST type (0x1F).
            var reply = _config.WireFixes.MlsHeaderEcho
                ? MediusPacket.BuildLobby(MediusLobbyMessageId.ChannelList_ExtraInfoResponse, w.ToArray())
                : MediusPacket.BuildLobbyExt(MediusLobbyExtMessageId.ChannelList_ExtraInfo, w.ToArray());
            await SendMediusAsync(tcp, reply, ct);
        }
    }

    private async Task HandleJoinChannelAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        // MediusJoinChannelRequest (v108, 76 bytes): MessageID[21] | SessionKey[17] @0x15 | pad[2] |
        // MediusWorldID @0x28 (e.g. 0x44 = US EAST) | LobbyChannelPassword[32] @0x2C
        var r = new MediusReader(packet.Payload);
        r.Skip(MediusConstants.MESSAGEID_MAXLEN);
        string sessionKey = r.ReadString(MediusConstants.SESSIONKEY_MAXLEN);
        r.Skip(2);
        int    worldId    = r.ReadInt32();
        string password   = r.ReadString(MediusConstants.LOBBYPASSWORD_MAXLEN);

        var channel = _store.GetChannelById(worldId);
        var status =
            channel == null                                          ? MediusCallbackStatus.MediusChannelNotFound
            : channel.Password.Length > 0 && password != channel.Password ? MediusCallbackStatus.MediusInvalidPassword
            : channel.IsFull                                         ? MediusCallbackStatus.MediusWorldIsFull
            : MediusCallbackStatus.MediusSuccess;

        // MediusJoinChannelResponse = MessageID echo + pad + StatusCode + NetConnectionInfo. The old reply
        // (status + id, no echo) was 10 bytes on the wire — the client couldn't match or parse it and dropped.
        var w = new MediusWriter();
        WriteMlsHeader(w, packet, status);

        if (status == MediusCallbackStatus.MediusSuccess)
        {
            if (state.AccountId is int joiner)
            {
                // Hopping rooms: leave the previous one, or its roster (and IsFull) keeps counting this player.
                if (state.CurrentChannelId is int previous && previous != channel!.ChannelId)
                    _store.GetChannelById(previous)?.RemovePlayer(joiner);
                channel!.AddPlayer(joiner);
            }
            state.CurrentChannelId = channel!.ChannelId;
            state.Status           = PlayerStatus.InChatWorld;

            // Hand the client this room's lobby world. It then disconnects and reconnects to MLS with
            // TargetWorldId = the room's MediusWorldID (horizon: KeepAliveUntilNextConnection) — that
            // CLIENT_DISCONNECT right after the reply is the expected hop, not a failure.
            if (string.IsNullOrEmpty(sessionKey)) sessionKey = state.SessionKey;
            w.WriteNetConnectionInfo(
                NetConnectionType.ClientServerTCP,
                mls: (NetAddressType.External,   _config.ServerIp, _config.MlsPort),
                nat: (NetAddressType.NATService, _config.ServerIp, _config.NatPort),
                worldId: channel.ChannelId,
                serverKey: Ps2Rsa.ServerKey.GetPublicKey(),
                sessionKey: sessionKey,
                accessKey: sessionKey);
        }
        else
        {
            // Keep the reply full-size on failure so the parser never reads past the payload.
            w.WriteNetConnectionInfo(NetConnectionType.None, null, null, 0, null, string.Empty, string.Empty);
        }

        _log.LogInformation("[MLS] JoinChannel world=0x{World:X} ({Name}) -> {Status}",
            worldId, channel?.ChannelName ?? "?", status);

        // Encrypted like MAS's AccountLoginResponse — the other NetConnectionInfo-bearing reply this
        // client is proven to accept.
        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.JoinChannelResponse, w.ToArray()), state, ct);
    }

    private async Task HandleGameListAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        // Reply type must match the request, like the channel list: the client's GameList_ExtraInfo0
        // (0xEA) sender pairs it with GameList_ExtraInfoResponse0 (0xEB) — retail request-type table at
        // EE 0x004B9150 (… EA EB EC ED …). Answering 0xEA with GameListResponse (0x2A) and no MessageID
        // echo (a 7-byte reply) never completed the request, so the client retried then dropped on
        // entering a briefing room.
        var responseType = packet.MessageType == (byte)MediusLobbyMessageId.GameList_ExtraInfo0
            ? MediusLobbyMessageId.GameList_ExtraInfoResponse0
            : MediusLobbyMessageId.GameListResponse;

        // Retail listed permanent server-hosted "default rooms" in every briefing room (27 in the retail
        // dump's US EAST list), followed by player-made games. Defaults only apply inside a room.
        var room = state.WorldId is int world ? _store.GetChannelById(world) : null;
        var entries = new List<GameListEntry>();

        if (room != null)
        {
            for (int i = 0; i < _config.DefaultGames.Count; i++)
            {
                int id = (room.ChannelId << 8) | (2 + i);
                int players = _defaultGameWorlds.TryGetValue(id, out var dw) && DmeWorld.GetById(dw.WorldId) == dw
                    ? dw.ConnectedCount : 0;
                entries.Add(DefaultGameEntry(_config.DefaultGames[i], room, index: 2 + i, players));
            }
        }

        foreach (var g in _store.GetGames(state.AppId).ToList())
        {
            // A player game whose DME world emptied out (host left) is gone — drop it from the list.
            var gw = g.DmeWorldId is int wid ? DmeWorld.GetById(wid) : null;
            if ((gw == null || gw.MediusWorldId != g.GameId) && DateTime.UtcNow - g.CreatedAt > EmptyWorldGrace)
            {
                RemoveGame(g, "DME world gone");
                continue;
            }
            if (room != null && g.LobbyChannelId != 0 && g.LobbyChannelId != room.ChannelId)
                continue;
            entries.Add(PlayerGameEntry(g, room, gw?.ConnectedCount ?? g.PlayerCount));
        }

        if (_config.ApplyGameListFilters && !state.GameListFilters.IsEmpty)
        {
            var filters = state.GameListFilters.Values.ToList();
            entries = entries.Where(e => filters.All(f => f.Matches(FilterValue(e, f.Field, room)))).ToList();
        }

        if (entries.Count == 0)
        {
            // No games in the room is a normal retail state — reply with the proven empty-list body.
            var wEmpty = new MediusWriter();
            if (_config.WireFixes.EmptyGameListEndOfList) WriteEmptyGameListRow(wEmpty, packet);
            else WriteEmptyListBody(wEmpty, packet);
            await SendMediusAsync(tcp, MediusPacket.BuildLobby(responseType, wEmpty.ToArray()), ct);
            return;
        }

        _log.LogDebug("[MLS] GameList room=0x{Room:X} ({Name}) -> {Count} games",
            room?.ChannelId ?? 0, room?.ChannelName ?? "-", entries.Count);

        for (int i = 0; i < entries.Count; i++)
        {
            var w = new MediusWriter();
            WriteGameListEntry(w, packet, entries[i], isLast: i == entries.Count - 1);
            await SendMediusAsync(tcp, MediusPacket.BuildLobby(responseType, w.ToArray()), ct);
        }
    }

    /// <summary>The value a game-list filter field compares, for one row.</summary>
    internal static int FilterValue(GameListEntry e, MediusGameListFilterField field, MediusChannel? room) => field switch
    {
        MediusGameListFilterField.MEDIUS_FILTER_PLAYER_COUNT       => e.PlayerCount,
        MediusGameListFilterField.MEDIUS_FILTER_MIN_PLAYERS        => e.MinPlayers,
        MediusGameListFilterField.MEDIUS_FILTER_MAX_PLAYERS        => e.MaxPlayers,
        MediusGameListFilterField.MEDIUS_FILTER_GAME_LEVEL         => e.GameLevel,
        MediusGameListFilterField.MEDIUS_FILTER_PLAYER_SKILL_LEVEL => e.PlayerSkillLevel,
        MediusGameListFilterField.MEDIUS_FILTER_RULES_SET          => e.RulesSet,
        MediusGameListFilterField.MEDIUS_FILTER_GENERIC_FIELD_1    => e.GenericField1,
        MediusGameListFilterField.MEDIUS_FILTER_GENERIC_FIELD_2    => e.GenericField2,
        MediusGameListFilterField.MEDIUS_FILTER_GENERIC_FIELD_3    => e.GenericField3,
        MediusGameListFilterField.MEDIUS_FILTER_LOBBY_WORLDID      => room?.ChannelId ?? 0,
        _                                                          => 0,
    };

    /// <summary>One game-list row, in the order the 0xEB wire struct carries it.</summary>
    internal sealed record GameListEntry(
        int WorldId, int PlayerCount, int MinPlayers, int MaxPlayers,
        int GameLevel, int PlayerSkillLevel, int RulesSet,
        int GenericField1, int GenericField2, int GenericField3,
        int SecurityLevel, int WorldStatus, int GameHostType,
        string GameName, byte[] GameStats);

    /// <summary>
    /// A retail default room. Values are the ones every idle default carried in the retail dump:
    /// 0/2/24 players, RulesSet 1, GF1 = briefing-room id, GF2 = 24, WorldStatus 2, and
    /// GameStats = [roomId] 0B 05 00 08 00 [index] 00 [maps…].
    /// </summary>
    private static GameListEntry DefaultGameEntry(DefaultGameConfig def, MediusChannel room, int index, int playerCount)
    {
        var stats = new byte[256];
        stats[0] = (byte)room.ChannelId;
        stats[1] = 0x0B;
        stats[2] = 0x05;
        stats[4] = 0x08;
        stats[6] = (byte)index;
        for (int m = 0; m < def.Maps.Count && m < 4; m++)
            stats[8 + m] = (byte)def.Maps[m];

        return new GameListEntry(
            WorldId: (room.ChannelId << 8) | index,   // unique per room; retail ids were server-assigned
            PlayerCount: playerCount, MinPlayers: 2, MaxPlayers: DefaultGameMaxPlayers,
            GameLevel: def.Maps.Count > 0 ? def.Maps[0] : 0,
            PlayerSkillLevel: 0, RulesSet: 1,
            GenericField1: room.ChannelId, GenericField2: 24, GenericField3: 0,
            SecurityLevel: 0, WorldStatus: 2, GameHostType: 0,
            GameName: $"{def.Name}$~{room.ChannelName}",
            GameStats: stats);
    }

    /// <summary>
    /// A player-created game, from its CreateGame fields. Retail player games carried GameStats index 0x7F;
    /// the rest of the stats block is whatever the host last reported (WorldReport, once handled).
    /// </summary>
    private static GameListEntry PlayerGameEntry(MediusGame g, MediusChannel? room, int playerCount)
    {
        return new GameListEntry(
            WorldId: g.GameId, PlayerCount: playerCount, MinPlayers: g.MinPlayers, MaxPlayers: g.MaxPlayers,
            GameLevel: g.GameLevel, PlayerSkillLevel: g.PlayerSkillLevel, RulesSet: g.RulesSet,
            GenericField1: g.GenericField1 != 0 ? g.GenericField1 : room?.ChannelId ?? 0,
            GenericField2: g.GenericField2, GenericField3: g.GenericField3,
            SecurityLevel: g.IsLocked ? 1 : 0,
            WorldStatus: (int)g.Status, GameHostType: g.GameHostType,
            GameName: room != null && !g.GameName.Contains("$~") ? $"{g.GameName}$~{room.ChannelName}" : g.GameName,
            GameStats: g.GameStats);
    }

    /// <summary>
    /// GameList_ExtraInfoResponse0 (0xEB) entry — 0x190 bytes, verified against the retail dump: the
    /// client's game object (ctor EE 0x002FEBB0, copy 0x002FEC70) holds this payload at identical offsets.
    /// </summary>
    private static void WriteGameListEntry(MediusWriter w, MediusPacket packet, GameListEntry e, bool isLast)
    {
        WriteMlsHeader(w, packet, MediusCallbackStatus.MediusSuccess); // 0x00 msgId, 0x18 status
        w.Write(e.WorldId);                                          // 0x1C MediusWorldID
        w.Write((ushort)e.PlayerCount);                              // 0x20
        w.Write((ushort)e.MinPlayers);                               // 0x22
        w.Write((ushort)e.MaxPlayers);                               // 0x24
        w.WritePadding(2);                                           // 0x26
        w.Write(e.GameLevel);                                        // 0x28
        w.Write(e.PlayerSkillLevel);                                 // 0x2C
        w.Write(e.RulesSet);                                         // 0x30
        w.Write(e.GenericField1);                                    // 0x34 briefing-room id
        w.Write(e.GenericField2);                                    // 0x38
        w.Write(e.GenericField3);                                    // 0x3C
        w.Write(e.SecurityLevel);                                    // 0x40
        w.Write(e.WorldStatus);                                      // 0x44
        w.Write(e.GameHostType);                                     // 0x48
        w.WriteString(e.GameName, 64);                               // 0x4C
        w.Write(e.GameStats);                                        // 0x8C GameStats[256]
        w.Write((byte)(isLast ? 1 : 0));                             // 0x18C EndOfList
        w.WritePadding(3);                                           // 0x18D → 0x190
    }

    private async Task HandleGameListExtAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var games = _store.GetGames(state.AppId).ToList();

        if (games.Count == 0)
        {
            var wEmpty = new MediusWriter();
            if (_config.WireFixes.MlsHeaderEcho) WriteMlsHeader(wEmpty, packet, MediusCallbackStatus.MediusNoResult);
            else wEmpty.Write((int)MediusCallbackStatus.MediusNoResult);
            wEmpty.Write((byte)1);
            await SendMediusAsync(tcp, MediusPacket.BuildLobbyExt(MediusLobbyExtMessageId.GameList_ExtraInfoResponse, wEmpty.ToArray()), ct);
            return;
        }

        for (int i = 0; i < games.Count; i++)
        {
            var g = games[i];
            bool isLast = i == games.Count - 1;
            await SendGameListEntryExt(tcp, packet, g, isLast, ct);
        }
    }

    /// <summary>
    /// CreateGame1 (0xF4) / CreateGame — horizon layout: MessageID[21] | SessionKey[17] | pad2 | AppID |
    /// MinPlayers | MaxPlayers | GameLevel | GameName[64] | GamePassword[32] | SpectatorPassword[32] |
    /// PlayerSkillLevel | RulesSet | GenericField1..3 (CreateGame1) or 1..8 (CreateGame) | GameHostType |
    /// WorldAttributes. Reply = MessageID + pad + StatusCode + MediusWorldID (horizon CreateGameResponse).
    /// No retail capture of a create exists — the request is logged in full so the layout can be checked.
    /// </summary>
    private async Task HandleCreateGameAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var p = packet.Payload;
        var r = new MediusReader(p);
        r.Skip(MediusConstants.MESSAGEID_MAXLEN);
        string sessionKey = r.ReadString(MediusConstants.SESSIONKEY_MAXLEN);
        r.Skip(2);
        int appId       = r.ReadInt32();
        int minPlayers  = r.ReadInt32();
        int maxPlayers  = r.ReadInt32();
        int gameLevel   = r.ReadInt32();
        string gameName = r.ReadString(64);
        string password = r.ReadString(32);
        string spectatorPassword = r.ReadString(32);  // SpectatorPassword
        int skillLevel  = r.ReadInt32();
        int rulesSet    = r.ReadInt32();
        // CreateGame1 carries 3 generic fields, CreateGame 8; both end with GameHostType + WorldAttributes.
        int genericCount = Math.Clamp(r.Remaining / 4 - 2, 0, 8);
        var generic = new int[8];
        for (int i = 0; i < genericCount; i++) generic[i] = r.ReadInt32();
        int hostType    = r.Remaining >= 4 ? r.ReadInt32() : 0;
        int attributes  = r.Remaining >= 4 ? r.ReadInt32() : 0;

        _log.LogInformation(
            "[MLS] CreateGame type=0x{Type:X2} ({Len} B): '{Name}' app={App} players={Min}-{Max} level=0x{Level:X} " +
            "skill={Skill} rules={Rules} GF=[{GF}] host={HostType} attr=0x{Attr:X} pw={HasPw} room=0x{Room:X}",
            packet.MessageType, p.Length, gameName, appId, minPlayers, maxPlayers, gameLevel, skillLevel, rulesSet,
            string.Join(",", generic.Take(genericCount).Select(g => $"0x{g:X}")), hostType, attributes,
            password.Length > 0 ? (spectatorPassword.Length > 0 ? "game+spectator" : "game") : spectatorPassword.Length > 0 ? "spectator" : "none",
            state.WorldId ?? 0);

        // A DME world holds 1..32 players; keep the listed limits consistent with it.
        maxPlayers = Math.Clamp(maxPlayers, 1, DmeWorld.MaxClientsPerWorld);
        minPlayers = Math.Clamp(minPlayers, 0, maxPlayers);
        // Games are listed per briefing room. The community connection's world (1) is no room: list those everywhere.
        int lobbyId = state.WorldId is int lw && _store.GetChannelById(lw) != null ? lw : 0;
        int hostId  = state.AccountId ?? 0;

        bool nameTaken = _store.GetGames(state.AppId).Any(g =>
            g.LobbyChannelId == lobbyId && g.HostAccountId != hostId
            && string.Equals(BaseGameName(g.GameName), BaseGameName(gameName), StringComparison.OrdinalIgnoreCase));
        if (nameTaken)
        {
            await SendCreateGameFailureAsync(packet, state, tcp, MediusCallbackStatus.MediusGameNameExists, gameName, ct);
            return;
        }

        var game = _store.CreateGame(gameName, state.AppId, hostId, state.AccountName, maxPlayers);
        game.MinPlayers       = minPlayers;
        game.GameLevel        = gameLevel;
        game.PlayerSkillLevel = skillLevel;
        game.RulesSet         = rulesSet;
        game.Password         = password;
        game.SpectatorPassword = spectatorPassword;
        game.GenericField1    = generic[0];
        game.GenericField2    = generic[1];
        game.GenericField3    = generic[2];
        game.GenericField4    = generic[3];
        game.GameHostType     = hostType;
        game.LobbyChannelId   = lobbyId;
        game.GameStats[0]     = (byte)game.LobbyChannelId;
        game.GameStats[6]     = 0x7F;                // retail player-made games carry index 0x7F

        var world = DmeServer.TryCreateWorld(game.GameId, state.AppId, maxPlayers);
        if (world == null)
        {
            RemoveGame(game, "no free DME world id");
            await SendCreateGameFailureAsync(packet, state, tcp, MediusCallbackStatus.MediusFail, gameName, ct);
            return;
        }
        world.SelfDestructFlag = true;
        game.DmeWorldId = world.WorldId;

        var w = new MediusWriter();
        WriteMlsHeader(w, packet, MediusCallbackStatus.MediusSuccess);
        w.Write(game.GameId);                        // MediusWorldID

        _log.LogInformation("[MLS] CreateGame -> world 0x{Id:X} ({World})", game.GameId, world);
        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.CreateGameResponse, w.ToArray()), state, ct);
    }

    /// <summary>CreateGameResponse with a failure status: same size as success (MediusWorldID 0).</summary>
    private async Task SendCreateGameFailureAsync(MediusPacket packet, MediusClientState state, TcpClient tcp,
        MediusCallbackStatus status, string gameName, CancellationToken ct)
    {
        var w = new MediusWriter();
        WriteMlsHeader(w, packet, status);
        w.Write(0);
        _log.LogInformation("[MLS] CreateGame '{Name}' -> {Status}", gameName, status);
        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.CreateGameResponse, w.ToArray()), state, ct);
    }

    /// <summary>A game name without the "$~room" suffix the list adds.</summary>
    private static string BaseGameName(string name)
    {
        int cut = name.IndexOf("$~", StringComparison.Ordinal);
        return (cut >= 0 ? name[..cut] : name).Trim();
    }

    /// <summary>
    /// JoinGame (0xF3) — layout confirmed by the retail Join_Medley capture sizes (198 → 190 bytes on the wire):
    /// request = MessageID[21] | SessionKey[17] | pad2 | MediusWorldID | JoinType | GamePassword[32] |
    /// GameHostType | RSA_KEY[64] | NetAddressList[48]; reply = MessageID + pad + StatusCode + GameHostType +
    /// NetConnectionInfo (this DME server, the DME world id, and the reserved slot's access token).
    ///
    /// Spectators: the client sends the same request with JoinType = MediusJoinAsSpectator (SOCOM's join-as-spectator
    /// flag, 0x00453170, selects it) and the game's SPECTATOR password in the password field, so a spectator join is
    /// checked against <see cref="MediusGame.SpectatorPassword"/>, not the player password. CreateGame's MaxPlayers
    /// already includes the spectator seats (players + spectators; GameStats[4] = max spectators), so spectators take
    /// ordinary slots in the same DME world — the game itself tells the peers who is spectating.
    /// </summary>
    private async Task HandleJoinGameAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var r = new MediusReader(packet.Payload);
        r.Skip(MediusConstants.MESSAGEID_MAXLEN);
        string sessionKey = r.ReadString(MediusConstants.SESSIONKEY_MAXLEN);
        r.Skip(2);
        int    worldId   = r.ReadInt32();
        int    joinType  = r.ReadInt32();
        string password  = r.ReadString(32);
        int    hostType  = r.ReadInt32();
        if (string.IsNullOrEmpty(sessionKey)) sessionKey = state.SessionKey;

        var game  = _store.GetGameById(worldId);
        var world = game != null ? GetOrCreatePlayerGameWorld(game) : GetOrCreateDefaultGameWorld(worldId, state.AppId);
        var joinAs = (MediusJoinType)joinType;
        bool spectator = joinAs is MediusJoinType.MediusJoinAsSpectator or MediusJoinType.MediusJoinAsMassSpectator;

        var status =
            world == null                                                   ? MediusCallbackStatus.MediusGameNotFound
            : state.AccountId is int who && IsBannedFromGame(worldId, who)  ? MediusCallbackStatus.MediusPlayerBanned
            : game != null && !PasswordAccepted(game, spectator, password)  ? MediusCallbackStatus.MediusInvalidPassword
            : MediusCallbackStatus.MediusSuccess;

        DmeClientState? slot = null;
        if (status == MediusCallbackStatus.MediusSuccess)
        {
            slot = world!.Reserve(sessionKey, state.AccountId ?? 0, spectator);
            // The world can be swept between the lookup and the reservation; a fresh one takes the join.
            if (slot == null && world.IsDestroyed)
            {
                world = game != null ? GetOrCreatePlayerGameWorld(game) : GetOrCreateDefaultGameWorld(worldId, state.AppId);
                slot = world?.Reserve(sessionKey, state.AccountId ?? 0, spectator);
            }
            if (slot == null) status = world == null ? MediusCallbackStatus.MediusGameNotFound : MediusCallbackStatus.MediusWorldIsFull;
        }

        var w = new MediusWriter();
        WriteMlsHeader(w, packet, status);
        w.Write(game?.GameHostType ?? 0);                                   // GameHostType (retail defaults: 0)
        if (slot != null)
        {
            if (state.AccountId is int member)
            {
                // Joining another game: leave the previous one, or its player count stays inflated.
                if (state.CurrentGameId is int previous && previous != worldId)
                    _store.GetGameById(previous)?.RemovePlayer(member);
                game?.AddPlayer(member);
            }
            state.CurrentGameId = worldId;
            state.Status        = PlayerStatus.InGameWorld;
            if (state.AccountId is int joiner)
            {
                int defaultIndex = (worldId & 0xFF) - 2;
                string gameName = game?.GameName
                    ?? (defaultIndex >= 0 && defaultIndex < _config.DefaultGames.Count ? _config.DefaultGames[defaultIndex].Name : "");
                _presence.JoinedGame(joiner, worldId, gameName);
            }

            w.WriteNetConnectionInfo(
                NetConnectionType.ClientServerTCP,
                mls: (NetAddressType.External,   _config.ServerIp, _config.DmePort),
                nat: (NetAddressType.NATService, _config.ServerIp, _config.NatPort),
                worldId: world!.WorldId,
                serverKey: Ps2Rsa.ServerKey.GetPublicKey(),
                sessionKey: sessionKey,
                accessKey: slot.AccessKey);
        }
        else
        {
            w.WriteNetConnectionInfo(NetConnectionType.None, null, null, 0, null, string.Empty, string.Empty);
        }

        _log.LogInformation("[MLS] JoinGame world=0x{World:X} as {JoinType} host={Host} by {Acct} -> {Status} {Dme}",
            worldId, joinAs, hostType, state.AccountName, status, world?.ToString() ?? "-");
        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.JoinGameResponse, w.ToArray()), state, ct);
    }

    /// <summary>Players must match the game password, spectators the spectator password; an empty password = open.</summary>
    internal static bool PasswordAccepted(MediusGame game, bool spectator, string presented)
    {
        string required = spectator ? game.SpectatorPassword : game.Password;
        return string.IsNullOrEmpty(required) || presented == required;
    }

    // Default rooms are permanent in the list but only get a DME world while someone is in them
    // (DME world ids are one byte in v108, so ~300 defaults can't all hold one at once).
    private readonly System.Collections.Concurrent.ConcurrentDictionary<int, DmeWorld> _defaultGameWorlds = new();

    /// <summary>Resolve a default-room MediusWorldID ((roomId &lt;&lt; 8) | index) to its DME world.</summary>
    private DmeWorld? GetOrCreateDefaultGameWorld(int mediusWorldId, int appId)
    {
        int roomId = mediusWorldId >> 8, index = mediusWorldId & 0xFF;
        if (_store.GetChannelById(roomId) == null || index < 2 || index - 2 >= _config.DefaultGames.Count)
            return null;

        lock (_defaultGameWorlds)
        {
            if (_defaultGameWorlds.TryGetValue(mediusWorldId, out var existing) && DmeWorld.GetById(existing.WorldId) == existing)
                return existing;
            var world = DmeServer.TryCreateWorld(mediusWorldId, appId, DefaultGameMaxPlayers);
            if (world == null)
            {
                _log.LogWarning("[MLS] No free DME world id for default room 0x{Id:X}", mediusWorldId);
                return null;
            }
            world.SelfDestructFlag = true;
            _defaultGameWorlds[mediusWorldId] = world;
            _gameBans.TryRemove(mediusWorldId, out _);   // a fresh session of a default room starts with no vote-outs
            return world;
        }
    }

    private static DmeWorld? GetOrCreatePlayerGameWorld(MediusGame game)
    {
        // Two joins racing on a game whose world died must not each create one (the first joiner would be
        // left reserved in an orphan).
        lock (game)
        {
            if (game.DmeWorldId is int id && DmeWorld.GetById(id) is { } world && world.MediusWorldId == game.GameId)
                return world;
            var created = DmeServer.TryCreateWorld(game.GameId, game.AppId, game.MaxPlayers);
            if (created == null) return null;
            created.SelfDestructFlag = true;
            game.DmeWorldId = created.WorldId;
            return created;
        }
    }

    /// <summary>Retail default rooms list 2–24 players.</summary>
    private const int DefaultGameMaxPlayers = 24;

    // Old-proto (SOCOM II) Medius responses begin with the request's 21-byte messageID echo
    // + 3 pad bytes + the 4-byte status, exactly like the working MAS handlers. The MLS
    // handlers were written without this header, so SOCOM II read every reply as garbage.
    private static byte[] MlsMsgId(MediusPacket packet) =>
        packet.Payload.Length >= MediusConstants.MESSAGEID_MAXLEN
            ? packet.Payload[..MediusConstants.MESSAGEID_MAXLEN]
            : new byte[MediusConstants.MESSAGEID_MAXLEN];

    /// <summary>
    /// Old-proto MLS response header, matching the working MAS handlers:
    /// [msgId echo:21][pad:3][status:4]. The client correlates the reply to its
    /// pending request by the echoed messageID, so this prefix is mandatory.
    /// </summary>
    private static void WriteMlsHeader(MediusWriter w, MediusPacket packet, MediusCallbackStatus status)
    {
        w.Write(MlsMsgId(packet));            // 21 — messageID echo
        w.WritePadding(3);                    // 3  — alignment
        w.Write((int)status);                 // 4  — StatusCode
    }

    /// <summary>
    /// Body for an empty list reply. Status = <see cref="MediusCallbackStatus.MediusNoResult"/>
    /// (the game's own "no entries" signal — see HandleGameListAsync) so the parser does NOT
    /// read any entry fields. CRITICAL: the minimal 32-byte form let the game read a full
    /// list-entry struct off the end of our short reply, pulling STALE bytes from the previous
    /// packet (the EULA/news text) into clan/buddy NAME fields → visible "bleed" in the UI and
    /// likely garbage IDs behind the disconnect. We zero-pad past the largest entry struct so any
    /// field the parser still touches reads clean zeros instead of leftover buffer.
    /// </summary>
    /// <summary>An empty game list as one full 0x190-byte row: NoResult, zeroed fields, EndOfList at 0x18C like a real row.</summary>
    internal static void WriteEmptyGameListRow(MediusWriter w, MediusPacket packet)
    {
        WriteMlsHeader(w, packet, MediusCallbackStatus.MediusNoResult);   // 0x00 .. 0x1C
        w.WritePadding(0x18C - 0x1C);                                     // row fields, all zero
        w.Write((byte)1);                                                 // 0x18C EndOfList
        w.WritePadding(3);                                                // → 0x190
    }

    private static void WriteEmptyListBody(MediusWriter w, MediusPacket packet)
    {
        WriteMlsHeader(w, packet, MediusCallbackStatus.MediusNoResult);  // msgId + pad + status
        w.Write((byte)1);          // EndOfList
        w.WritePadding(3);         // align to 4
        w.WritePadding(256);       // zero filler — keeps stale-buffer reads clean (empty names/ids)
    }

    /// <summary>
    /// PolicyResponse (0x48) — the client requests the usage/EULA policy at the
    /// community screen. Layout mirrors the working MAS HandlePolicyAsync and the
    /// 0x4801 struct schema: header + Policy Message[POLICY_MAXLEN] + EndOfText.
    /// </summary>
    private async Task HandlePolicyAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        string policyText = _config.EulaText;

        var w = new MediusWriter();
        WriteMlsHeader(w, packet, MediusCallbackStatus.MediusSuccess);
        w.WriteString(policyText, MediusConstants.POLICY_MAXLEN);   // 256
        w.Write((byte)1);                                          // EndOfText
        w.WritePadding(3);
        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.PolicyResponse, w.ToArray()), ct);
    }

    // Watchdog RE (SCUS-97275): the ~2-min community-screen "Disconnected from Network" is a game-side
    // watchdog — the lobby PlayerInfo (0x31) poll's completion callback is cbIsGameAlive (fn 0x0030C620),
    // which shows "_1067_MEDIUS_DISCONNECTED_GAME_MSG" unless the response StatusCode (offset 0x18) == 0
    // (checked via 0x00311560 = `return status == 0 ? 1 : 0`). HOWEVER, replying to THIS login-batch
    // PlayerInfo regressed the flow (see handler note below), so the watchdog must be addressed via the
    // community-screen poll specifically, not here.
    //
    // PlayerInfo (0x31) is left UNANSWERED. Although live RE showed its completion callback is
    // cbIsGameAlive (the disconnect-modal, game fn 0x0030C620) and that StatusCode==0 satisfies it,
    // sending ANY PlayerInfoResponse during this initial login-batch — even with the correct queried
    // accountId+name (acct=2/zzzzz) and StatusCode=Success — stops the game from advancing to the
    // community-screen reconnect (the ChannelList/announcements batch never follows; it just idles on
    // CLIENT_ECHO). The known-good baseline reaches the fully-populated community screen with PlayerInfo
    // silent here, then soft-disconnects after ~2 min. Do NOT answer this one without a different,
    // RE-verified approach (the community-screen PlayerInfo poll is what the watchdog rides on, and must
    // be handled separately from this login-batch poll).
    private async Task HandlePlayerInfoAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        // Briefing-room connection: after JoinChannel the client reconnects with TargetWorldId = the room's
        // MediusWorldID and re-runs the login batch there, PlayerInfo included — but never sends ChannelList,
        // so CommunityReached stays false. Leaving that PlayerInfo silent fired cbIsGameAlive's
        // "_1067 disconnected" screen on entering the room (socket still up, game-list refresh still polling).
        bool roomConnection = IsRoomConnection(state);
        // Retail answered this on the community connection as well (create_Masquarr: 330 B). The old "stops
        // advancing" failure was with the legacy layout, which made the client read its status as Disconnected.
        bool retailLayout = roomConnection || _config.CommunityRetailReplies;

        // LOGIN-batch connection (no ChannelList seen yet): stay SILENT — answering here (legacy layout)
        // stopped the game from advancing to the community reconnect.
        if (!state.CommunityReached && !retailLayout)
        {
            _log.LogDebug("[MLS] PlayerInfo received (login batch — no reply)");
            return;
        }

        // COMMUNITY / ROOM connection: answer the poll so its cbIsGameAlive completion callback sees
        // StatusCode==0 (MediusSuccess) and does NOT fire the ~2-min "Disconnected from Network" watchdog.
        // Request layout: [msgId:21][sessionKey:17][pad:2][accountId:4]; echo the queried accountId + name.
        var r = new MediusReader(packet.Payload);
        r.Skip(MediusConstants.MESSAGEID_MAXLEN + MediusConstants.SESSIONKEY_MAXLEN + 2);
        int accountId = r.ReadInt32();
        if (accountId <= 0) accountId = state.AccountId ?? 0;
        var account = _store.GetAccountById(accountId);
        string name = account?.AccountName ?? state.AccountName ?? string.Empty;

        var w = new MediusWriter();
        WriteMlsHeader(w, packet, MediusCallbackStatus.MediusSuccess);          // msgId echo + pad + StatusCode=0 @0x18
        if (retailLayout)
        {
            // Retail layout (horizon MediusPlayerInfoResponse): 328-byte payload = the 330-byte reply in both
            // retail room-join captures (Join_US_East, create_Masquarr). The legacy layout below put an
            // AccountID before the name, so the client read PlayerStatus from zeroed stats = 0 (Disconnected).
            w.WriteString(name, MediusConstants.ACCOUNTNAME_MAXLEN);            // 0x1C AccountName[32]
            w.Write(state.AppId);                                               // 0x3C ApplicationID
            w.Write((int)(_presence.Get(accountId)?.Status ?? MediusPlayerStatus.MediusPlayerInChatWorld)); // 0x40 PlayerStatus
            w.Write((int)MediusConnectionType.Ethernet);                       // 0x44 ConnectionClass
            w.Write(Fixed(account?.AccountStats, MediusConstants.ACCOUNTSTATS_MAXLEN)); // 0x48 Stats[256]
        }
        else
        {
            // Community poll — hardware-stable legacy layout, kept until the retail layout is tested there.
            w.Write(accountId);                                                 // AccountID (echo queried id)
            w.WriteString(name, MediusConstants.ACCOUNTNAME_MAXLEN);            // 32
            w.WritePadding(MediusConstants.ACCOUNTSTATS_MAXLEN);                // 256 — Stats
            w.Write((int)MediusPlayerStatus.MediusPlayerInChatWorld);          // PlayerStatus
            w.Write((int)MediusConnectionType.Ethernet);                       // ConnectionClass
            w.WritePadding(32);                                                 // zero filler
        }

        _log.LogDebug("[MLS] -> PlayerInfoResponse ({Where} poll) acct={Id}/{Name}",
            roomConnection ? $"room 0x{state.WorldId:X}" : "community", accountId, name);
        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.PlayerInfoResponse, w.ToArray()), ct);
    }

    private async Task HandleSetGameListFilterAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        if (GameListFilter.Parse(packet.Payload) is { } filter)
        {
            state.GameListFilters[(int)filter.Field] = filter;
            _log.LogInformation("[MLS] SetGameListFilter0 {Field} & 0x{Mask:X} {Op} {Baseline} (world 0x{World:X}){Applied}",
                filter.Field, filter.Mask, filter.Op, filter.BaselineValue, state.WorldId ?? 0,
                _config.ApplyGameListFilters ? "" : " — recorded, not applied (ApplyGameListFilters off)");
        }

        // Briefing-room connection: retail DOES answer. Hash-verified against the Join_US_East and
        // create_Masquarr captures: the constant 30-byte reply (hash fb182a2e) is exactly
        // 01 4F + MessageID(21 zero) + pad(90 FF BF, uninitialised server stack) + StatusCode 0 — the v108
        // header-only SetGameListFilterResponse0 (FilterID only exists for v>108). create_Masquarr shows retail
        // sent the same reply on the community connection (CommunityRetailReplies).
        if (IsRoomConnection(state) || _config.CommunityRetailReplies)
        {
            var w = new MediusWriter();
            WriteMlsHeader(w, packet, MediusCallbackStatus.MediusSuccess);
            _log.LogDebug("[MLS] -> SetGameListFilterResponse0 (world 0x{World:X})", state.WorldId);
            await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.SetGameListFilterResponse0, w.ToArray()), ct);
            return;
        }

        // Community/login connection: MUST stay a NO-OP for SOCOM II (v108). On-hardware 2026-06-22: sending the Horizon-style
        // SetGameListFilterResponse0 ack REGRESSED it — the client ran the whole community batch then
        // disconnected BEFORE its first CLIENT_ECHO (never reached the ~60-90s hold). Confirms the old
        // archaeology note that crafted SetGameListFilter replies make SOCOM II disconnect. Horizon acks it,
        // but Horizon targets newer Medius; v108 wants it silent. Do NOT re-add a reply here.
        _log.LogDebug("[MLS] SetGameListFilter0 received (no reply — required for v108)");
    }

    // Both stats updates are request/response. The client sends them on the briefing-room connection right
    // after PlayerInfo is answered; each unanswered one raised its own "Disconnected" screen (two on entering
    // a room). Both are persisted on the account (AccountStats → PlayerInfo/ladder rows, LadderStats → ranking).

    /// <summary>
    /// AccountUpdateStatsResponse (0x12) = MessageID + pad + StatusCode. Hash-verified against the retail
    /// create_Masquarr capture: the 30-byte reply is exactly 01 12 + 28 zero bytes (Success).
    /// Request body (294 B, v108 — no pad): MessageID[21] | SessionKey[17] | Stats[256].
    /// </summary>
    private async Task HandleAccountUpdateStatsAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        const int statsOffset = MediusConstants.MESSAGEID_MAXLEN + MediusConstants.SESSIONKEY_MAXLEN;
        var account = state.AccountId is int acct ? _store.GetAccountById(acct) : null;
        if (account != null && packet.Payload.Length >= statsOffset + MediusConstants.ACCOUNTSTATS_MAXLEN)
        {
            account.AccountStats = packet.Payload.AsSpan(statsOffset, MediusConstants.ACCOUNTSTATS_MAXLEN).ToArray();
            _store.MarkDirty();
        }

        var w = new MediusWriter();
        WriteMlsHeader(w, packet, MediusCallbackStatus.MediusSuccess);
        _log.LogDebug("[MLS] -> AccountUpdateStatsResponse (ack)");
        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.AccountUpdateStatsResponse, w.ToArray()), ct);
    }

    /// <summary>
    /// UpdateLadderStatsResponse (0xCF) = MessageID + pad + StatusCode only: retail's reply is 30 bytes on the
    /// wire in both room-join captures (our old reply added 32 filler bytes → 62). Its exact bytes aren't
    /// hash-recoverable (status isn't 0/±1 and the pad is server garbage), so we answer Success.
    /// Request body (88 B): MessageID[21] | pad3 | LadderType (0 player, 1 clan) | Stats: 15 × int32
    /// (SOCOM II: index 0 = rating, 1000 for a new player). Persisted — the ladder ranks on these.
    /// </summary>
    private async Task HandleUpdateLadderStatsAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        const int typeAt = MediusConstants.MESSAGEID_MAXLEN + 3, statsAt = typeAt + 4;
        var p = packet.Payload;
        var account = state.AccountId is int acct ? _store.GetAccountById(acct) : null;
        if (account != null && p.Length >= statsAt + 4)
        {
            int ladderType = BitConverter.ToInt32(p, typeAt);
            var stats = new int[(p.Length - statsAt) / 4];
            for (int i = 0; i < stats.Length; i++) stats[i] = BitConverter.ToInt32(p, statsAt + i * 4);

            if (ladderType == (int)MediusLadderType.MediusLadderTypeClan)
            {
                if (_store.GetClanById(account.ClanId) is { } clan && clan.LeaderAccountId == account.AccountId)
                    clan.LadderStats = stats;
            }
            else
            {
                account.LadderStats = stats;
            }
            _store.MarkDirty();
        }

        var w = new MediusWriter();
        WriteMlsHeader(w, packet, MediusCallbackStatus.MediusSuccess);
        _log.LogDebug("[MLS] -> UpdateLadderStatsResponse (ack)");
        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.UpdateLadderStatsResponse, w.ToArray()), ct);
    }

    /// <summary>
    /// FileListFiles (0xB2) — the game asks for its saved weapon profile ("WeapProfile_N.dat") in the login
    /// batch. Request (176 B): Filename[128] | 6×u32 filters | MessageID[21] @152 | pad3.
    /// Reply FileListFilesResponse (0xB3) = MediusFile[172] | StatusCode @0xAC | MessageID[21] @0xB0 |
    /// EndOfList @0xC5 | pad2 = 200 B (202 on the wire, the size retail sent on the community connection).
    /// Layout RE'd from the client's handler at EE 0x003225D0 (status @0xAC checked by 0x00311560, MessageID
    /// @0xB0 looked up in the pending-request map 0x00453440, EOL @0xC5). A non-zero status opens the
    /// MP_MEDIUS_FILE_DOES_NOT_EXIST modal via 0x0027F920, and left UNANSWERED the request times out ~15-18 s
    /// later — if the player is already on the community screen by then, that is the intermittent "news"
    /// disconnect. So: Success + an empty entry + EndOfList = "no server-side profile".
    /// </summary>
    private async Task HandleFileListFilesAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        const int msgIdAt = 152;
        var p = packet.Payload;
        byte[] msgId = p.Length >= msgIdAt + MediusConstants.MESSAGEID_MAXLEN
            ? p[msgIdAt..(msgIdAt + MediusConstants.MESSAGEID_MAXLEN)]
            : ExtractTrailingMessageId(p);

        var w = new MediusWriter();
        WriteEmptyMediusFile(w);                                   // 0x00 MediusFile[172] (no file)
        w.Write((int)MediusCallbackStatus.MediusSuccess);          // 0xAC StatusCode
        w.Write(msgId);                                            // 0xB0 MessageID[21]
        w.Write((byte)1);                                          // 0xC5 EndOfList
        w.WritePadding(2);                                         // → 0xC8 = 200

        _log.LogInformation("[MLS] FileListFiles '{File}' -> empty list (msgId={MsgId})",
            ReadLeadingString(p), System.Text.Encoding.ASCII.GetString(msgId).TrimEnd('\0'));
        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.FileListFilesResponse, w.ToArray()), state, ct);
    }

    /// <summary>
    /// Write a zeroed 172-byte Medius <c>MediusFile</c> struct (Filename[128] + ServerChecksum[16]
    /// + FileID/FileSize/CreationTimeStamp/OwnerID/GroupID (5×u32) + 4×u16 permission/op fields),
    /// little-endian, matching Horizon's RT.Models/Misc/MediusFile.cs serializer.
    /// </summary>
    private static void WriteEmptyMediusFile(MediusWriter w)
    {
        w.WriteString("", 128);   // Filename[MEDIUS_FILE_MAX_FILENAME_LENGTH]
        w.WritePadding(16);       // ServerChecksum[MEDIUS_FILE_CHECKSUM_NUMBYTES]
        w.Write(0);               // FileID
        w.Write(0);               // FileSize
        w.Write(0);               // CreationTimeStamp
        w.Write(0);               // OwnerID
        w.Write(0);               // GroupID
        w.Write((ushort)0);       // OwnerPermissionRWX
        w.Write((ushort)0);       // GroupPermissionRWX
        w.Write((ushort)0);       // GlobalPermissionRWX
        w.Write((ushort)0);       // ServerOperationID
    }

    /// <summary>Read the leading NUL-terminated ASCII string of a payload (the FileListFiles filename).</summary>
    private static string ReadLeadingString(byte[] payload)
    {
        int n = 0;
        while (n < payload.Length && payload[n] != 0) n++;
        return System.Text.Encoding.ASCII.GetString(payload, 0, n);
    }

    /// <summary>
    /// Extract the last NUL-terminated ASCII string in a payload as a 21-byte (MESSAGEID_MAXLEN)
    /// field. FileListFiles puts its messageID ("&lt;sessionKey&gt;.0") at the END of the request,
    /// after the filename and a block of (largely uninitialized) fields, so the normal front-of-
    /// payload MlsMsgId() does not apply.
    /// </summary>
    private static byte[] ExtractTrailingMessageId(byte[] payload)
    {
        var id = new byte[MediusConstants.MESSAGEID_MAXLEN];
        int end = payload.Length;
        while (end > 0 && payload[end - 1] == 0) end--;        // skip trailing NULs
        if (end == 0) return id;
        int start = end;
        while (start > 0 && payload[start - 1] != 0) start--;  // back to start of last string
        int len = Math.Min(end - start, MediusConstants.MESSAGEID_MAXLEN);
        Buffer.BlockCopy(payload, start, id, 0, len);
        return id;
    }

    /// <summary>
    /// TextFilter (0x98) — the client vets typed text (e.g. a new game's name) before using it. Request (110 B,
    /// hardware) = MessageID[21] | SessionKey[17] | pad2 | TextFilterType | Text[64]. Reply TextFilterResponse
    /// (0x99, horizon) = MessageID[21] | Text[64] | pad3 | StatusCode = 94 B on the wire — the same size as the
    /// retail create_Masquarr "110 → 94" exchange. No word filter: every text passes and is echoed back.
    /// </summary>
    private async Task HandleTextFilterAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var r = new MediusReader(packet.Payload);
        r.Skip(MediusConstants.MESSAGEID_MAXLEN + MediusConstants.SESSIONKEY_MAXLEN + 2);
        int    filterType = r.ReadInt32();
        string text       = r.ReadString(64);

        var w = new MediusWriter();
        w.Write(MlsMsgId(packet));                                   // MessageID[21]
        w.WriteString(text, 64);                                     // Text[64]
        w.WritePadding(3);
        w.Write((int)MediusCallbackStatus.MediusSuccess);

        _log.LogInformation("[MLS] TextFilter type={Type} '{Text}' -> pass", filterType, text);
        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.TextFilterResponse, w.ToArray()), state, ct);
    }

    /// <summary>The host's latest WorldReport0 for a game world (default rooms included).</summary>
    private sealed record WorldReport(
        int PlayerCount, string GameName, byte[] GameStats, int MinPlayers, int MaxPlayers, int GameLevel,
        int PlayerSkillLevel, int RulesSet, int GenericField1, int GenericField2, int GenericField3, int WorldStatus);

    private readonly System.Collections.Concurrent.ConcurrentDictionary<int, WorldReport> _worldReports = new();

    /// <summary>
    /// WorldReport0 (0x00) — the game HOST reports its world every ~7 s; one-way. Horizon layout, confirmed on
    /// hardware (386 B): SessionKey[17] | pad3 | MediusWorldID | PlayerCount | GameName[64] | GameStats[256] |
    /// Min | Max | GameLevel | Skill | RulesSet | GF1 | GF2 | GF3 | WorldStatus. The first player into a default
    /// room becomes its host and reports it (GF2 = host value, status 1 = staging).
    /// </summary>
    private void HandleWorldReport0(MediusPacket packet, MediusClientState state)
    {
        var r = new MediusReader(packet.Payload);
        r.Skip(MediusConstants.SESSIONKEY_MAXLEN + 3);
        int worldId = r.ReadInt32();
        var report = new WorldReport(
            PlayerCount: r.ReadInt32(), GameName: r.ReadString(64), GameStats: r.ReadBytes(256),
            MinPlayers: r.ReadInt32(), MaxPlayers: r.ReadInt32(), GameLevel: r.ReadInt32(),
            PlayerSkillLevel: r.ReadInt32(), RulesSet: r.ReadInt32(), GenericField1: r.ReadInt32(),
            GenericField2: r.ReadInt32(), GenericField3: r.ReadInt32(), WorldStatus: r.ReadInt32());

        // Only a player in that game world (or the game's host) may describe it; anyone else could rename or
        // close other people's games.
        var reportedGame = _store.GetGameById(worldId);
        if (state.AccountId is not int reporter
            || (reportedGame?.HostAccountId != reporter
                && !DmeWorld.All.Any(w => w.MediusWorldId == worldId && w.Clients.Values.Any(c => c.AccountId == reporter))))
        {
            _log.LogDebug("[MLS] WorldReport0 for world 0x{World:X} from {Acct} ignored: not in that game", worldId, state.AccountName);
            return;
        }

        bool first = !_worldReports.ContainsKey(worldId);
        _worldReports[worldId] = report;

        if (reportedGame is { } game)
        {
            game.GameName         = report.GameName;
            game.GameStats        = report.GameStats;
            game.MinPlayers       = report.MinPlayers;
            // The DME world's slot count is fixed at creation; never list more seats than it has.
            int seats = game.DmeWorldId is int dw && DmeWorld.GetById(dw) is { } gw ? gw.MaxPlayers : DmeWorld.MaxClientsPerWorld;
            game.MaxPlayers       = Math.Clamp(report.MaxPlayers, 1, seats);
            game.GameLevel        = report.GameLevel;
            game.PlayerSkillLevel = report.PlayerSkillLevel;
            game.RulesSet         = report.RulesSet;
            game.GenericField1    = report.GenericField1;
            game.GenericField2    = report.GenericField2;
            game.GenericField3    = report.GenericField3;
            game.Status           = (GameWorldStatus)report.WorldStatus;
        }

        if (first)
            _log.LogInformation("[MLS] WorldReport0 world=0x{World:X} '{Name}' players={Count} status={Status} GF2=0x{GF2:X} from {Acct}",
                worldId, report.GameName, report.PlayerCount, report.WorldStatus, report.GenericField2, state.AccountName);
    }

    /// <summary>
    /// EndGameReport (126 B, one-way): SessionKey[17] | pad3 | MediusWorldID | WinningTeam[64] | WinningPlayer[32] |
    /// FinalScore (horizon MediusEndGameReport). Accepted from a player in that game, like WorldReport0; the result is
    /// kept on the game (shown by the debug /rooms report) and the game is marked closed. The world itself is cleaned
    /// up by the sweep once its players leave.
    /// </summary>
    private void HandleEndGameReport(MediusPacket packet, MediusClientState state)
    {
        var r = new MediusReader(packet.Payload);
        if (r.Remaining < MediusConstants.SESSIONKEY_MAXLEN + 3 + 4) return;
        r.Skip(MediusConstants.SESSIONKEY_MAXLEN + 3);
        int worldId = r.ReadInt32();
        string team   = r.Remaining >= 64 ? r.ReadString(64) : "";
        string player = r.Remaining >= MediusConstants.ACCOUNTNAME_MAXLEN ? r.ReadString(MediusConstants.ACCOUNTNAME_MAXLEN) : "";
        int score     = r.Remaining >= 4 ? r.ReadInt32() : 0;

        var game = _store.GetGameById(worldId);
        bool inGame = state.AccountId is int reporter
            && (game?.HostAccountId == reporter
                || DmeWorld.All.Any(w => w.MediusWorldId == worldId && w.Clients.Values.Any(c => c.AccountId == reporter)));
        if (!inGame)
        {
            _log.LogDebug("[MLS] EndGameReport for world 0x{World:X} from {Acct} ignored: not in that game", worldId, state.AccountName);
            return;
        }

        if (game != null)
        {
            game.Result = new GameResult(team, player, score, DateTime.UtcNow);
            game.Status = GameWorldStatus.WorldClosed;
        }
        _log.LogInformation("[MLS] Game 0x{World:X} '{Name}' ended: team '{Team}', player '{Player}', score {Score} (reported by {Acct})",
            worldId, game?.GameName ?? "default room", team, player, score, state.AccountName);
    }

    /// <summary>
    /// UpdateUserState (one-way): SessionKey[17] | pad3 | UserAction @20 (horizon MediusUpdateUserState).
    /// LeftGameWorld puts the player back in the lobby (presence, the game's roster); JoinedChatWorld marks them in
    /// the chat world; KeepAlive is just that.
    /// </summary>
    private void HandleUpdateUserState(MediusPacket packet, MediusClientState state)
    {
        const int actionAt = MediusConstants.SESSIONKEY_MAXLEN + 3;
        if (packet.Payload.Length < actionAt + 4 || state.AccountId is not int account) return;
        var action = (MediusUserAction)BitConverter.ToInt32(packet.Payload, actionAt);

        switch (action)
        {
            case MediusUserAction.LeftGameWorld:
                if (state.CurrentGameId is int gameId) _store.GetGameById(gameId)?.RemovePlayer(account);
                state.CurrentGameId = null;
                state.Status        = PlayerStatus.InChatWorld;
                _presence.LeftGame(account);
                _log.LogDebug("[MLS] {Acct} left their game world", state.AccountName);
                break;
            case MediusUserAction.JoinedChatWorld:
                state.Status = PlayerStatus.InChatWorld;
                break;
        }
    }

    /// <summary>
    /// GetWorldSecurityLevel (MLS): MessageID[21] | SessionKey[17] | pad2 | MediusWorldID @0x28 | AppType @0x2C →
    /// header | SecurityLevel (the MAS layout). A room or game with a password reports PLAYER_PASSWORD, else NONE.
    /// </summary>
    private async Task HandleGetWorldSecurityLevelAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        const int worldAt = MediusConstants.MESSAGEID_MAXLEN + MediusConstants.SESSIONKEY_MAXLEN + 2;
        int worldId = packet.Payload.Length >= worldAt + 4 ? BitConverter.ToInt32(packet.Payload, worldAt) : 0;
        bool locked = _store.GetChannelById(worldId) is { } room ? room.Password.Length > 0
                    : _store.GetGameById(worldId) is { } game && game.IsLocked;

        var w = new MediusWriter();
        WriteMlsHeader(w, packet, MediusCallbackStatus.MediusSuccess);
        w.Write((int)(locked ? MediusWorldSecurityLevelType.WORLD_SECURITY_PLAYER_PASSWORD : MediusWorldSecurityLevelType.WORLD_SECURITY_NONE));
        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.GetWorldSecurityLevelResponse, w.ToArray()), state, ct);
    }

    /// <summary>GetMyIP (MLS): MessageID | SessionKey → header | IP[20] (the MAS layout), the address this connection comes from.</summary>
    private async Task HandleGetMyIpAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var ip = (tcp.Client.RemoteEndPoint as System.Net.IPEndPoint)?.Address.MapToIPv4().ToString() ?? "";
        var w = new MediusWriter();
        WriteMlsHeader(w, packet, MediusCallbackStatus.MediusSuccess);
        w.WriteString(ip, MediusConstants.IP_MAXLEN);
        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.GetMyIPResponse, w.ToArray()), state, ct);
    }

    /// <summary>Latest host report for a world, only while its DME world is still alive.</summary>
    private WorldReport? LiveReport(int mediusWorldId)
    {
        if (!_worldReports.TryGetValue(mediusWorldId, out var report)) return null;
        bool alive = DmeWorld.All.Any(w => w.MediusWorldId == mediusWorldId);
        if (!alive) _worldReports.TryRemove(mediusWorldId, out _);
        return alive ? report : null;
    }

    /// <summary>
    /// GameInfo0 (0x33, 46 B) = MessageID[21] | SessionKey[17] | pad2 | MediusWorldID. Reply GameInfoResponse0
    /// (0x34, horizon layout, 398 B on the wire): header | AppID | Min | Max | GameLevel | Skill | PlayerCount |
    /// GameStats[256] | GameName[64] | RulesSet | GF1 | GF2 | GF3 | WorldStatus | GameHostType.
    /// The old 6-byte reply (no MessageID echo) dropped the host right as the game lobby loaded.
    /// </summary>
    private async Task HandleGameInfoAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var r = new MediusReader(packet.Payload);
        r.Skip(MediusConstants.MESSAGEID_MAXLEN + MediusConstants.SESSIONKEY_MAXLEN + 2);
        int worldId = r.ReadInt32();

        // Prefer the host's own report; fall back to the listed entry (default room or player game).
        var room  = _store.GetChannelById(worldId >> 8);
        var game  = _store.GetGameById(worldId);
        int index = worldId & 0xFF;
        GameListEntry? listed =
            game != null ? PlayerGameEntry(game, _store.GetChannelById(game.LobbyChannelId), game.PlayerCount)
            : room != null && index >= 2 && index - 2 < _config.DefaultGames.Count
                ? DefaultGameEntry(_config.DefaultGames[index - 2], room, index, 0)
                : null;
        var report  = LiveReport(worldId);
        int players = DmeWorld.All.FirstOrDefault(w => w.MediusWorldId == worldId)?.ConnectedCount ?? 0;

        var w = new MediusWriter();
        if (listed == null && report == null)
        {
            WriteMlsHeader(w, packet, MediusCallbackStatus.MediusGameNotFound);
            w.WritePadding(4 * 6 + 256 + 64 + 4 * 6);
        }
        else
        {
            WriteMlsHeader(w, packet, MediusCallbackStatus.MediusSuccess);
            w.Write(state.AppId);                                                 // ApplicationID
            w.Write(report?.MinPlayers ?? listed!.MinPlayers);
            w.Write(report?.MaxPlayers ?? listed!.MaxPlayers);
            w.Write(report?.GameLevel ?? listed!.GameLevel);
            w.Write(report?.PlayerSkillLevel ?? listed!.PlayerSkillLevel);
            w.Write(Math.Max(players, report?.PlayerCount ?? 0));                 // PlayerCount
            w.Write(report?.GameStats ?? listed!.GameStats);                      // GameStats[256]
            w.WriteString(report?.GameName ?? listed!.GameName, 64);              // GameName[64]
            w.Write(report?.RulesSet ?? listed!.RulesSet);
            w.Write(report?.GenericField1 ?? listed!.GenericField1);
            w.Write(report?.GenericField2 ?? listed!.GenericField2);
            w.Write(report?.GenericField3 ?? listed!.GenericField3);
            w.Write(report?.WorldStatus ?? listed!.WorldStatus);
            w.Write(game?.GameHostType ?? 0);                                     // GameHostType
        }

        _log.LogInformation("[MLS] GameInfo0 world=0x{World:X} -> {Result} (players={Players}, from {Src})",
            worldId, listed == null && report == null ? "not found" : "ok", players,
            report != null ? "host report" : "list entry");
        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.GameInfoResponse0, w.ToArray()), state, ct);
    }

    private async Task HandleGetLocationsAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var w = new MediusWriter();
        if (_config.WireFixes.MlsHeaderEcho)
        {
            // header | LocationID | LocationName[64] | EndOfList | pad3
            WriteMlsHeader(w, packet, MediusCallbackStatus.MediusSuccess);
            w.Write(0);
            w.WriteString(_config.UniverseName, 64);
            w.Write((byte)1);
            w.WritePadding(3);
        }
        else
        {
            w.Write((int)MediusCallbackStatus.MediusSuccess);
            w.Write((byte)1);   // EndOfList
            w.Write(0);         // LocationId
            w.WriteString("Default", 64);
        }

        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.GetLocationsResponse, w.ToArray()), ct);
    }

    private async Task HandlePickLocationAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var w = new MediusWriter();
        if (_config.WireFixes.MlsHeaderEcho) WriteMlsHeader(w, packet, MediusCallbackStatus.MediusSuccess);
        else w.Write((int)MediusCallbackStatus.MediusSuccess);

        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.PickLocationResponse, w.ToArray()), ct);
    }

    /// <summary>Retail MLS version string — hash-verified against the 2012 room-join captures.</summary>
    private const string RetailLobbyServerVersion = "Medius Lobby Server Version 1.52.0019";

    private async Task HandleVersionServerAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        // Briefing-room connection: retail DOES answer. Hash-verified (Join_US_East + create_Masquarr, constant
        // hash f1037739): the 79-byte reply is exactly 01 87 + MessageID[21] + VersionServer[56] — no pad, no
        // StatusCode. Left unanswered, the pending request raised the transition-screen disconnect. The same
        // reply also went out on the retail community connection (create_Masquarr) — CommunityRetailReplies.
        if (IsRoomConnection(state) || _config.CommunityRetailReplies)
        {
            var w = new MediusWriter();
            w.Write(MlsMsgId(packet));                                          // MessageID[21]
            w.WriteString(RetailLobbyServerVersion, MediusConstants.MEDIUS_VERSION_MAXLEN);
            _log.LogDebug("[MLS] -> VersionServerResponse (world 0x{World:X})", state.WorldId);
            await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.VersionServerResponse, w.ToArray()), ct);
            return;
        }

        // Community/login connection: VersionServer (0x86) is a one-way notification from the PS2 client —
        // the client advances its own state machine immediately without expecting a reply.
        // The real server does NOT send VersionServerResponse here on MLS. Replying to it
        // desyncs the lobby exchange and was the regression that broke the EULA/online screen.
        _log.LogInformation("[MLS] VersionServer received (one-way notification, no reply sent)");
    }

    private async Task HandleUtilGetServerVersionAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var w = new MediusWriter();
        if (_config.WireFixes.MlsHeaderEcho) WriteMlsHeader(w, packet, MediusCallbackStatus.MediusSuccess);
        else w.Write((int)MediusCallbackStatus.MediusSuccess);
        w.WriteString(_config.WireFixes.MlsHeaderEcho ? RetailLobbyServerVersion : "CodeDesigner MLS 1.0", 64);

        await SendMediusAsync(tcp, MediusPacket.BuildLobbyExt(MediusLobbyExtMessageId.UtilGetServerVersionResponse, w.ToArray()), ct);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private async Task SendGameListEntryExt(TcpClient tcp, MediusPacket packet, MediusGame g, bool isLast, CancellationToken ct)
    {
        var w = new MediusWriter();
        if (_config.WireFixes.MlsHeaderEcho) WriteMlsHeader(w, packet, MediusCallbackStatus.MediusSuccess);
        else w.Write((int)MediusCallbackStatus.MediusSuccess);
        w.Write((byte)(isLast ? 1 : 0));
        w.Write(g.GameId);
        w.WriteString(g.GameName, 64);
        w.Write(g.PlayerCount);
        w.Write(g.MaxPlayers);
        w.Write((int)g.Status);
        w.Write(g.GenericField1);
        w.Write(g.GenericField2);
        w.Write(g.GenericField3);
        w.Write(g.GenericField4);

        await SendMediusAsync(tcp, MediusPacket.BuildLobbyExt(MediusLobbyExtMessageId.GameList_ExtraInfoResponse, w.ToArray()), ct);
    }
}
