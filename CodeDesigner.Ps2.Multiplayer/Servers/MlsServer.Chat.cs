using System.Net.Sockets;
using CodeDesigner.Ps2.Multiplayer.Models;
using CodeDesigner.Ps2.Multiplayer.Protocol;
using Microsoft.Extensions.Logging;

namespace CodeDesigner.Ps2.Multiplayer.Servers;

/// <summary>
/// Chat and "who's here" queries: lobby chat / whispers / clan + buddy chat, briefing-room and game player
/// lists, channel info and total rankings. Horizon layouts; the ChatMessage request size is confirmed on
/// hardware (112 B — SOCOM also uses whispers for clan-invite notifications).
///
/// The briefing-room player list is GetLobbyPlayerNames_ExtraInfo (0xDC → 0xDD), verified against the r0004
/// client: its RefreshRoomPlayerList native (EE 0x0027EA80 → 0x0030E380) sends 0x1C bytes (MessageID | pad3 |
/// MediusWorldID = the room, global 0x00669EB8) at most once per 10 s and only while no request is in flight
/// (flag 0x00452DB8). Its callback (0x0030E530) parses each 0xDD row as AccountID @0x1C | Name[32] @0x20 |
/// OnlineState @0x40 (ConnectStatus, LobbyWorldID, GameWorldID, LobbyName[64] @0x4C, GameName[64] @0x8C) |
/// EndOfList @0xCC — exactly the 208-byte row written here. Before sending it zeroes every known player's
/// ConnectStatus, merges the rows by AccountID, and on EndOfList erases the players still at 0, so the reply
/// must list EVERY player in the room with a non-zero status (2 In Lobby / 3 In Game) and end with EndOfList.
/// The GameWorldPlayerList (0x2F → 0x30) callback (0x00314040) reads Stats @0x40 and EndOfList @0x144 — the
/// 328-byte row below. Rows are polled every few seconds, so they log at Debug.
/// </summary>
public partial class MlsServer
{
    private const int ChatLen = 64;   // CHATMESSAGE_MAXLEN

    private async Task<bool> TryHandleChatAndListsAsync(MediusLobbyMessageId type, MediusPacket packet,
        MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        switch (type)
        {
            case MediusLobbyMessageId.ChatMessage:                  await HandleChatAsync(packet, state, ct); return true;
            case MediusLobbyMessageId.ChatToggle:                   await SendStatusAsync(packet, state, tcp, MediusLobbyMessageId.ChatToggleResponse, MediusCallbackStatus.MediusSuccess, ct); return true;
            case MediusLobbyMessageId.LobbyWorldPlayerList:         await HandleLobbyWorldPlayerListAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.GetLobbyPlayerNames:          await HandleGetLobbyPlayerNamesAsync(packet, state, tcp, extraInfo: false, ct); return true;
            case MediusLobbyMessageId.GetLobbyPlayerNames_ExtraInfo: await HandleGetLobbyPlayerNamesAsync(packet, state, tcp, extraInfo: true, ct); return true;
            case MediusLobbyMessageId.GameWorldPlayerList:          await HandleGameWorldPlayerListAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.ChannelInfo:                  await HandleChannelInfoAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.GetTotalRankings:             await HandleGetTotalRankingsAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.BanPlayer:                    await HandleBanPlayerAsync(packet, state, tcp, ct); return true;
            default: return false;
        }
    }

    // =========================================================================
    // Game bans (vote-outs)
    // =========================================================================

    /// <summary>Game-room bans: MediusWorldID → (account → ban expiry). Runtime-only.</summary>
    private readonly System.Collections.Concurrent.ConcurrentDictionary<int, System.Collections.Concurrent.ConcurrentDictionary<int, DateTime>> _gameBans = new();

    private bool IsBannedFromGame(int gameWorldId, int accountId) =>
        _gameBans.TryGetValue(gameWorldId, out var bans) && bans.TryGetValue(accountId, out var until) && until > DateTime.UtcNow;

    /// <summary>
    /// BanPlayer (0x8A) — a vote-out: SOCOM's "BanSelfFromGame" has the voted-out console ban itself from the game
    /// room. Layout RE'd from the retail client (sender EE 0x00316900 → library 0x003FC160, which sends type
    /// [0x004B90B4] = 0x8A with a 0x38-byte body; reply callback 0x00316990 checks the status @0x18):
    ///   MessageID[21] | SessionKey[17] | pad2 | AccountID @40 | 120 @44 (ban length, minutes) |
    ///   game MediusWorldID @48 (the client global 0x00669F70, -1 when not in a game) | 0 @52.
    /// Reply BanPlayerResponse (0x8B) = header only. The ban makes JoinGame for that room answer MediusPlayerBanned
    /// (the client's MP_BANNED_FROM_GAME dialog) until it expires or the room's session ends.
    /// </summary>
    private Task HandleBanPlayerAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var p = packet.Payload;
        int accountId = Int(p, SessionBody), minutes = Int(p, SessionBody + 4), worldId = Int(p, SessionBody + 8);
        if (worldId <= 0) worldId = state.CurrentGameId ?? 0;
        if (minutes <= 0) minutes = 120;
        minutes = Math.Min(minutes, 60 * 24 * 365);   // AddMinutes(int.MaxValue) would throw

        // The voted-out console bans itself; otherwise only the game's host may ban someone from it.
        bool allowed = state.AccountId is int sender
                       && (sender == accountId || _store.GetGameById(worldId)?.HostAccountId == sender);
        var status = accountId <= 0 || worldId <= 0 ? MediusCallbackStatus.MediusInvalidRequestMsg
                   : !allowed                       ? MediusCallbackStatus.MediusFail
                   : MediusCallbackStatus.MediusSuccess;
        if (status == MediusCallbackStatus.MediusSuccess)
            _gameBans.GetOrAdd(worldId, _ => new())[accountId] = DateTime.UtcNow.AddMinutes(minutes);

        _log.LogInformation("[MLS] BanPlayer {Target} ({Acct}) from game room 0x{World:X} for {Min} min (sent by {Me}) -> {Status}",
            _store.GetAccountById(accountId)?.AccountName ?? "?", accountId, worldId, minutes, state.AccountName, status);
        return SendStatusAsync(packet, state, tcp, MediusLobbyMessageId.BanPlayerResponse, status, ct);
    }

    // =========================================================================
    // Chat
    // =========================================================================

    /// <summary>
    /// ChatMessage (0x3B, 112 B): SessionKey | pad2 | MessageType @40 | TargetID @44 | Message[64] @48. No reply to the
    /// sender; recipients get ChatFwdMessage (0x3C): MessageID(zero) | pad3 | OriginatorAccountID |
    /// OriginatorAccountName[32] | MessageType | Message[64] (130 B). Broadcast = everyone in the sender's lobby
    /// world (briefing room / community), Whisper = TargetID's connections, clan / buddy = those members.
    /// Recipients that ignore the sender are skipped.
    /// </summary>
    private async Task HandleChatAsync(MediusPacket packet, MediusClientState state, CancellationToken ct)
    {
        var p = packet.Payload;
        var type = (MediusChatMessageType)Int(p, SessionBody);
        int targetId = Int(p, SessionBody + 4);
        string text = Str(p, SessionBody + 8, ChatLen);
        var me = Me(state);
        if (me == null) return;

        // Clan, buddy and ignore lists change under _store.Sync; read them under it too.
        List<(MediusClientState State, TcpClient Client)> recipients;
        lock (_store.Sync)
        {
            HashSet<int>? accounts = type switch
            {
                MediusChatMessageType.Whisper                       => new HashSet<int> { targetId },
                MediusChatMessageType.MediusClanChatType            => _store.GetClanById(me.ClanId)?.Members.ToHashSet() ?? new HashSet<int>(),
                MediusChatMessageType.MediusBuddyChatType           => me.Buddies.ToHashSet(),
                _                                                   => null,   // broadcast: by lobby world, below
            };

            recipients = Clients.Values.Where(c =>
                c.State.ConnectionId != state.ConnectionId
                && c.State.IsSessionEstablished
                && c.State.AccountId is int id && id != me.AccountId
                && (type == MediusChatMessageType.BroadcastAcrossEntireUniverse
                    || (accounts != null ? accounts.Contains(id) : c.State.WorldId == state.WorldId))
                && _store.GetAccountById(id)?.Ignores.Contains(me.AccountId) != true).ToList();
        }

        var fwd = new MediusWriter();
        fwd.WritePadding(MediusConstants.MESSAGEID_MAXLEN);   // MessageID (unsolicited)
        fwd.WritePadding(3);
        fwd.Write(me.AccountId);
        fwd.WriteString(me.AccountName, NameLen);
        fwd.Write((int)type);
        fwd.WriteString(text, ChatLen);
        var body = fwd.ToArray();

        foreach (var (rState, rTcp) in recipients)
            await SendMediusAsync(rTcp, MediusPacket.BuildLobby(MediusLobbyMessageId.ChatFwdMessage, body), rState, ct);

        _log.LogInformation("[MLS] Chat {Type} from {Me}{Target} -> {Count} recipient(s): {Text}",
            type, me.AccountName, type == MediusChatMessageType.Whisper ? $" to {targetId}" : "", recipients.Count, text);
    }

    // =========================================================================
    // Player lists
    // =========================================================================

    /// <summary>The lobby world a request asks about — its MediusWorldID, or the sender's own world when 0.</summary>
    private int LobbyWorld(MediusClientState state, int requested) => requested != 0 ? requested : state.WorldId ?? 0;

    private List<MediusAccount> AccountsInLobby(int worldId) =>
        _presence.AccountsInLobby(worldId).Select(_store.GetAccountById).OfType<MediusAccount>()
            .OrderBy(a => a.AccountName, StringComparer.OrdinalIgnoreCase).ToList();

    /// <summary>
    /// LobbyWorldPlayerList (0x2D): SessionKey | pad2 | MediusWorldID @40 → 0x2E rows: PlayerStatus | AccountID |
    /// Name[32] | Stats[256] | ConnectionClass.
    /// </summary>
    private Task HandleLobbyWorldPlayerListAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        int world = LobbyWorld(state, Int(packet.Payload, SessionBody));
        var players = AccountsInLobby(world);
        _log.LogDebug("[MLS] LobbyWorldPlayerList world=0x{World:X} -> {Count}", world, players.Count);

        return SendListAsync(packet, state, tcp, MediusLobbyMessageId.LobbyWorldPlayerListResponse, players,
            4 + 4 + NameLen + StatsLen + 4, (w, a) =>
            {
                w.Write((int)(_presence.Get(a.AccountId)?.Status ?? MediusPlayerStatus.MediusPlayerDisconnected));
                w.Write(a.AccountId);
                w.WriteString(a.AccountName, NameLen);
                w.Write(Fixed(a.AccountStats, StatsLen));
                w.Write((int)MediusConnectionType.Ethernet);
            }, ct);
    }

    /// <summary>
    /// GetLobbyPlayerNames (0x9F): SessionKey | pad2 | MediusWorldID @40 → 0xA0 rows: AccountID | Name[32].
    /// GetLobbyPlayerNames_ExtraInfo (0xDC): MessageID | pad3 | MediusWorldID @24 → 0xDD rows: AccountID | Name[32] | OnlineState.
    /// </summary>
    private Task HandleGetLobbyPlayerNamesAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, bool extraInfo, CancellationToken ct)
    {
        int world = LobbyWorld(state, Int(packet.Payload, extraInfo ? Pad3Body : SessionBody));
        var players = AccountsInLobby(world);
        _log.LogDebug("[MLS] GetLobbyPlayerNames{Extra} world=0x{World:X} -> {Count}", extraInfo ? "_ExtraInfo" : "", world, players.Count);

        if (!extraInfo)
            return SendListAsync(packet, state, tcp, MediusLobbyMessageId.GetLobbyPlayerNamesResponse, players,
                4 + NameLen, (w, a) =>
                {
                    w.Write(a.AccountId);
                    w.WriteString(a.AccountName, NameLen);
                }, ct);

        return SendListAsync(packet, state, tcp, MediusLobbyMessageId.GetLobbyPlayerNames_ExtraInfoResponse, players,
            4 + NameLen + OnlineStateSize, (w, a) =>
            {
                w.Write(a.AccountId);
                w.WriteString(a.AccountName, NameLen);
                WriteOnlineState(w, a.AccountId);
            }, ct);
    }

    /// <summary>
    /// GameWorldPlayerList (0x2F): SessionKey | pad2 | MediusWorldID @40 (the game) → 0x30 rows: AccountID | Name[32] |
    /// Stats[256] | ConnectionClass. Players = accounts with a live slot in that game's DME world.
    /// </summary>
    private Task HandleGameWorldPlayerListAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        int gameId = Int(packet.Payload, SessionBody);
        var world = DmeWorld.All.FirstOrDefault(w => w.MediusWorldId == gameId);
        var players = world == null ? new List<MediusAccount>()
            : world.Clients.Values.Where(c => c.IsConnected && !c.Disconnected)
                .Select(c => _store.GetAccountById(c.AccountId)).OfType<MediusAccount>().ToList();
        _log.LogDebug("[MLS] GameWorldPlayerList game=0x{Game:X} -> {Count}", gameId, players.Count);

        return SendListAsync(packet, state, tcp, MediusLobbyMessageId.GameWorldPlayerListResponse, players,
            4 + NameLen + StatsLen + 4, (w, a) =>
            {
                w.Write(a.AccountId);
                w.WriteString(a.AccountName, NameLen);
                w.Write(Fixed(a.AccountStats, StatsLen));
                w.Write((int)MediusConnectionType.Ethernet);
            }, ct);
    }

    /// <summary>ChannelInfo (0x35): SessionKey | pad2 | MediusWorldID @40 → 0x36: header | LobbyName[64] | ActivePlayerCount | MaxPlayers.</summary>
    private Task HandleChannelInfoAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        int world = LobbyWorld(state, Int(packet.Payload, SessionBody));
        var channel = _store.GetChannelById(world);

        var w = new MediusWriter();
        WriteMlsHeader(w, packet, channel != null ? MediusCallbackStatus.MediusSuccess : MediusCallbackStatus.MediusChannelNotFound);
        w.WriteString(channel?.ChannelName ?? "", WorldNameLen);
        w.Write(channel != null ? RoomPlayerCount(channel.ChannelId) : 0);
        w.Write(channel?.MaxPlayers ?? 0);
        _log.LogDebug("[MLS] ChannelInfo world=0x{World:X} -> {Name}", world, channel?.ChannelName ?? "(none)");
        return SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.ChannelInfoResponse, w.ToArray()), state, ct);
    }

    /// <summary>Players currently in a briefing room (online presence, not the hop-prone channel roster).</summary>
    private int RoomPlayerCount(int roomId) => _presence.AccountsInLobby(roomId).Count;

    /// <summary>GetTotalRankings (0xD8): MessageID | pad3 | LadderType @24 (0 players, 1 clans) → 0xD9: header | TotalRankings.</summary>
    private Task HandleGetTotalRankingsAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var ladderType = (MediusLadderType)Int(packet.Payload, Pad3Body);
        int total = ladderType == MediusLadderType.MediusLadderTypeClan
            ? RankedClans(0, (int)MediusSortOrder.MEDIUS_DESCENDING).Count
            : RankedPlayers(0, (int)MediusSortOrder.MEDIUS_DESCENDING).Count;

        var w = new MediusWriter();
        WriteMlsHeader(w, packet, MediusCallbackStatus.MediusSuccess);
        w.Write(total);
        _log.LogInformation("[MLS] GetTotalRankings {Type} -> {Total}", ladderType, total);
        return SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.GetTotalRankingsResponse, w.ToArray()), state, ct);
    }
}
