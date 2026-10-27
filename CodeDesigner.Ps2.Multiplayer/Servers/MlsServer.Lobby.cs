using System.Net.Sockets;
using CodeDesigner.Ps2.Multiplayer.Models;
using CodeDesigner.Ps2.Multiplayer.Protocol;
using Microsoft.Extensions.Logging;

namespace CodeDesigner.Ps2.Multiplayer.Servers;

/// <summary>
/// Lobby requests the SOCOM II client sends that had no handler. All of them were found by walking the r0004
/// client's Medius sender table (every sender loads its request type from the table at EE 0x004B9000 and stores
/// its reply callback at 0x0040C8DC+; CodeDesigner.Ps2.Bridge/Resources/Dumps/r0004.bin) and keeping the senders
/// that game code actually calls:
///
///  • ClearGameListFilter0 (0x50) — first link of the game-list refresh chain: its callback (EE 0x00315E50) sends
///    SetGameListFilter0, whose callback (0x00315ED0) sends GameList_ExtraInfo0. No reply → no refresh.
///  • FindWorldByName (0x37) — "FindRoomByName" / "FindGameByName": resolves a room or game NAME to its
///    MediusWorldID before a JoinChannel / JoinGame (join-by-name paths, e.g. following a friend).
///  • AddToBuddyListConfirmation (LobbyExt 0x05) — the add-friend-by-name flow: FindPlayer → this → the callback
///    (0x0031DF70) refreshes the buddy list only when StatusCode == MediusRequestAccepted (2).
///  • AddPlayerToClan (0x5E) — leader adds a player straight into the clan ("Everyone welcome X to the clan").
///  • GetTotalUsers / GetTotalGames / GetTotalChannels, SessionEnd, SetLocalizationParams — small acks.
///
/// Request offsets: "session" requests are MessageID[21] | SessionKey[17] | pad2 → body @0x28 (SessionBody).
/// </summary>
public partial class MlsServer
{
    // =========================================================================
    // Game-list refresh chain
    // =========================================================================

    /// <summary>
    /// ClearGameListFilter0 (0x50, 44 B): SessionKey | pad2 | FilterID @0x28 (SOCOM uses 1 and 0x0A). Reply
    /// ClearGameListFilterResponse (0x51) = header only; the client's callbacks read nothing but StatusCode and
    /// go on to SetGameListFilter0 → GameList_ExtraInfo0. Filters themselves are never applied here (the room's
    /// full list is always sent), so the ack is all that is needed. Gated like SetGameListFilter0: a briefing-room
    /// connection is always answered, the community/login connection only with CommunityRetailReplies.
    /// </summary>
    private Task HandleClearGameListFilterAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        int filterId = Int(packet.Payload, SessionBody);
        if (IsRoomConnection(state) || _config.CommunityRetailReplies)
        {
            _log.LogDebug("[MLS] ClearGameListFilter0 filter={Filter} (world 0x{World:X}) -> ack", filterId, state.WorldId ?? 0);
            return SendStatusAsync(packet, state, tcp, MediusLobbyMessageId.ClearGameListFilterResponse, MediusCallbackStatus.MediusSuccess, ct);
        }

        _log.LogInformation("[MLS] ClearGameListFilter0 filter={Filter} on the community connection left unanswered (CommunityRetailReplies off)", filterId);
        return Task.CompletedTask;
    }

    // =========================================================================
    // FindWorldByName
    // =========================================================================

    /// <summary>FindWorldByName WorldType as the r0004 client sends it (not horizon's enum).</summary>
    internal const int FindWorldTypeGame  = 0;
    internal const int FindWorldTypeLobby = 1;

    /// <summary>FindWorldByNameResponse payload size (horizon layout, 0x9C).</summary>
    internal const int FindWorldByNameResponseSize = 0x9C;

    /// <summary>
    /// Parse the v108 FindWorldByName request (108 B): MessageID[21] | SessionKey[17] | Name[64] @0x26 | pad2 |
    /// WorldType @0x68 — RE'd from the client's FindRoomByName (EE 0x0030A810, type 1, result → lobby-world
    /// global 0x00669EB8) and FindGameByName (0x0030B050, type 0, result → game-world global 0x00669F70) senders.
    /// Horizon puts WorldType before the name; SOCOM II does not.
    /// </summary>
    internal static (string Name, int WorldType) ParseFindWorldByName(byte[] payload)
    {
        const int nameAt = MediusConstants.MESSAGEID_MAXLEN + MediusConstants.SESSIONKEY_MAXLEN;   // 0x26
        const int typeAt = nameAt + WorldNameLen + 2;                                              // 0x68
        return (Str(payload, nameAt, WorldNameLen), Int(payload, typeAt));
    }

    /// <summary>
    /// FindWorldByNameResponse (0x38, 0x9C B): header | ApplicationID | ApplicationName[32] | ApplicationType |
    /// MediusWorldID @0x44 | WorldName[64] | WorldStatus | PlayerCount | MaxPlayers | GameWorldCount | EndOfList |
    /// pad3. The client reads StatusCode @0x18 and MediusWorldID @0x44 (callbacks EE 0x0030A980 / 0x0030B1D0).
    /// </summary>
    internal static byte[] BuildFindWorldByNameResponse(MediusPacket packet, MediusCallbackStatus status, int appId,
        int worldId, string worldName, int worldStatus, int playerCount, int maxPlayers, int gameWorldCount)
    {
        var w = new MediusWriter();
        WriteMlsHeader(w, packet, status);                                   // 0x00 .. 0x1C
        w.Write(appId);                                                       // 0x1C ApplicationID
        w.WriteString(status == MediusCallbackStatus.MediusSuccess ? "SOCOM II" : "", MediusConstants.APPNAME_MAXLEN); // 0x20
        w.Write(0);                                                           // 0x40 ApplicationType (game)
        w.Write(worldId);                                                     // 0x44 MediusWorldID
        w.WriteString(worldName, WorldNameLen);                               // 0x48 WorldName[64]
        w.Write(worldStatus);                                                 // 0x88
        w.Write(playerCount);                                                 // 0x8C
        w.Write(maxPlayers);                                                  // 0x90
        w.Write(gameWorldCount);                                              // 0x94
        w.Write((byte)1);                                                     // 0x98 EndOfList
        w.WritePadding(3);                                                    // → 0x9C
        return w.ToArray();
    }

    private Task HandleFindWorldByNameAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var (name, worldType) = ParseFindWorldByName(packet.Payload);
        byte[] body;

        if (worldType == FindWorldTypeLobby)
        {
            var room = GetBriefingRoomChannels(state.AppId)
                .FirstOrDefault(r => string.Equals(r.ChannelName, name, StringComparison.OrdinalIgnoreCase));
            body = room == null
                ? BuildFindWorldByNameResponse(packet, MediusCallbackStatus.MediusChannelNotFound, 0, 0, "", 0, 0, 0, 0)
                : BuildFindWorldByNameResponse(packet, MediusCallbackStatus.MediusSuccess, state.AppId, room.ChannelId, room.ChannelName,
                    (int)MediusWorldStatus.WorldActive, RoomPlayerCount(room.ChannelId), room.MaxPlayers, GamesInRoom(room.ChannelId, state.AppId));
            _log.LogInformation("[MLS] FindWorldByName lobby '{Name}' -> {Result}", name, room != null ? $"0x{room.ChannelId:X}" : "not found");
        }
        else
        {
            var found = FindGameByName(name, state);
            body = found == null
                ? BuildFindWorldByNameResponse(packet, MediusCallbackStatus.MediusGameNotFound, 0, 0, "", 0, 0, 0, 0)
                : BuildFindWorldByNameResponse(packet, MediusCallbackStatus.MediusSuccess, state.AppId, found.Value.WorldId, found.Value.Name,
                    found.Value.WorldStatus, found.Value.PlayerCount, found.Value.MaxPlayers, 0);
            _log.LogInformation("[MLS] FindWorldByName game '{Name}' -> {Result}", name, found != null ? $"0x{found.Value.WorldId:X}" : "not found");
        }

        return SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.FindWorldByNameResponse, body), state, ct);
    }

    /// <summary>Live games listed in a briefing room (player games whose DME world is up, plus occupied default rooms).</summary>
    private int GamesInRoom(int roomId, int appId)
    {
        int n = _store.GetGames(appId).Count(g => g.LobbyChannelId == roomId
            && g.DmeWorldId is int wid && DmeWorld.GetById(wid) is { } w && w.MediusWorldId == g.GameId);
        n += _defaultGameWorlds.Count(kv => kv.Key >> 8 == roomId && DmeWorld.GetById(kv.Value.WorldId) == kv.Value && kv.Value.ConnectedCount > 0);
        return n;
    }

    /// <summary>
    /// Resolve a game name the way the lists show it: a player game ("Name" or "Name$~Room") or a default room
    /// ("Name" or "Name$~Room", the sender's briefing room first). Returns the MediusWorldID the lists carry.
    /// </summary>
    private (int WorldId, string Name, int WorldStatus, int PlayerCount, int MaxPlayers)? FindGameByName(string name, MediusClientState state)
    {
        static string Base(string s) { int i = s.IndexOf("$~", StringComparison.Ordinal); return i < 0 ? s : s[..i]; }
        string wanted = Base(name).Trim();
        if (wanted.Length == 0) return null;

        foreach (var g in _store.GetGames(state.AppId))
        {
            if (!string.Equals(Base(g.GameName).Trim(), wanted, StringComparison.OrdinalIgnoreCase)) continue;
            var world = g.DmeWorldId is int wid ? DmeWorld.GetById(wid) : null;
            return (g.GameId, g.GameName, (int)g.Status, world?.ConnectedCount ?? g.PlayerCount, g.MaxPlayers);
        }

        var rooms = GetBriefingRoomChannels(state.AppId);
        if (state.WorldId is int here && rooms.FirstOrDefault(r => r.ChannelId == here) is { } own)
            rooms = rooms.Where(r => r.ChannelId == own.ChannelId).Concat(rooms.Where(r => r.ChannelId != own.ChannelId)).ToList();
        string roomName = name.Contains("$~", StringComparison.Ordinal) ? name[(name.IndexOf("$~", StringComparison.Ordinal) + 2)..].Trim() : "";

        foreach (var room in rooms)
        {
            if (roomName.Length > 0 && !string.Equals(room.ChannelName, roomName, StringComparison.OrdinalIgnoreCase)) continue;
            for (int i = 0; i < _config.DefaultGames.Count; i++)
            {
                if (!string.Equals(_config.DefaultGames[i].Name.Trim(), wanted, StringComparison.OrdinalIgnoreCase)) continue;
                int id = (room.ChannelId << 8) | (2 + i);
                int players = _defaultGameWorlds.TryGetValue(id, out var dw) && DmeWorld.GetById(dw.WorldId) == dw ? dw.ConnectedCount : 0;
                return (id, $"{_config.DefaultGames[i].Name}$~{room.ChannelName}", (int)MediusWorldStatus.WorldActive, players, DefaultGameMaxPlayers);
            }
        }
        return null;
    }

    // =========================================================================
    // Totals, session end
    // =========================================================================

    /// <summary>GetTotalUsers (0xA1) / GetTotalGames (0x9B) / GetTotalChannels (0x9D): MessageID | SessionKey → header | Total.</summary>
    private Task HandleGetTotalsAsync(MediusLobbyMessageId type, MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var (responseType, total) = type switch
        {
            MediusLobbyMessageId.GetTotalGames    => (MediusLobbyMessageId.GetTotalGamesResponse,
                                                      DmeWorld.All.Count(w => w.AppId == state.AppId && w.ConnectedCount > 0)),
            MediusLobbyMessageId.GetTotalChannels => (MediusLobbyMessageId.GetTotalChannelsResponse, GetBriefingRoomChannels(state.AppId).Count),
            _                                     => (MediusLobbyMessageId.GetTotalUsersResponse, _presence.OnlineCount),
        };

        var w = new MediusWriter();
        WriteMlsHeader(w, packet, MediusCallbackStatus.MediusSuccess);
        w.Write(total);
        _log.LogDebug("[MLS] {Type} -> {Total}", type, total);
        return SendMediusAsync(tcp, MediusPacket.BuildLobby(responseType, w.ToArray()), state, ct);
    }

    /// <summary>SessionEnd (0x05): MessageID | SessionKey → SessionEndResponse (0x06) header only. The session itself ends with the socket.</summary>
    private Task HandleSessionEndAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        _log.LogInformation("[MLS] SessionEnd from {Acct}", state.AccountName);
        state.Status = PlayerStatus.Disconnected;
        return SendStatusAsync(packet, state, tcp, MediusLobbyMessageId.SessionEndResponse, MediusCallbackStatus.MediusSuccess, ct);
    }

    // =========================================================================
    // Friends: add by name (confirmation flow)
    // =========================================================================

    /// <summary>AddToBuddyListConfirmationResponse payload size the client's library expects (0x48).</summary>
    internal const int AddToBuddyListConfirmationResponseSize = 0x48;

    /// <summary>
    /// AddToBuddyListConfirmationResponse (Lobby 0x44): header | TargetAccountID | TargetAccountName[32] | pad8 (0x48 B).
    /// StatusCode MediusRequestAccepted (2) is what the client's callback (EE 0x0031DF70) waits for before it
    /// re-requests its buddy list.
    /// </summary>
    internal static byte[] BuildAddToBuddyListConfirmationResponse(MediusPacket packet, MediusCallbackStatus status, int targetId, string targetName)
    {
        var w = new MediusWriter();
        WriteMlsHeader(w, packet, status);
        w.Write(targetId);
        w.WriteString(targetName, NameLen);
        w.WritePadding(AddToBuddyListConfirmationResponseSize - (MediusConstants.MESSAGEID_MAXLEN + 3 + 4 + 4 + NameLen));
        return w.ToArray();
    }

    /// <summary>
    /// AddToBuddyListConfirmation (LobbyExt 0x05, 48 B): SessionKey | pad2 | TargetAccountID @0x28 | 0 @0x2C. SOCOM II
    /// sends it after a FindPlayer-by-name (callback EE 0x0031E960 copies FindPlayerResponse.AccountID @0x48 into it)
    /// when the player types a friend's name. Retail forwarded the request to the target for confirmation; this
    /// private server accepts on their behalf and makes the friendship mutual, then answers RequestAccepted so the
    /// client refreshes its buddy list straight away.
    /// </summary>
    private Task HandleAddToBuddyListConfirmationAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        int targetId = Int(packet.Payload, SessionBody);
        var me = Me(state);
        var target = _store.GetAccountById(targetId);
        MediusCallbackStatus status;

        lock (_store.Sync)
        {
            if (me == null || target == null || target.AccountId == me.AccountId)
                status = MediusCallbackStatus.MediusAccountNotFound;
            else
            {
                if (!me.Buddies.Contains(target.AccountId)) me.Buddies.Add(target.AccountId);
                if (!target.Buddies.Contains(me.AccountId)) target.Buddies.Add(me.AccountId);
                _store.MarkDirty();
                status = MediusCallbackStatus.MediusRequestAccepted;
            }
        }

        _log.LogInformation("[MLS] AddToBuddyListConfirmation {Target} ({Id}) by {Me} -> {Status} (auto-accepted, mutual)",
            target?.AccountName ?? "?", targetId, me?.AccountName, status);
        var body = BuildAddToBuddyListConfirmationResponse(packet, status, target?.AccountId ?? 0, target?.AccountName ?? "");
        return SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.AddToBuddyListConfirmationResponse, body), state, ct);
    }

    // =========================================================================
    // Clans: leader adds a player
    // =========================================================================

    /// <summary>
    /// AddPlayerToClan (0x5E, 244 B): SessionKey | pad2 | AccountID @0x28 | Message[200] @0x2C ("Everyone welcome %s to the
    /// clan", EE 0x00303EF0). Leader only; the player must not be in a clan. The message is posted on the clan board.
    /// Reply AddPlayerToClanResponse (0x5F) = header only (the callback, EE 0x00304220, checks StatusCode).
    /// </summary>
    private Task HandleAddPlayerToClanAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var p = packet.Payload;
        int targetId = Int(p, SessionBody);
        string message = Str(p, SessionBody + 4, ClanMsgLen);
        var me = Me(state);
        var target = _store.GetAccountById(targetId);
        MediusCallbackStatus status;

        lock (_store.Sync)
        {
            var clan = me != null ? _store.GetClanById(me.ClanId) : null;
            if (clan == null)                                   status = MediusCallbackStatus.MediusClanNotFound;
            else if (clan.LeaderAccountId != me!.AccountId)     status = MediusCallbackStatus.MediusNotClanLeader;
            else if (target == null)                            status = MediusCallbackStatus.MediusAccountNotFound;
            else if (_store.GetClanById(target.ClanId) != null) status = MediusCallbackStatus.MediusInvalidRequestMsg;   // already in a clan (same as the invite path)
            else
            {
                if (!clan.Members.Contains(target.AccountId)) clan.Members.Add(target.AccountId);
                target.ClanId = clan.ClanId;
                foreach (var inv in _store.Invitations.Where(i => i.ClanId == clan.ClanId && i.AccountId == target.AccountId
                             && i.Status == MediusClanInvitationsResponseStatus.ClanInvitationUndecided))
                    inv.Status = MediusClanInvitationsResponseStatus.ClanInvitationAccept;
                if (message.Trim().Length > 0)
                    clan.Messages.Add(new MediusClanMessage { MessageId = _store.NextClanMessageId(), Text = message });
                _store.MarkDirty();
                status = MediusCallbackStatus.MediusSuccess;
            }
        }

        _log.LogInformation("[MLS] AddPlayerToClan {Target} by {Me} -> {Status}", target?.AccountName ?? targetId.ToString(), me?.AccountName, status);
        return SendStatusAsync(packet, state, tcp, MediusLobbyMessageId.AddPlayerToClanResponse, status, ct);
    }
}
