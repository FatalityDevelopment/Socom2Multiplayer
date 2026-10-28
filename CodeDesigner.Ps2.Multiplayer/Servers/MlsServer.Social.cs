using System.Net.Sockets;
using CodeDesigner.Ps2.Multiplayer.Models;
using CodeDesigner.Ps2.Multiplayer.Protocol;
using Microsoft.Extensions.Logging;

namespace CodeDesigner.Ps2.Multiplayer.Servers;

/// <summary>
/// Friends (buddy list), ignore list, ladder rankings and clans.
///
/// Wire layouts are horizon-server's (RT.Models/Lobby) unless noted. Every reply size the retail
/// acceptEULA / create_Masquarr captures show matches exactly: buddy 210, ignore 74, my clans 370,
/// clan invitations 282, clan ladder 74, ladder position 38. The ladder list entry is the exception —
/// SOCOM v108 drops horizon's AccountID (RE'd from the client's ladder callback, EE 0x00308660/0x00308E10:
/// position @0x1C, stat @0x20, name @0x24, stats @0x44, OnlineState @0x144, EndOfList @0x1D0 → 470 B,
/// the retail size). The rest (member list, clan messages, invitations sent) are horizon layouts
/// not yet seen on the wire; every request is logged in full.
///
/// Request offsets used below: MessageID[21] @0, SessionKey[17] @21, pad2 → body @40 ("session" requests);
/// MessageID[21] @0, pad3 → body @24 ("pad3" requests).
/// </summary>
public partial class MlsServer
{
    private const int SessionBody = MediusConstants.MESSAGEID_MAXLEN + MediusConstants.SESSIONKEY_MAXLEN + 2; // 40
    private const int Pad3Body    = MediusConstants.MESSAGEID_MAXLEN + 3;                                      // 24
    private const int NameLen      = MediusConstants.ACCOUNTNAME_MAXLEN;   // 32
    private const int ClanNameLen  = 32;
    private const int ClanMsgLen   = 200;
    private const int WorldNameLen = 64;
    private const int StatsLen     = MediusConstants.ACCOUNTSTATS_MAXLEN;  // 256
    private const int OnlineStateSize = 4 + 4 + 4 + WorldNameLen + WorldNameLen; // 140

    private async Task<bool> TryHandleSocialAsync(MediusLobbyMessageId type, MediusPacket packet,
        MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        switch (type)
        {
            // ── Friends ──────────────────────────────────────────────────────
            case MediusLobbyMessageId.GetBuddyList_ExtraInfo: await HandleGetBuddyListAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.AddToBuddyList:         await HandleBuddyChangeAsync(packet, state, tcp, add: true, ct); return true;
            case MediusLobbyMessageId.RemoveFromBuddyList:    await HandleBuddyChangeAsync(packet, state, tcp, add: false, ct); return true;
            case MediusLobbyMessageId.AccountGetID:           await HandleAccountGetIdAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.FindPlayer:             await HandleFindPlayerAsync(packet, state, tcp, ct); return true;

            // ── Ignore list ──────────────────────────────────────────────────
            case MediusLobbyMessageId.GetIgnoreList:          await HandleGetIgnoreListAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.AddToIgnoreList:        await HandleIgnoreChangeAsync(packet, state, tcp, add: true, ct); return true;
            case MediusLobbyMessageId.RemoveFromIgnoreList:   await HandleIgnoreChangeAsync(packet, state, tcp, add: false, ct); return true;

            // ── Ladder rankings ──────────────────────────────────────────────
            case MediusLobbyMessageId.LadderList_ExtraInfo0:    await HandleLadderListAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.LadderPosition_ExtraInfo: await HandleLadderPositionAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.ClanLadderList:           await HandleClanLadderListAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.ClanLadderPosition:       await HandleClanLadderPositionAsync(packet, state, tcp, ct); return true;

            // ── Clans ────────────────────────────────────────────────────────
            case MediusLobbyMessageId.GetMyClans:                  await HandleGetMyClansAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.CreateClan:                  await HandleCreateClanAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.DisbandClan:                 await HandleDisbandClanAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.GetClanByID:                 await HandleGetClanByIdAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.GetClanByName:               await HandleGetClanByNameAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.TransferClanLeadership:      await HandleTransferClanLeadershipAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.RemovePlayerFromClan:        await HandleRemovePlayerFromClanAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.AddPlayerToClan:             await HandleAddPlayerToClanAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.InvitePlayerToClan:          await HandleInvitePlayerToClanAsync(packet, state, tcp, byName: false, ct); return true;
            case MediusLobbyMessageId.InvitePlayerToClan_ByName:   await HandleInvitePlayerToClanAsync(packet, state, tcp, byName: true, ct); return true;
            case MediusLobbyMessageId.CheckMyClanInvitations:      await HandleCheckMyClanInvitationsAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.RespondToClanInvitation:     await HandleRespondToClanInvitationAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.RevokeClanInvitation:        await HandleRevokeClanInvitationAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.GetClanInvitationsSent:      await HandleGetClanInvitationsSentAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.GetClanMemberList_ExtraInfo: await HandleGetClanMemberListAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.GetMyClanMessages:           await HandleGetMyClanMessagesAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.GetAllClanMessages:          await HandleGetAllClanMessagesAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.SendClanMessage:             await HandleSendClanMessageAsync(packet, state, tcp, ct); return true;
            case MediusLobbyMessageId.ModifyClanMessage:           await HandleModifyClanMessageAsync(packet, state, tcp, delete: false, ct); return true;
            case MediusLobbyMessageId.DeleteClanMessage:           await HandleModifyClanMessageAsync(packet, state, tcp, delete: true, ct); return true;
            case MediusLobbyMessageId.UpdateClanStats:             await HandleUpdateClanStatsAsync(packet, state, tcp, ct); return true;

            default: return await TryHandleChatAndListsAsync(type, packet, state, tcp, ct);
        }
    }

    // =========================================================================
    // Friends
    // =========================================================================

    /// <summary>GetBuddyList_ExtraInfo (0xD6, MessageID only) → 0xD7 rows: AccountID | Name[32] | OnlineState.</summary>
    private Task HandleGetBuddyListAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var me = Me(state);
        var buddies = me == null ? new List<MediusAccount>()
            : Snapshot(me.Buddies).Select(_store.GetAccountById).OfType<MediusAccount>().ToList();

        return SendListAsync(packet, state, tcp, MediusLobbyMessageId.GetBuddyList_ExtraInfoResponse, buddies,
            4 + NameLen + OnlineStateSize, (w, b) =>
            {
                w.Write(b.AccountId);
                w.WriteString(b.AccountName, NameLen);
                WriteOnlineState(w, b.AccountId);
            }, ct);
    }

    /// <summary>AddToBuddyList (0x3F) / RemoveFromBuddyList (0x41): SessionKey | pad2 | AccountID @40.</summary>
    private Task HandleBuddyChangeAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, bool add, CancellationToken ct)
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
                if (add && !me.Buddies.Contains(targetId)) me.Buddies.Add(targetId);
                if (!add) me.Buddies.Remove(targetId);
                _store.MarkDirty();
                status = MediusCallbackStatus.MediusSuccess;
            }
        }

        _log.LogInformation("[MLS] {Action} buddy {Target} for {Me} -> {Status}",
            add ? "Add" : "Remove", target?.AccountName ?? targetId.ToString(), me?.AccountName, status);
        return SendStatusAsync(packet, state, tcp,
            add ? MediusLobbyMessageId.AddToBuddyListResponse : MediusLobbyMessageId.RemoveFromBuddyListResponse, status, ct);
    }

    /// <summary>AccountGetID (0x17): MessageID | SessionKey[17] | AccountName[32] → 0x18: MessageID | pad3 | AccountID | Status.</summary>
    private Task HandleAccountGetIdAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        string name = Str(packet.Payload, MediusConstants.MESSAGEID_MAXLEN + MediusConstants.SESSIONKEY_MAXLEN, NameLen);
        var account = _store.GetAccountByName(name);

        var w = new MediusWriter();
        w.Write(MlsMsgId(packet));
        w.WritePadding(3);
        w.Write(account?.AccountId ?? 0);
        w.Write((int)(account != null ? MediusCallbackStatus.MediusSuccess : MediusCallbackStatus.MediusAccountNotFound));

        _log.LogInformation("[MLS] AccountGetID '{Name}' -> {Id}", name, account?.AccountId);
        return SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.AccountGetIDResponse, w.ToArray()), state, ct);
    }

    /// <summary>
    /// FindPlayer (0x39): SessionKey | pad2 | SearchType @40 (0 id, 1 name) | ID @44 | Name[32] @48 (82 B on the wire).
    /// Reply 0x3A: header | AppID | AppName[32] | AppType | MediusWorldID | AccountID | AccountName[32] | EndOfList | pad3
    /// (114 B). MediusWorldID is the player's current game (else lobby) world; unknown names → AccountNotFound.
    /// </summary>
    private Task HandleFindPlayerAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var p = packet.Payload;
        var searchType = (MediusPlayerSearchType)Int(p, SessionBody);
        var account = searchType == MediusPlayerSearchType.PlayerAccountID
            ? _store.GetAccountById(Int(p, SessionBody + 4))
            : _store.GetAccountByName(Str(p, SessionBody + 8, MediusConstants.PLAYERNAME_MAXLEN));
        var presence = account != null ? _presence.Get(account.AccountId) : null;

        var w = new MediusWriter();
        WriteMlsHeader(w, packet, account != null ? MediusCallbackStatus.MediusSuccess : MediusCallbackStatus.MediusAccountNotFound);
        w.Write(account != null ? state.AppId : 0);
        w.WriteString(account != null ? "SOCOM II" : "", MediusConstants.APPNAME_MAXLEN);
        w.Write(0);                                                   // ApplicationType (game)
        w.Write(presence == null ? 0 : presence.GameWorldId != 0 ? presence.GameWorldId : presence.LobbyWorldId);
        w.Write(account?.AccountId ?? 0);
        w.WriteString(account?.AccountName ?? "", NameLen);
        w.Write((byte)1);
        w.WritePadding(3);

        _log.LogInformation("[MLS] FindPlayer {Type} -> {Name} ({Online})", searchType, account?.AccountName ?? "(none)",
            presence != null ? "online" : "offline");
        return SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.FindPlayerResponse, w.ToArray()), state, ct);
    }

    // =========================================================================
    // Ignore list
    // =========================================================================

    /// <summary>GetIgnoreList (0xC0) → 0xC1 rows: IgnoreAccountID | Name[32] | PlayerStatus (74 B, retail size).</summary>
    private Task HandleGetIgnoreListAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var me = Me(state);
        var ignored = me == null ? new List<MediusAccount>()
            : Snapshot(me.Ignores).Select(_store.GetAccountById).OfType<MediusAccount>().ToList();

        return SendListAsync(packet, state, tcp, MediusLobbyMessageId.GetIgnoreListResponse, ignored,
            4 + NameLen + 4, (w, a) =>
            {
                w.Write(a.AccountId);
                w.WriteString(a.AccountName, NameLen);
                w.Write((int)(_presence.Get(a.AccountId)?.Status ?? MediusPlayerStatus.MediusPlayerDisconnected));
            }, ct);
    }

    /// <summary>AddToIgnoreList (0xC2) / RemoveFromIgnoreList (0xC4): SessionKey | pad2 | IgnoreAccountID @40.</summary>
    private Task HandleIgnoreChangeAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, bool add, CancellationToken ct)
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
                if (add && !me.Ignores.Contains(targetId)) me.Ignores.Add(targetId);
                if (!add) me.Ignores.Remove(targetId);
                _store.MarkDirty();
                status = MediusCallbackStatus.MediusSuccess;
            }
        }

        _log.LogInformation("[MLS] {Action} ignore {Target} for {Me} -> {Status}",
            add ? "Add" : "Remove", target?.AccountName ?? targetId.ToString(), me?.AccountName, status);
        return SendStatusAsync(packet, state, tcp,
            add ? MediusLobbyMessageId.AddToIgnoreListResponse : MediusLobbyMessageId.RemoveFromIgnoreListResponse, status, ct);
    }

    // =========================================================================
    // Ladder rankings
    // =========================================================================

    /// <summary>
    /// LadderList_ExtraInfo0 (0xEF): MessageID | pad3 | LadderStatIndex @24 | SortOrder @28 | StartPosition @32 (1-based)
    /// | PageSize @36. Reply 0xF0 rows (SOCOM v108, RE'd): Position | LadderStat | Name[32] | Stats[256] | OnlineState.
    /// SOCOM asks for the top 10 by stat 0 descending ("TheBest") on the community screen.
    /// </summary>
    private Task HandleLadderListAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var p = packet.Payload;
        int statIndex = Int(p, Pad3Body), sortOrder = Int(p, Pad3Body + 4);
        int start = Int(p, Pad3Body + 8), pageSize = Int(p, Pad3Body + 12);

        var ranked = RankedPlayers(statIndex, sortOrder);
        var page = ranked.Select((a, i) => (Position: i + 1, Account: a))
            .Skip(Math.Max(0, start - 1)).Take(pageSize <= 0 ? 10 : pageSize).ToList();

        _log.LogInformation("[MLS] LadderList stat={Stat} sort={Sort} start={Start} size={Size} -> {Count}/{Total}",
            statIndex, sortOrder, start, pageSize, page.Count, ranked.Count);
        return SendListAsync(packet, state, tcp, MediusLobbyMessageId.LadderList_ExtraInfoResponse, page,
            4 + 4 + NameLen + StatsLen + OnlineStateSize, (w, e) =>
            {
                w.Write(e.Position);
                w.Write(StatOf(e.Account.LadderStats, statIndex));
                w.WriteString(e.Account.AccountName, NameLen);
                w.Write(Fixed(e.Account.AccountStats, StatsLen));
                WriteOnlineState(w, e.Account.AccountId);
            }, ct);
    }

    /// <summary>
    /// LadderPosition_ExtraInfo (0xF1): MessageID | pad3 | AccountID @24 | LadderStatIndex @28 | SortOrder @32.
    /// Reply 0xF2: header | LadderPosition | TotalRankings (38 B, retail size). Unranked → position 0.
    /// </summary>
    private Task HandleLadderPositionAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var p = packet.Payload;
        int accountId = Int(p, Pad3Body), statIndex = Int(p, Pad3Body + 4), sortOrder = Int(p, Pad3Body + 8);
        var ranked = RankedPlayers(statIndex, sortOrder);
        int position = ranked.FindIndex(a => a.AccountId == accountId) + 1;

        var w = new MediusWriter();
        WriteMlsHeader(w, packet, MediusCallbackStatus.MediusSuccess);
        w.Write(position);
        w.Write(ranked.Count);
        _log.LogInformation("[MLS] LadderPosition acct={Acct} stat={Stat} -> {Pos}/{Total}", accountId, statIndex, position, ranked.Count);
        return SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.LadderPosition_ExtraInfoResponse, w.ToArray()), state, ct);
    }

    /// <summary>
    /// ClanLadderList (0xD2): MessageID | pad3 | ClanLadderStatIndex @24 | SortOrder @28 | StartPosition @32 | PageSize @36.
    /// Reply 0xD3 rows — status AFTER the body: MessageID | pad3 | ClanID | ClanName[32] | LadderPosition | Status |
    /// EndOfList | pad3 (74 B, retail size).
    /// </summary>
    private async Task HandleClanLadderListAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var p = packet.Payload;
        int statIndex = Int(p, Pad3Body), sortOrder = Int(p, Pad3Body + 4);
        int start = Int(p, Pad3Body + 8), pageSize = Int(p, Pad3Body + 12);

        var ranked = RankedClans(statIndex, sortOrder);
        var page = ranked.Select((c, i) => (Position: i + 1, Clan: c))
            .Skip(Math.Max(0, start - 1)).Take(pageSize <= 0 ? 10 : pageSize).ToList();

        _log.LogInformation("[MLS] ClanLadderList stat={Stat} -> {Count}/{Total}", statIndex, page.Count, ranked.Count);
        if (page.Count == 0)
        {
            var w = new MediusWriter();
            w.Write(MlsMsgId(packet)); w.WritePadding(3);
            w.Write(0); w.WriteString("", ClanNameLen); w.Write(0);
            w.Write((int)MediusCallbackStatus.MediusNoResult);
            w.Write((byte)1); w.WritePadding(3);
            await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.ClanLadderListResponse, w.ToArray()), state, ct);
            return;
        }
        for (int i = 0; i < page.Count; i++)
        {
            var w = new MediusWriter();
            w.Write(MlsMsgId(packet)); w.WritePadding(3);
            w.Write(page[i].Clan.ClanId);
            w.WriteString(page[i].Clan.ClanName, ClanNameLen);
            w.Write(page[i].Position);
            w.Write((int)MediusCallbackStatus.MediusSuccess);
            w.Write((byte)(i == page.Count - 1 ? 1 : 0)); w.WritePadding(3);
            await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.ClanLadderListResponse, w.ToArray()), state, ct);
        }
    }

    /// <summary>ClanLadderPosition (0xD4): MessageID | pad3 | ClanID @24 | StatIndex @28 | SortOrder @32 → MessageID | pad3 | Position | Total | Status.</summary>
    private Task HandleClanLadderPositionAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var p = packet.Payload;
        int clanId = Int(p, Pad3Body), statIndex = Int(p, Pad3Body + 4), sortOrder = Int(p, Pad3Body + 8);
        var ranked = RankedClans(statIndex, sortOrder);
        int position = ranked.FindIndex(c => c.ClanId == clanId) + 1;

        var w = new MediusWriter();
        w.Write(MlsMsgId(packet)); w.WritePadding(3);
        w.Write(position);
        w.Write(ranked.Count);
        w.Write((int)(_store.GetClanById(clanId) != null ? MediusCallbackStatus.MediusSuccess : MediusCallbackStatus.MediusClanNotFound));
        return SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.ClanLadderPositionResponse, w.ToArray()), state, ct);
    }

    /// <summary>Accounts that have reported ladder stats, best first (SortOrder 1 = descending, SOCOM's default).</summary>
    private List<MediusAccount> RankedPlayers(int statIndex, int sortOrder)
    {
        var ranked = _store.Accounts.Where(a => a.LadderStats != null && !a.IsBanned);
        return (sortOrder == (int)MediusSortOrder.MEDIUS_ASCENDING
                ? ranked.OrderBy(a => StatOf(a.LadderStats, statIndex))
                : ranked.OrderByDescending(a => StatOf(a.LadderStats, statIndex)))
            .ThenBy(a => a.AccountId).ToList();
    }

    private List<MediusClan> RankedClans(int statIndex, int sortOrder)
    {
        var ranked = _store.Clans.Where(c => c.LadderStats != null);
        return (sortOrder == (int)MediusSortOrder.MEDIUS_ASCENDING
                ? ranked.OrderBy(c => StatOf(c.LadderStats, statIndex))
                : ranked.OrderByDescending(c => StatOf(c.LadderStats, statIndex)))
            .ThenBy(c => c.ClanId).ToList();
    }

    /// <summary>Copy a social list under <see cref="InMemoryStorage.Sync"/> (its writers hold that lock).</summary>
    private List<T> Snapshot<T>(List<T> list)
    {
        lock (_store.Sync) return list.ToList();
    }

    private static int StatOf(int[]? stats, int index) =>
        stats != null && index >= 0 && index < stats.Length ? stats[index] : 0;

    // =========================================================================
    // Clans
    // =========================================================================

    /// <summary>
    /// GetMyClans (0x7C): SessionKey | pad2 | Start @40 | PageSize @44 → 0x7D rows: ClanID | AppID | ClanName[32] |
    /// LeaderAccountID | LeaderName[32] | Stats[256] | Status (370 B, retail size).
    /// </summary>
    private Task HandleGetMyClansAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var clan = Me(state) is { } me ? _store.GetClanById(me.ClanId) : null;
        var clans = clan != null ? new List<MediusClan> { clan } : new List<MediusClan>();

        return SendListAsync(packet, state, tcp, MediusLobbyMessageId.GetMyClansResponse, clans,
            4 + 4 + ClanNameLen + 4 + NameLen + StatsLen + 4, (w, c) =>
            {
                w.Write(c.ClanId);
                w.Write(c.AppId);
                w.WriteString(c.ClanName, ClanNameLen);
                w.Write(c.LeaderAccountId);
                w.WriteString(_store.GetAccountById(c.LeaderAccountId)?.AccountName ?? "", NameLen);
                w.Write(Fixed(c.Stats, StatsLen));
                w.Write((int)c.Status);
            }, ct);
    }

    /// <summary>CreateClan (0x54): SessionKey | pad2 | AppID @40 | ClanName[32] @44 → 0x55: header | ClanID.</summary>
    private Task HandleCreateClanAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        int appId = Int(packet.Payload, SessionBody);
        string name = Str(packet.Payload, SessionBody + 4, ClanNameLen).Trim();
        var me = Me(state);
        MediusCallbackStatus status;
        MediusClan? clan = null;

        lock (_store.Sync)
        {
            if (me == null)                                 status = MediusCallbackStatus.MediusAccountNotFound;
            else if (_store.GetClanById(me.ClanId) != null) status = MediusCallbackStatus.MediusAlreadyLeaderOfClan;
            else if (name.Length == 0)                      status = MediusCallbackStatus.MediusInvalidRequestMsg;
            else if (_store.GetClanByName(name) != null)    status = MediusCallbackStatus.MediusClanNameInUse;
            else
            {
                clan = _store.CreateClan(appId, name, me);
                status = MediusCallbackStatus.MediusSuccess;
            }
        }

        _log.LogInformation("[MLS] CreateClan '{Name}' by {Me} -> {Status} (id {Id})", name, me?.AccountName, status, clan?.ClanId);
        var w = new MediusWriter();
        WriteMlsHeader(w, packet, status);
        w.Write(clan?.ClanId ?? 0);
        return SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.CreateClanResponse, w.ToArray()), state, ct);
    }

    /// <summary>DisbandClan (0x56): SessionKey | pad2 | ClanID @40. Leader only.</summary>
    private Task HandleDisbandClanAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        int clanId = Int(packet.Payload, SessionBody);
        var me = Me(state);
        MediusCallbackStatus status;

        lock (_store.Sync)
        {
            var clan = _store.GetClanById(clanId != 0 ? clanId : me?.ClanId ?? 0);
            if (clan == null)                                  status = MediusCallbackStatus.MediusClanNotFound;
            else if (me == null || clan.LeaderAccountId != me.AccountId) status = MediusCallbackStatus.MediusNotClanLeader;
            else
            {
                clan.Status = MediusClanStatus.ClanDisbanded;
                foreach (var memberId in clan.Members)
                    if (_store.GetAccountById(memberId) is { } m && m.ClanId == clan.ClanId) m.ClanId = 0;
                clan.Members.Clear();
                foreach (var inv in _store.Invitations.Where(i => i.ClanId == clan.ClanId && i.Status == MediusClanInvitationsResponseStatus.ClanInvitationUndecided))
                    inv.Status = MediusClanInvitationsResponseStatus.ClanInvitationRevoked;
                _store.MarkDirty();
                status = MediusCallbackStatus.MediusSuccess;
            }
        }

        _log.LogInformation("[MLS] DisbandClan {Clan} by {Me} -> {Status}", clanId, me?.AccountName, status);
        return SendStatusAsync(packet, state, tcp, MediusLobbyMessageId.DisbandClanResponse, status, ct);
    }

    /// <summary>
    /// GetClanByID (0x58): SessionKey | pad2 | AccountID @40 | ClanID @44 → 0x59: header | AppID | ClanName[32] |
    /// LeaderAccountID | LeaderName[32] | Stats[256] | Status.
    /// </summary>
    private Task HandleGetClanByIdAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        int accountId = Int(packet.Payload, SessionBody), clanId = Int(packet.Payload, SessionBody + 4);
        var clan = _store.GetClanById(clanId) ?? _store.GetClanById(_store.GetAccountById(accountId)?.ClanId ?? 0);

        var w = new MediusWriter();
        WriteMlsHeader(w, packet, clan != null ? MediusCallbackStatus.MediusSuccess : MediusCallbackStatus.MediusClanNotFound);
        w.Write(clan?.AppId ?? 0);
        w.WriteString(clan?.ClanName ?? "", ClanNameLen);
        w.Write(clan?.LeaderAccountId ?? 0);
        w.WriteString(clan != null ? _store.GetAccountById(clan.LeaderAccountId)?.AccountName ?? "" : "", NameLen);
        w.Write(Fixed(clan?.Stats, StatsLen));
        w.Write((int)(clan?.Status ?? MediusClanStatus.ClanDisbanded));
        _log.LogInformation("[MLS] GetClanByID clan={Clan} acct={Acct} -> {Name}", clanId, accountId, clan?.ClanName ?? "(none)");
        return SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.GetClanByIDResponse, w.ToArray()), state, ct);
    }

    /// <summary>
    /// GetClanByName (0x5A): SessionKey | pad2 | AppID @40 | ClanName[32] @44 → 0x5B: header | ClanID |
    /// LeaderAccountID | LeaderName[32] | Stats[256] | Status.
    /// </summary>
    private Task HandleGetClanByNameAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        string name = Str(packet.Payload, SessionBody + 4, ClanNameLen);
        var clan = _store.GetClanByName(name);

        var w = new MediusWriter();
        WriteMlsHeader(w, packet, clan != null ? MediusCallbackStatus.MediusSuccess : MediusCallbackStatus.MediusClanNotFound);
        w.Write(clan?.ClanId ?? 0);
        w.Write(clan?.LeaderAccountId ?? 0);
        w.WriteString(clan != null ? _store.GetAccountById(clan.LeaderAccountId)?.AccountName ?? "" : "", NameLen);
        w.Write(Fixed(clan?.Stats, StatsLen));
        w.Write((int)(clan?.Status ?? MediusClanStatus.ClanDisbanded));
        _log.LogInformation("[MLS] GetClanByName '{Name}' -> {Id}", name, clan?.ClanId);
        return SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.GetClanByNameResponse, w.ToArray()), state, ct);
    }

    /// <summary>TransferClanLeadership (0x5C): SessionKey | pad2 | NewLeaderAccountID @40 | NewLeaderName[32] @44.</summary>
    private Task HandleTransferClanLeadershipAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        int newLeaderId = Int(packet.Payload, SessionBody);
        var me = Me(state);
        MediusCallbackStatus status;

        lock (_store.Sync)
        {
            var clan = me != null ? _store.GetClanById(me.ClanId) : null;
            if (clan == null)                              status = MediusCallbackStatus.MediusClanNotFound;
            else if (clan.LeaderAccountId != me!.AccountId) status = MediusCallbackStatus.MediusNotClanLeader;
            else if (!clan.Members.Contains(newLeaderId))  status = MediusCallbackStatus.MediusNotClanMember;
            else
            {
                clan.LeaderAccountId = newLeaderId;
                _store.MarkDirty();
                status = MediusCallbackStatus.MediusSuccess;
            }
        }

        _log.LogInformation("[MLS] TransferClanLeadership to {New} by {Me} -> {Status}", newLeaderId, me?.AccountName, status);
        return SendStatusAsync(packet, state, tcp, MediusLobbyMessageId.TransferClanLeadershipResponse, status, ct);
    }

    /// <summary>
    /// RemovePlayerFromClan (0x60): SessionKey | pad2 | PlayerAccountID @40 | ClanID @44. Removing yourself = leaving
    /// (the leader can't leave — disband or transfer first); removing someone else needs the leader.
    /// </summary>
    private Task HandleRemovePlayerFromClanAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        int playerId = Int(packet.Payload, SessionBody), clanId = Int(packet.Payload, SessionBody + 4);
        var me = Me(state);
        MediusCallbackStatus status;

        lock (_store.Sync)
        {
            var clan = _store.GetClanById(clanId != 0 ? clanId : me?.ClanId ?? 0);
            var player = _store.GetAccountById(playerId);
            if (clan == null)                                   status = MediusCallbackStatus.MediusClanNotFound;
            else if (me == null || player == null || !clan.Members.Contains(playerId)) status = MediusCallbackStatus.MediusNotClanMember;
            else if (playerId == clan.LeaderAccountId)          status = MediusCallbackStatus.MediusLeaderCannotLeaveClan;
            else if (playerId != me.AccountId && clan.LeaderAccountId != me.AccountId) status = MediusCallbackStatus.MediusNotClanLeader;
            else
            {
                clan.Members.Remove(playerId);
                player.ClanId = 0;
                _store.MarkDirty();
                status = MediusCallbackStatus.MediusSuccess;
            }
        }

        _log.LogInformation("[MLS] RemovePlayerFromClan {Player} clan={Clan} by {Me} -> {Status}", playerId, clanId, me?.AccountName, status);
        return SendStatusAsync(packet, state, tcp, MediusLobbyMessageId.RemovePlayerFromClanResponse, status, ct);
    }

    /// <summary>
    /// InvitePlayerToClan (0x62): SessionKey | pad2 | PlayerAccountID @40 | InviteMessage[200] @44.
    /// InvitePlayerToClan_ByName (0xEE): MessageID | AccountName[32] @21 | InviteMessage[200] @53 (no session key).
    /// Both reply InvitePlayerToClanResponse (0x63). Leader only.
    /// </summary>
    private Task HandleInvitePlayerToClanAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, bool byName, CancellationToken ct)
    {
        var p = packet.Payload;
        MediusAccount? target;
        string message;
        if (byName)
        {
            target  = _store.GetAccountByName(Str(p, MediusConstants.MESSAGEID_MAXLEN, NameLen));
            message = Str(p, MediusConstants.MESSAGEID_MAXLEN + NameLen, ClanMsgLen);
        }
        else
        {
            target  = _store.GetAccountById(Int(p, SessionBody));
            message = Str(p, SessionBody + 4, ClanMsgLen);
        }

        var me = Me(state);
        MediusCallbackStatus status;
        lock (_store.Sync)
        {
            var clan = me != null ? _store.GetClanById(me.ClanId) : null;
            if (clan == null)                                  status = MediusCallbackStatus.MediusClanNotFound;
            else if (clan.LeaderAccountId != me!.AccountId)    status = MediusCallbackStatus.MediusNotClanLeader;
            else if (target == null)                           status = MediusCallbackStatus.MediusAccountNotFound;
            else if (_store.GetClanById(target.ClanId) != null) status = MediusCallbackStatus.MediusInvalidRequestMsg;  // already in a clan
            else
            {
                bool pending = _store.Invitations.Any(i => i.ClanId == clan.ClanId && i.AccountId == target.AccountId
                    && i.Status == MediusClanInvitationsResponseStatus.ClanInvitationUndecided);
                if (!pending) _store.CreateInvitation(clan.ClanId, target.AccountId, message);
                status = MediusCallbackStatus.MediusSuccess;
            }
        }

        _log.LogInformation("[MLS] InvitePlayerToClan {Target} by {Me} -> {Status}", target?.AccountName, me?.AccountName, status);
        return SendStatusAsync(packet, state, tcp, MediusLobbyMessageId.InvitePlayerToClanResponse, status, ct);
    }

    /// <summary>
    /// CheckMyClanInvitations (0x64): SessionKey | pad2 | Start @40 | PageSize @44 → 0x65 rows: InvitationID | ClanID |
    /// ResponseStatus | Message[200] | LeaderAccountID | LeaderName[32] (282 B, retail size).
    /// </summary>
    private Task HandleCheckMyClanInvitationsAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var me = Me(state);
        var invitations = me == null ? new List<MediusClanInvitation>()
            : _store.Invitations.Where(i => i.AccountId == me.AccountId
                    && i.Status == MediusClanInvitationsResponseStatus.ClanInvitationUndecided
                    && _store.GetClanById(i.ClanId) != null)
                .OrderBy(i => i.InvitationId).ToList();
        var page = Page(invitations, Int(packet.Payload, SessionBody), Int(packet.Payload, SessionBody + 4));

        return SendListAsync(packet, state, tcp, MediusLobbyMessageId.CheckMyClanInvitationsResponse, page,
            4 + 4 + 4 + ClanMsgLen + 4 + NameLen, (w, i) =>
            {
                // The clan can be disbanded between the filter above and this row being written.
                var clan = _store.GetClanById(i.ClanId);
                w.Write(i.InvitationId);
                w.Write(i.ClanId);
                w.Write((int)i.Status);
                w.WriteString(i.Message, ClanMsgLen);
                w.Write(clan?.LeaderAccountId ?? 0);
                w.WriteString(clan != null ? _store.GetAccountById(clan.LeaderAccountId)?.AccountName ?? "" : "", NameLen);
            }, ct);
    }

    /// <summary>RespondToClanInvitation (0x66): SessionKey | pad2 | InvitationID @40 | Response @44 | Message[200] @48.</summary>
    private Task HandleRespondToClanInvitationAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var p = packet.Payload;
        int invitationId = Int(p, SessionBody);
        var response = (MediusClanInvitationsResponseStatus)Int(p, SessionBody + 4);
        string message = Str(p, SessionBody + 8, ClanMsgLen);
        var me = Me(state);
        MediusCallbackStatus status;

        lock (_store.Sync)
        {
            var inv = _store.GetInvitation(invitationId);
            var clan = inv != null ? _store.GetClanById(inv.ClanId) : null;
            if (inv == null || me == null || inv.AccountId != me.AccountId
                || inv.Status != MediusClanInvitationsResponseStatus.ClanInvitationUndecided)
                status = MediusCallbackStatus.MediusInvalidRequestMsg;
            else if (clan == null)
                status = MediusCallbackStatus.MediusClanNotFound;
            else if (response == MediusClanInvitationsResponseStatus.ClanInvitationAccept && _store.GetClanById(me.ClanId) != null)
                status = MediusCallbackStatus.MediusInvalidRequestMsg;   // already in a clan
            else
            {
                inv.Status = response;
                inv.ResponseMessage = message;
                inv.ResponseTime = DateTime.UtcNow;
                if (response == MediusClanInvitationsResponseStatus.ClanInvitationAccept)
                {
                    if (!clan.Members.Contains(me.AccountId)) clan.Members.Add(me.AccountId);
                    me.ClanId = clan.ClanId;
                }
                _store.MarkDirty();
                status = MediusCallbackStatus.MediusSuccess;
            }
        }

        _log.LogInformation("[MLS] RespondToClanInvitation {Inv} {Response} by {Me} -> {Status}", invitationId, response, me?.AccountName, status);
        return SendStatusAsync(packet, state, tcp, MediusLobbyMessageId.RespondToClanInvitationResponse, status, ct);
    }

    /// <summary>RevokeClanInvitation (0x68): SessionKey | pad2 | PlayerAccountID @40. Leader only.</summary>
    private Task HandleRevokeClanInvitationAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        int playerId = Int(packet.Payload, SessionBody);
        var me = Me(state);
        MediusCallbackStatus status;

        lock (_store.Sync)
        {
            var clan = me != null ? _store.GetClanById(me.ClanId) : null;
            if (clan == null)                               status = MediusCallbackStatus.MediusClanNotFound;
            else if (clan.LeaderAccountId != me!.AccountId) status = MediusCallbackStatus.MediusNotClanLeader;
            else
            {
                foreach (var inv in _store.Invitations.Where(i => i.ClanId == clan.ClanId && i.AccountId == playerId
                             && i.Status == MediusClanInvitationsResponseStatus.ClanInvitationUndecided))
                    inv.Status = MediusClanInvitationsResponseStatus.ClanInvitationRevoked;
                _store.MarkDirty();
                status = MediusCallbackStatus.MediusSuccess;
            }
        }

        _log.LogInformation("[MLS] RevokeClanInvitation {Player} by {Me} -> {Status}", playerId, me?.AccountName, status);
        return SendStatusAsync(packet, state, tcp, MediusLobbyMessageId.RevokeClanInvitationResponse, status, ct);
    }

    /// <summary>
    /// GetClanInvitationsSent (0x7A): SessionKey | pad2 | Start @40 | PageSize @44 → 0x7B rows: AccountID | Name[32] |
    /// ResponseMsg[200] | ResponseStatus | ResponseTime.
    /// </summary>
    private Task HandleGetClanInvitationsSentAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var clan = Me(state) is { } me ? _store.GetClanById(me.ClanId) : null;
        var sent = clan == null ? new List<MediusClanInvitation>()
            : _store.Invitations.Where(i => i.ClanId == clan.ClanId).OrderBy(i => i.InvitationId).ToList();
        var page = Page(sent, Int(packet.Payload, SessionBody), Int(packet.Payload, SessionBody + 4));

        return SendListAsync(packet, state, tcp, MediusLobbyMessageId.GetClanInvitationsSentResponse, page,
            4 + NameLen + ClanMsgLen + 4 + 4, (w, i) =>
            {
                w.Write(i.AccountId);
                w.WriteString(_store.GetAccountById(i.AccountId)?.AccountName ?? "", NameLen);
                w.WriteString(i.ResponseMessage, ClanMsgLen);
                w.Write((int)i.Status);
                w.Write(i.ResponseTime == default ? 0 : (int)new DateTimeOffset(i.ResponseTime).ToUnixTimeSeconds());
            }, ct);
    }

    /// <summary>
    /// GetClanMemberList_ExtraInfo (0xDA): MessageID | pad3 | ClanID @24 | LadderStatIndex @28 | SortOrder @32 →
    /// 0xDB rows: AccountID | Name[32] | Stats[256] | OnlineState | LadderStat | LadderPosition | TotalRankings.
    /// </summary>
    private Task HandleGetClanMemberListAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var p = packet.Payload;
        int clanId = Int(p, Pad3Body), statIndex = Int(p, Pad3Body + 4), sortOrder = Int(p, Pad3Body + 8);
        var clan = _store.GetClanById(clanId) ?? (Me(state) is { } me ? _store.GetClanById(me.ClanId) : null);
        var ranked = RankedPlayers(statIndex, sortOrder);
        var members = clan == null ? new List<MediusAccount>()
            : Snapshot(clan.Members).Select(_store.GetAccountById).OfType<MediusAccount>()
                .OrderBy(a => a.AccountId == clan.LeaderAccountId ? 0 : 1).ThenBy(a => a.AccountName).ToList();

        _log.LogInformation("[MLS] GetClanMemberList clan={Clan} -> {Count}", clanId, members.Count);
        return SendListAsync(packet, state, tcp, MediusLobbyMessageId.GetClanMemberList_ExtraInfoResponse, members,
            4 + NameLen + StatsLen + OnlineStateSize + 4 + 4 + 4, (w, a) =>
            {
                w.Write(a.AccountId);
                w.WriteString(a.AccountName, NameLen);
                w.Write(Fixed(a.AccountStats, StatsLen));
                WriteOnlineState(w, a.AccountId);
                w.Write(StatOf(a.LadderStats, statIndex));
                w.Write(ranked.FindIndex(r => r.AccountId == a.AccountId) + 1);
                w.Write(ranked.Count);
            }, ct);
    }

    /// <summary>GetMyClanMessages (0x6C): SessionKey | pad2 | ClanID @40 | Start @44 | PageSize @48 → 0x6D rows: ClanID | Message[200].</summary>
    private Task HandleGetMyClanMessagesAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var p = packet.Payload;
        // Clan messages are for members: a request for another clan's board gets nothing.
        var me = Me(state);
        var requested = _store.GetClanById(Int(p, SessionBody)) ?? (me != null ? _store.GetClanById(me.ClanId) : null);
        var clan = requested != null && me != null && Snapshot(requested.Members).Contains(me.AccountId) ? requested : null;
        var messages = clan == null ? new List<MediusClanMessage>()
            : Snapshot(clan.Messages).Where(m => m.Status != MediusClanMessageStatus.ClanMessageDeleted).OrderByDescending(m => m.MessageId).ToList();
        var page = Page(messages, Int(p, SessionBody + 4), Int(p, SessionBody + 8));

        return SendListAsync(packet, state, tcp, MediusLobbyMessageId.GetMyClanMessagesResponse, page,
            4 + ClanMsgLen, (w, m) =>
            {
                w.Write(clan!.ClanId);
                w.WriteString(m.Text, ClanMsgLen);
            }, ct);
    }

    /// <summary>GetAllClanMessages (0x7E): SessionKey | pad2 | Start @40 | PageSize @44 → 0x7F rows: ClanMessageID | Message[200] | Status.</summary>
    private Task HandleGetAllClanMessagesAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var clan = Me(state) is { } me ? _store.GetClanById(me.ClanId) : null;
        var messages = clan == null ? new List<MediusClanMessage>()
            : Snapshot(clan.Messages).OrderByDescending(m => m.MessageId).ToList();
        var page = Page(messages, Int(packet.Payload, SessionBody), Int(packet.Payload, SessionBody + 4));

        return SendListAsync(packet, state, tcp, MediusLobbyMessageId.GetAllClanMessagesResponse, page,
            4 + ClanMsgLen + 4, (w, m) =>
            {
                w.Write(m.MessageId);
                w.WriteString(m.Text, ClanMsgLen);
                w.Write((int)m.Status);
            }, ct);
    }

    /// <summary>SendClanMessage (0x6E): MessageID | SessionKey[17] | Message[200] @38 (no pad). Leader only.</summary>
    private Task HandleSendClanMessageAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        string text = Str(packet.Payload, MediusConstants.MESSAGEID_MAXLEN + MediusConstants.SESSIONKEY_MAXLEN, ClanMsgLen);
        var me = Me(state);
        MediusCallbackStatus status;

        lock (_store.Sync)
        {
            var clan = me != null ? _store.GetClanById(me.ClanId) : null;
            if (clan == null)                               status = MediusCallbackStatus.MediusClanNotFound;
            else if (clan.LeaderAccountId != me!.AccountId) status = MediusCallbackStatus.MediusNotClanLeader;
            else
            {
                clan.Messages.Add(new MediusClanMessage { MessageId = _store.NextClanMessageId(), Text = text });
                _store.MarkDirty();
                status = MediusCallbackStatus.MediusSuccess;
            }
        }

        _log.LogInformation("[MLS] SendClanMessage by {Me} -> {Status}: '{Text}'", me?.AccountName, status, text);
        return SendStatusAsync(packet, state, tcp, MediusLobbyMessageId.SendClanMessageResponse, status, ct);
    }

    /// <summary>ModifyClanMessage (0x70): ClanMessageID @40 | NewMessage[200] @44; DeleteClanMessage (0x72): ClanMessageID @40. Leader only.</summary>
    private Task HandleModifyClanMessageAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, bool delete, CancellationToken ct)
    {
        int messageId = Int(packet.Payload, SessionBody);
        var me = Me(state);
        MediusCallbackStatus status;

        lock (_store.Sync)
        {
            var clan = me != null ? _store.GetClanById(me.ClanId) : null;
            var msg = clan?.Messages.FirstOrDefault(m => m.MessageId == messageId
                                                      && m.Status != MediusClanMessageStatus.ClanMessageDeleted);
            if (clan == null)                               status = MediusCallbackStatus.MediusClanNotFound;
            else if (clan.LeaderAccountId != me!.AccountId) status = MediusCallbackStatus.MediusNotClanLeader;
            else if (msg == null)                           status = MediusCallbackStatus.MediusNoResult;
            else
            {
                if (delete) msg.Status = MediusClanMessageStatus.ClanMessageDeleted;
                else
                {
                    msg.Text = Str(packet.Payload, SessionBody + 4, ClanMsgLen);
                    msg.Status = MediusClanMessageStatus.ClanMessageModified;
                }
                _store.MarkDirty();
                status = MediusCallbackStatus.MediusSuccess;
            }
        }

        return SendStatusAsync(packet, state, tcp,
            delete ? MediusLobbyMessageId.DeleteClanMessageResponse : MediusLobbyMessageId.ModifyClanMessageResponse, status, ct);
    }

    /// <summary>UpdateClanStats (0x84): SessionKey | pad2 | ClanID @40 | Stats[256] @44. Members only.</summary>
    private Task HandleUpdateClanStatsAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        int clanId = Int(packet.Payload, SessionBody);
        var me = Me(state);
        MediusCallbackStatus status;

        lock (_store.Sync)
        {
            var clan = _store.GetClanById(clanId);
            if (clan == null)                                       status = MediusCallbackStatus.MediusClanNotFound;
            else if (me == null || !clan.Members.Contains(me.AccountId)) status = MediusCallbackStatus.MediusNotClanMember;
            else
            {
                clan.Stats = Fixed(packet.Payload.Length >= SessionBody + 4 + StatsLen
                    ? packet.Payload.AsSpan(SessionBody + 4, StatsLen).ToArray() : null, StatsLen);
                _store.MarkDirty();
                status = MediusCallbackStatus.MediusSuccess;
            }
        }
        return SendStatusAsync(packet, state, tcp, MediusLobbyMessageId.UpdateClanStatsResponse, status, ct);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private MediusAccount? Me(MediusClientState state) =>
        state.AccountId is int id ? _store.GetAccountById(id) : null;

    /// <summary>
    /// A Medius list reply: one message per row = header (Success) | body | EndOfList | pad3, EndOfList set on the
    /// last row. No rows = one full-size message with StatusCode NoResult, a zeroed body and EndOfList = 1, so the
    /// client's parser never reads past the payload.
    /// </summary>
    private async Task SendListAsync<T>(MediusPacket packet, MediusClientState state, TcpClient tcp,
        MediusLobbyMessageId responseType, IReadOnlyList<T> rows, int bodySize, Action<MediusWriter, T> writeBody,
        CancellationToken ct)
    {
        if (rows.Count == 0)
        {
            var w = new MediusWriter();
            WriteMlsHeader(w, packet, MediusCallbackStatus.MediusNoResult);
            w.WritePadding(bodySize);
            w.Write((byte)1);
            w.WritePadding(3);
            await SendMediusAsync(tcp, MediusPacket.BuildLobby(responseType, w.ToArray()), state, ct);
            return;
        }

        for (int i = 0; i < rows.Count; i++)
        {
            var w = new MediusWriter();
            WriteMlsHeader(w, packet, MediusCallbackStatus.MediusSuccess);
            writeBody(w, rows[i]);
            w.Write((byte)(i == rows.Count - 1 ? 1 : 0));
            w.WritePadding(3);
            await SendMediusAsync(tcp, MediusPacket.BuildLobby(responseType, w.ToArray()), state, ct);
        }
    }

    /// <summary>Header-only reply: MessageID echo | pad3 | StatusCode (30 B on the wire).</summary>
    private Task SendStatusAsync(MediusPacket packet, MediusClientState state, TcpClient tcp,
        MediusLobbyMessageId responseType, MediusCallbackStatus status, CancellationToken ct)
    {
        var w = new MediusWriter();
        WriteMlsHeader(w, packet, status);
        return SendMediusAsync(tcp, MediusPacket.BuildLobby(responseType, w.ToArray()), state, ct);
    }

    /// <summary>MediusPlayerOnlineState (140 B): ConnectStatus | LobbyWorldID | GameWorldID | LobbyName[64] | GameName[64].</summary>
    private void WriteOnlineState(MediusWriter w, int accountId)
    {
        var p = _presence.Get(accountId);
        w.Write((int)(p?.Status ?? MediusPlayerStatus.MediusPlayerDisconnected));
        w.Write(p?.LobbyWorldId ?? 0);
        w.Write(p?.GameWorldId ?? 0);
        w.WriteString(p?.LobbyName ?? "", WorldNameLen);
        w.WriteString(p?.GameName ?? "", WorldNameLen);
    }

    /// <summary>List paging: Start is 1-based (0 is treated as 1); PageSize ≤ 0 = everything.</summary>
    private static List<T> Page<T>(List<T> rows, int start, int pageSize) =>
        rows.Skip(Math.Max(0, start - 1)).Take(pageSize <= 0 ? int.MaxValue : pageSize).ToList();

    /// <summary>Exactly <paramref name="length"/> bytes (zero-padded / truncated copy).</summary>
    private static byte[] Fixed(byte[]? src, int length)
    {
        var dst = new byte[length];
        if (src != null) Buffer.BlockCopy(src, 0, dst, 0, Math.Min(src.Length, length));
        return dst;
    }

    private static int Int(byte[] p, int offset) =>
        offset + 4 <= p.Length ? BitConverter.ToInt32(p, offset) : 0;

    private static string Str(byte[] p, int offset, int maxLength)
    {
        if (offset >= p.Length) return string.Empty;
        int end = offset, limit = Math.Min(p.Length, offset + maxLength);
        while (end < limit && p[end] != 0) end++;
        return System.Text.Encoding.ASCII.GetString(p, offset, end - offset);
    }
}
