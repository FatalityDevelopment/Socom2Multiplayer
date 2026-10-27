using System.Collections.Concurrent;
using CodeDesigner.Ps2.Multiplayer.Protocol;

namespace CodeDesigner.Ps2.Multiplayer.Storage;

/// <summary>
/// Where each online account is — the MediusPlayerOnlineState shown in buddy, ladder and clan rows.
/// Fed by MLS (lobby / briefing-room connections, JoinGame) and DME (leaving a game world).
/// </summary>
public class PresenceRegistry
{
    public sealed record Presence(
        MediusPlayerStatus Status, int LobbyWorldId, string LobbyName, int GameWorldId, string GameName);

    private sealed class Entry
    {
        public int Connections;
        /// <summary>Debug-API virtual player: no connection behind it, stays until removed explicitly.</summary>
        public bool IsVirtual;
        public Presence State = new(MediusPlayerStatus.MediusPlayerInChatWorld, 0, "", 0, "");
    }

    private readonly ConcurrentDictionary<int, Entry> _online = new();

    /// <summary>An MLS connection for this account came up (community screen or a briefing room).</summary>
    public void Connected(int accountId, int lobbyWorldId, string lobbyName)
    {
        var e = _online.GetOrAdd(accountId, _ => new Entry());
        lock (e)
        {
            e.Connections++;
            e.State = new Presence(MediusPlayerStatus.MediusPlayerInChatWorld, lobbyWorldId, lobbyName, 0, "");
        }
    }

    /// <summary>An MLS connection for this account closed; the account is offline once none remain.</summary>
    public void Disconnected(int accountId)
    {
        if (!_online.TryGetValue(accountId, out var e)) return;
        lock (e)
        {
            if (e.IsVirtual) return;
            if (--e.Connections <= 0) _online.TryRemove(accountId, out _);
        }
    }

    /// <summary>
    /// Put a virtual player into a lobby (debug API): it shows up in the briefing-room player list, the room's
    /// player count and FindPlayer like a real player, without a console behind it. Re-adding moves it.
    /// </summary>
    public void AddVirtual(int accountId, int lobbyWorldId, string lobbyName)
    {
        var e = _online.GetOrAdd(accountId, _ => new Entry());
        lock (e)
        {
            e.IsVirtual = true;
            e.State = new Presence(MediusPlayerStatus.MediusPlayerInChatWorld, lobbyWorldId, lobbyName, 0, "");
        }
    }

    /// <summary>Remove a virtual player. False when the account is not a virtual player.</summary>
    public bool RemoveVirtual(int accountId)
    {
        if (!_online.TryGetValue(accountId, out var e)) return false;
        lock (e)
        {
            if (!e.IsVirtual) return false;
            return _online.TryRemove(accountId, out _);
        }
    }

    public bool IsVirtual(int accountId) => _online.TryGetValue(accountId, out var e) && e.IsVirtual;

    /// <summary>Every online account with its presence (debug reports).</summary>
    public List<(int AccountId, Presence State, bool IsVirtual)> Snapshot() =>
        _online.Select(kv => (kv.Key, kv.Value.State, kv.Value.IsVirtual)).ToList();

    public void JoinedGame(int accountId, int gameWorldId, string gameName)
    {
        if (!_online.TryGetValue(accountId, out var e)) return;
        lock (e) e.State = e.State with { Status = MediusPlayerStatus.MediusPlayerInGameWorld, GameWorldId = gameWorldId, GameName = gameName };
    }

    public void LeftGame(int accountId)
    {
        if (!_online.TryGetValue(accountId, out var e)) return;
        lock (e) e.State = e.State with { Status = MediusPlayerStatus.MediusPlayerInChatWorld, GameWorldId = 0, GameName = "" };
    }

    /// <summary>Current presence, or null when the account is offline.</summary>
    public Presence? Get(int accountId) =>
        _online.TryGetValue(accountId, out var e) ? e.State : null;

    public bool IsOnline(int accountId) => _online.ContainsKey(accountId);

    /// <summary>Number of accounts currently online (universe list player count).</summary>
    public int OnlineCount => _online.Count;

    /// <summary>Online accounts whose lobby is <paramref name="lobbyWorldId"/> (a briefing room, or 1 = community).</summary>
    public List<int> AccountsInLobby(int lobbyWorldId) =>
        _online.Where(kv => kv.Value.State.LobbyWorldId == lobbyWorldId).Select(kv => kv.Key).ToList();
}
