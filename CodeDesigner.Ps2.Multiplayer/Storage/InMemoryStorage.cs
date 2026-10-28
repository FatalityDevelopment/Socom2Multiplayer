using System.Collections.Concurrent;
using System.Text.Json;
using CodeDesigner.Ps2.Multiplayer.Config;
using CodeDesigner.Ps2.Multiplayer.Models;
using CodeDesigner.Ps2.Multiplayer.Protocol;
using Microsoft.Extensions.Logging;

namespace CodeDesigner.Ps2.Multiplayer.Storage;

/// <summary>
/// Thread-safe store for accounts, channels, games, sessions and clans.
/// Accounts (with stats, friends/ignore lists) and clans persist to a JSON snapshot in
/// <see cref="MultiplayerConfig.DataDirectory"/>; channels, games and sessions are runtime-only.
/// </summary>
public class InMemoryStorage : IMultiplayerStorage, IDisposable
{
    private const string SnapshotFile = "server-data.json";

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly ILogger<InMemoryStorage>? _log;
    private readonly string? _snapshotPath;
    private readonly Timer? _saveTimer;
    private int _dirty;

    /// <summary>Debounce for snapshot writes, and the longest a change may wait under constant activity.</summary>
    private static readonly TimeSpan SaveDebounce = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan MaxSaveDelay = TimeSpan.FromSeconds(30);
    private long _firstDirtyTicks;   // when the pending (unsaved) changes started; 0 = nothing pending

    /// <summary>Lock for multi-step social/clan mutations (friends, ignores, clan membership, invitations).</summary>
    public object Sync { get; } = new();

    public InMemoryStorage() { }

    public InMemoryStorage(MultiplayerConfig config, ILogger<InMemoryStorage> log)
    {
        _log = log;
        var dir = string.IsNullOrWhiteSpace(config.DataDirectory)
            ? Path.Combine(AppContext.BaseDirectory, "data")
            : config.DataDirectory;
        Directory.CreateDirectory(dir);
        _snapshotPath = Path.Combine(dir, SnapshotFile);
        _saveTimer = new Timer(_ => SaveIfDirty(), null, Timeout.Infinite, Timeout.Infinite);
        Load();
    }

    // -------------------------------------------------------------------------
    // Accounts
    // -------------------------------------------------------------------------
    private readonly ConcurrentDictionary<int, MediusAccount> _accountsById = new();
    private readonly ConcurrentDictionary<string, MediusAccount> _accountsByName = new(StringComparer.OrdinalIgnoreCase);
    private int _nextAccountId = 1;

    public IEnumerable<MediusAccount> Accounts => _accountsById.Values;

    public MediusAccount? GetAccountById(int id) =>
        _accountsById.TryGetValue(id, out var a) ? a : null;

    public MediusAccount? GetAccountByName(string name) =>
        _accountsByName.TryGetValue(name, out var a) ? a : null;

    private readonly object _accountCreateLock = new();

    /// <summary>
    /// Create an account named <paramref name="name"/>, or return null when the name is taken. Checking and
    /// creating happen under one lock, so two logins racing on a new name can't both create it.
    /// </summary>
    public MediusAccount? TryCreateAccount(string name, string passwordHash)
    {
        lock (_accountCreateLock)
        {
            if (_accountsByName.ContainsKey(name)) return null;
            var account = new MediusAccount
            {
                AccountId = Interlocked.Increment(ref _nextAccountId),
                AccountName = name,
                PasswordHash = passwordHash,
            };
            _accountsById[account.AccountId] = account;
            _accountsByName[account.AccountName] = account;
            MarkDirty();
            return account;
        }
    }

    /// <summary>The account named <paramref name="name"/>, creating it (with <paramref name="passwordHash"/>) if missing.</summary>
    public MediusAccount GetOrCreateAccount(string name, string passwordHash, out bool created)
    {
        var account = TryCreateAccount(name, passwordHash);
        created = account != null;
        return account ?? GetAccountByName(name)!;
    }

    // -------------------------------------------------------------------------
    // Sessions (runtime) — MAS issues the session key at login; MLS/DME connections present it back.
    // -------------------------------------------------------------------------
    private readonly ConcurrentDictionary<string, int> _accountBySession = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Map <paramref name="sessionKey"/> to the account. A fresh login (<paramref name="replaceOthers"/>) also drops
    /// the account's older keys, so keys from earlier sessions stop working and the table stays one key per login.
    /// </summary>
    public void RegisterSession(string sessionKey, int accountId, bool replaceOthers = false)
    {
        if (string.IsNullOrEmpty(sessionKey)) return;
        if (replaceOthers)
            foreach (var (key, id) in _accountBySession)
                if (id == accountId && !key.Equals(sessionKey, StringComparison.OrdinalIgnoreCase))
                    _accountBySession.TryRemove(new KeyValuePair<string, int>(key, id));
        _accountBySession[sessionKey] = accountId;
    }

    /// <summary>Forget a session key (logout, or the connection that owned it closed).</summary>
    public void RevokeSession(string? sessionKey)
    {
        if (!string.IsNullOrEmpty(sessionKey)) _accountBySession.TryRemove(sessionKey, out _);
    }

    /// <summary>True when <paramref name="sessionKey"/> is registered to <paramref name="accountId"/>.</summary>
    public bool IsSessionOf(string? sessionKey, int accountId) =>
        !string.IsNullOrEmpty(sessionKey) && _accountBySession.TryGetValue(sessionKey, out var id) && id == accountId;

    public MediusAccount? GetAccountBySession(string? sessionKey) =>
        !string.IsNullOrEmpty(sessionKey) && _accountBySession.TryGetValue(sessionKey, out var id) ? GetAccountById(id) : null;

    // -------------------------------------------------------------------------
    // Clans
    // -------------------------------------------------------------------------
    private readonly ConcurrentDictionary<int, MediusClan> _clansById = new();
    private readonly ConcurrentDictionary<int, MediusClanInvitation> _invitationsById = new();
    private int _nextClanId;
    private int _nextInvitationId;
    private int _nextClanMessageId;

    public IEnumerable<MediusClan> Clans => _clansById.Values.Where(c => c.Status == MediusClanStatus.ClanActive);
    public IEnumerable<MediusClanInvitation> Invitations => _invitationsById.Values;

    public MediusClan? GetClanById(int id) =>
        _clansById.TryGetValue(id, out var c) && c.Status == MediusClanStatus.ClanActive ? c : null;

    public MediusClan? GetClanByName(string name) =>
        Clans.FirstOrDefault(c => c.ClanName.Equals(name, StringComparison.OrdinalIgnoreCase));

    /// <summary>Create a clan led (and joined) by <paramref name="leader"/>. Caller holds <see cref="Sync"/>.</summary>
    public MediusClan CreateClan(int appId, string name, MediusAccount leader)
    {
        var clan = new MediusClan
        {
            ClanId = Interlocked.Increment(ref _nextClanId),
            AppId = appId,
            ClanName = name,
            LeaderAccountId = leader.AccountId,
            Members = { leader.AccountId },
        };
        _clansById[clan.ClanId] = clan;
        leader.ClanId = clan.ClanId;
        MarkDirty();
        return clan;
    }

    public MediusClanInvitation CreateInvitation(int clanId, int accountId, string message)
    {
        var inv = new MediusClanInvitation
        {
            InvitationId = Interlocked.Increment(ref _nextInvitationId),
            ClanId = clanId,
            AccountId = accountId,
            Message = message,
        };
        _invitationsById[inv.InvitationId] = inv;
        MarkDirty();
        return inv;
    }

    public MediusClanInvitation? GetInvitation(int id) =>
        _invitationsById.TryGetValue(id, out var i) ? i : null;

    public int NextClanMessageId() => Interlocked.Increment(ref _nextClanMessageId);

    // -------------------------------------------------------------------------
    // Channels
    // -------------------------------------------------------------------------
    private readonly ConcurrentDictionary<int, MediusChannel> _channelsById = new();
    private int _nextChannelId = 1;

    public IEnumerable<MediusChannel> GetChannels(int appId) =>
        _channelsById.Values.Where(c => c.AppId == appId);

    public MediusChannel? GetChannelById(int id) =>
        _channelsById.TryGetValue(id, out var c) ? c : null;

    public MediusChannel GetOrCreateDefaultChannel(int appId)
    {
        var existing = _channelsById.Values.FirstOrDefault(c => c.AppId == appId);
        if (existing != null) return existing;

        var channel = new MediusChannel
        {
            ChannelId = Interlocked.Increment(ref _nextChannelId),
            ChannelName = "Lobby",
            MaxPlayers = 256,
            AppId = appId,
        };
        _channelsById[channel.ChannelId] = channel;
        return channel;
    }

    /// <summary>Channel with a fixed id (e.g. a retail briefing room's MediusWorldID), created on first use.</summary>
    public MediusChannel GetOrCreateChannel(int channelId, string name, int appId, int maxPlayers = 256)
    {
        var channel = _channelsById.GetOrAdd(channelId, id => new MediusChannel
        {
            ChannelId = id,
            ChannelName = name,
            MaxPlayers = maxPlayers,
            AppId = appId,
        });

        // Keep auto-assigned ids clear of explicitly seeded ones.
        int current;
        while ((current = Volatile.Read(ref _nextChannelId)) < channelId
               && Interlocked.CompareExchange(ref _nextChannelId, channelId, current) != current) { }

        return channel;
    }

    public MediusChannel CreateChannel(string name, int appId, int maxPlayers = 256)
    {
        var channel = new MediusChannel
        {
            ChannelId = Interlocked.Increment(ref _nextChannelId),
            ChannelName = name,
            MaxPlayers = maxPlayers,
            AppId = appId,
        };
        _channelsById[channel.ChannelId] = channel;
        return channel;
    }

    // -------------------------------------------------------------------------
    // Games
    // -------------------------------------------------------------------------
    private readonly ConcurrentDictionary<int, MediusGame> _gamesById = new();
    private int _nextGameId = 1;

    public IEnumerable<MediusGame> GetGames(int appId) =>
        _gamesById.Values.Where(g => g.AppId == appId && g.Status != GameWorldStatus.WorldInactive);

    /// <summary>Every game, including ones whose host reported them inactive (housekeeping).</summary>
    public IEnumerable<MediusGame> AllGames => _gamesById.Values;

    public MediusGame? GetGameById(int id) =>
        _gamesById.TryGetValue(id, out var g) ? g : null;

    public MediusGame CreateGame(string name, int appId, int hostAccountId, string hostName, int maxPlayers)
    {
        var game = new MediusGame
        {
            GameId = Interlocked.Increment(ref _nextGameId),
            GameName = name,
            AppId = appId,
            HostAccountId = hostAccountId,
            HostName = hostName,
            MaxPlayers = maxPlayers,
            Status = GameWorldStatus.WorldStaging,
        };
        _gamesById[game.GameId] = game;
        return game;
    }

    public bool RemoveGame(int gameId) => _gamesById.TryRemove(gameId, out _);

    // -------------------------------------------------------------------------
    // Persistence (JSON snapshot)
    // -------------------------------------------------------------------------

    private sealed class Snapshot
    {
        public int NextAccountId { get; set; }
        public int NextClanId { get; set; }
        public int NextInvitationId { get; set; }
        public int NextClanMessageId { get; set; }
        public List<MediusAccount> Accounts { get; set; } = new();
        public List<MediusClan> Clans { get; set; } = new();
        public List<MediusClanInvitation> Invitations { get; set; } = new();
    }

    /// <summary>
    /// Schedule a snapshot write (debounced — many changes in a burst cost one write). Under constant activity the
    /// debounce would keep moving, so a write is forced once changes have waited <see cref="MaxSaveDelay"/>.
    /// </summary>
    public void MarkDirty()
    {
        if (_saveTimer == null) return;
        Interlocked.Exchange(ref _dirty, 1);
        long now = DateTime.UtcNow.Ticks;
        Interlocked.CompareExchange(ref _firstDirtyTicks, now, 0);
        var waited = TimeSpan.FromTicks(now - Interlocked.Read(ref _firstDirtyTicks));
        var delay  = waited >= MaxSaveDelay ? TimeSpan.Zero : SaveDebounce;
        try { _saveTimer.Change(delay, Timeout.InfiniteTimeSpan); }
        catch (ObjectDisposedException) { /* shutting down: Dispose writes the snapshot */ }
    }

    /// <summary>Write the snapshot now if anything changed.</summary>
    public void Flush() => SaveIfDirty();

    private void SaveIfDirty()
    {
        if (_snapshotPath == null || Interlocked.Exchange(ref _dirty, 0) == 0) return;
        Interlocked.Exchange(ref _firstDirtyTicks, 0);
        try
        {
            string json;
            lock (Sync)
            {
                // Serialized while holding Sync: the friend/ignore/clan lists only change under it.
                json = JsonSerializer.Serialize(new Snapshot
                {
                    NextAccountId     = Volatile.Read(ref _nextAccountId),
                    NextClanId        = Volatile.Read(ref _nextClanId),
                    NextInvitationId  = Volatile.Read(ref _nextInvitationId),
                    NextClanMessageId = Volatile.Read(ref _nextClanMessageId),
                    Accounts          = _accountsById.Values.OrderBy(a => a.AccountId).ToList(),
                    Clans             = _clansById.Values.OrderBy(c => c.ClanId).ToList(),
                    Invitations       = _invitationsById.Values.OrderBy(i => i.InvitationId).ToList(),
                }, JsonOptions);
            }
            // Keep the previous good snapshot as .bak: Load falls back to it if the main file is ever unreadable.
            if (File.Exists(_snapshotPath))
                File.Copy(_snapshotPath, _snapshotPath + ".bak", overwrite: true);
            AtomicFile.WriteAllText(_snapshotPath, json);
        }
        catch (Exception ex)
        {
            _log?.LogError(ex, "[Store] Saving {Path} failed — retrying", _snapshotPath);
            // Re-arm (slowly), or the changes would wait for the next unrelated write.
            Interlocked.Exchange(ref _dirty, 1);
            try { _saveTimer?.Change(MaxSaveDelay, Timeout.InfiniteTimeSpan); }
            catch (ObjectDisposedException) { /* shutting down */ }
        }
    }

    private void Load()
    {
        if (_snapshotPath == null) return;
        var snap = ReadSnapshot(_snapshotPath) ?? ReadSnapshot(_snapshotPath + ".bak");
        if (snap == null) return;

        foreach (var a in snap.Accounts)
        {
            _accountsById[a.AccountId] = a;
            _accountsByName[a.AccountName] = a;
        }
        foreach (var c in snap.Clans) _clansById[c.ClanId] = c;
        foreach (var i in snap.Invitations) _invitationsById[i.InvitationId] = i;

        _nextAccountId     = Math.Max(snap.NextAccountId, _accountsById.Keys.DefaultIfEmpty(1).Max());
        _nextClanId        = Math.Max(snap.NextClanId, _clansById.Keys.DefaultIfEmpty(0).Max());
        _nextInvitationId  = Math.Max(snap.NextInvitationId, _invitationsById.Keys.DefaultIfEmpty(0).Max());
        _nextClanMessageId = Math.Max(snap.NextClanMessageId,
            _clansById.Values.SelectMany(c => c.Messages).Select(m => m.MessageId).DefaultIfEmpty(0).Max());

        _log?.LogInformation("[Store] Loaded {Accounts} accounts, {Clans} clans from {Path}",
            _accountsById.Count, _clansById.Count, _snapshotPath);
    }

    /// <summary>Read one snapshot file; null if it is missing or unreadable (logged).</summary>
    private Snapshot? ReadSnapshot(string path)
    {
        if (!File.Exists(path)) return null;
        try
        {
            var snap = JsonSerializer.Deserialize<Snapshot>(File.ReadAllText(path), JsonOptions);
            if (snap != null && path.EndsWith(".bak", StringComparison.Ordinal))
                _log?.LogWarning("[Store] Main snapshot unreadable — restored from {Path}", path);
            return snap;
        }
        catch (Exception ex) when (ex is JsonException or IOException or NotSupportedException)
        {
            _log?.LogError("[Store] {Path} is unreadable: {Msg}", path, ex.Message);
            // Keep the bad file for inspection; the next save would overwrite it.
            try { File.Copy(path, path + ".corrupt-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss"), overwrite: true); }
            catch (IOException) { /* best effort */ }
            return null;
        }
    }

    public void Dispose()
    {
        _saveTimer?.Dispose();
        SaveIfDirty();
    }
}
