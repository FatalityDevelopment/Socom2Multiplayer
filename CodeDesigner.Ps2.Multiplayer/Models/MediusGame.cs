namespace CodeDesigner.Ps2.Multiplayer.Models;

public enum GameWorldStatus
{
    WorldInactive          = 0,
    WorldStaging           = 1,
    WorldActive            = 2,
    WorldClosed            = 3,
    WorldPendingCreation   = 4,
}

/// <summary>A game session (world) that players can create or join.</summary>
public class MediusGame
{
    public int             GameId         { get; set; }
    public string          GameName       { get; set; } = string.Empty;
    public int             AppId          { get; set; }
    public int             LobbyChannelId { get; set; }
    public int             HostAccountId  { get; set; }
    public string          HostName       { get; set; } = string.Empty;
    public int             MinPlayers     { get; set; } = 2;
    public int             MaxPlayers     { get; set; } = 8;
    public int             PlayerCount    { get { lock (_playerIds) return _playerIds.Count; } }
    public string          Password       { get; set; } = string.Empty;
    /// <summary>Password spectators present (CreateGame SpectatorPassword). Empty = open to spectators.</summary>
    public string          SpectatorPassword { get; set; } = string.Empty;
    public GameWorldStatus Status         { get; set; } = GameWorldStatus.WorldPendingCreation;
    public int             GameLevel      { get; set; }
    public int             PlayerSkillLevel { get; set; }
    public int             RulesSet       { get; set; }
    public int             GenericField1  { get; set; }
    public int             GenericField2  { get; set; }
    public int             GenericField3  { get; set; }
    public int             GenericField4  { get; set; }
    public int             GameHostType   { get; set; }
    /// <summary>GameStats[256] shown in the game list (retail: [roomId] .. [index 0x7F for player games] ..).</summary>
    public byte[]          GameStats      { get; set; } = new byte[256];
    public DateTime        CreatedAt      { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// ID of the associated <see cref="DmeWorld"/> created when this game was first made.
    /// Null if no DME world has been allocated yet.
    /// </summary>
    public int?            DmeWorldId     { get; set; }

    private readonly List<int> _playerIds = new();
    /// <summary>A copy of the roster (it changes from many connections at once).</summary>
    public IReadOnlyList<int> PlayerIds { get { lock (_playerIds) return _playerIds.ToArray(); } }

    public bool IsFull   => PlayerCount >= MaxPlayers;
    public bool IsLocked => !string.IsNullOrEmpty(Password);
    public bool IsSpectatorLocked => !string.IsNullOrEmpty(SpectatorPassword);

    public void AddPlayer(int accountId)    { lock (_playerIds) if (!_playerIds.Contains(accountId)) _playerIds.Add(accountId); }
    public void RemovePlayer(int accountId) { lock (_playerIds) _playerIds.Remove(accountId); }
}
