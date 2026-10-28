namespace CodeDesigner.Ps2.Multiplayer.Models;

/// <summary>A lobby channel that players can join and chat in.</summary>
public class MediusChannel
{
    public int    ChannelId        { get; set; }
    public string ChannelName      { get; set; } = string.Empty;
    public int    MaxPlayers       { get; set; } = 256;
    public int    AppId            { get; set; }
    public string Password         { get; set; } = string.Empty;
    public int    SecurityLevel    { get; set; }
    public int    GenericField1    { get; set; }
    public int    GenericField2    { get; set; }
    public int    GenericField3    { get; set; }

    private readonly List<int> _playerIds = new();

    /// <summary>A copy of the roster (it changes from many connections at once).</summary>
    public IReadOnlyList<int> PlayerIds { get { lock (_playerIds) return _playerIds.ToArray(); } }
    public int PlayerCount { get { lock (_playerIds) return _playerIds.Count; } }
    public bool IsFull => PlayerCount >= MaxPlayers;

    public void AddPlayer(int accountId)    { lock (_playerIds) if (!_playerIds.Contains(accountId)) _playerIds.Add(accountId); }
    public void RemovePlayer(int accountId) { lock (_playerIds) _playerIds.Remove(accountId); }
}
