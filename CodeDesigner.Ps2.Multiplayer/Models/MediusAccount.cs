namespace CodeDesigner.Ps2.Multiplayer.Models;

/// <summary>A player account. Persisted by <see cref="Storage.InMemoryStorage"/> (JSON snapshot).</summary>
public class MediusAccount
{
    public int    AccountId       { get; set; }
    public string AccountName     { get; set; } = string.Empty;
    public string PasswordHash    { get; set; } = string.Empty;  // SHA-1 hex or plain for dev
    public string Stats           { get; set; } = string.Empty;
    public bool   IsBanned        { get; set; }
    public DateTime CreatedAt     { get; set; } = DateTime.UtcNow;
    public DateTime LastLoginAt   { get; set; } = DateTime.UtcNow;

    /// <summary>AccountStats[256] the game uploads with AccountUpdateStats (shown in PlayerInfo / ladder rows).</summary>
    public byte[] AccountStats    { get; set; } = new byte[256];

    /// <summary>
    /// Player ladder stats from UpdateLadderStats (LadderType 0). Ranking sorts on one index of this array;
    /// SOCOM II uses index 0 (its rating, 1000 for a new player). Null = never reported → not ranked.
    /// </summary>
    public int[]? LadderStats     { get; set; }

    /// <summary>Buddy (friends) list — account ids.</summary>
    public List<int> Buddies      { get; set; } = new();

    /// <summary>Ignore list — account ids.</summary>
    public List<int> Ignores      { get; set; } = new();

    /// <summary>Clan membership (0 = none).</summary>
    public int    ClanId          { get; set; }
}
