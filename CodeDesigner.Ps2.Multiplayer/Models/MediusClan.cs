using CodeDesigner.Ps2.Multiplayer.Protocol;

namespace CodeDesigner.Ps2.Multiplayer.Models;

/// <summary>A clan. Persisted with the accounts.</summary>
public class MediusClan
{
    public int       ClanId          { get; set; }
    public int       AppId           { get; set; }
    public string    ClanName        { get; set; } = string.Empty;
    public int       LeaderAccountId { get; set; }
    public List<int> Members         { get; set; } = new();
    /// <summary>ClanStats[256] (UpdateClanStats).</summary>
    public byte[]    Stats           { get; set; } = new byte[256];
    /// <summary>Clan ladder stats (UpdateLadderStats with LadderType 1). Null = not ranked.</summary>
    public int[]?    LadderStats     { get; set; }
    public MediusClanStatus Status   { get; set; } = MediusClanStatus.ClanActive;
    public DateTime  CreatedAt       { get; set; } = DateTime.UtcNow;
    public List<MediusClanMessage> Messages { get; set; } = new();
}

/// <summary>An invitation for a player to join a clan.</summary>
public class MediusClanInvitation
{
    public int      InvitationId { get; set; }
    public int      ClanId       { get; set; }
    public int      AccountId    { get; set; }
    public string   Message      { get; set; } = string.Empty;
    public MediusClanInvitationsResponseStatus Status { get; set; } = MediusClanInvitationsResponseStatus.ClanInvitationUndecided;
    public string   ResponseMessage { get; set; } = string.Empty;
    public DateTime ResponseTime { get; set; }
}

/// <summary>A clan message-board entry.</summary>
public class MediusClanMessage
{
    public int      MessageId { get; set; }
    public string   Text      { get; set; } = string.Empty;
    public MediusClanMessageStatus Status { get; set; } = MediusClanMessageStatus.ClanMessageUnread;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
