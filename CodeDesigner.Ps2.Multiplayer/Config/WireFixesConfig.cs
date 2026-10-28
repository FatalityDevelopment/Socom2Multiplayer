namespace CodeDesigner.Ps2.Multiplayer.Config;

/// <summary>
/// Wire-format corrections that look right against the horizon layouts but haven't been confirmed on a console yet.
/// Each is off by default, so the hardware-tested replies stay exactly as they were; turn one on at a time
/// (Online:WireFixes:&lt;Name&gt; = true, or Online__WireFixes__&lt;Name&gt;=true) and check the README checklist.
/// </summary>
public class WireFixesConfig
{
    /// <summary>
    /// MLS replies that were sent without the request's MessageID echo (so the client can't match them to the
    /// request) get the standard header: MLS SessionBegin (with a 17-byte key), AccountLogout, GetUniverse_ExtraInfo,
    /// LobbyExt ChannelList_ExtraInfo (also answered with the response type, not the request type), LobbyExt
    /// GameList_ExtraInfo, GetLocations, PickLocation and UtilGetServerVersion.
    /// </summary>
    public bool MlsHeaderEcho { get; set; }

    /// <summary>MAS ExtendedSessionBeginResponse gets the 3-byte pad after the MessageID that SessionBeginResponse has.</summary>
    public bool MasExtendedSessionBeginPad { get; set; }

    /// <summary>TicketLoginResponse carries the server RSA key and is sent encrypted, like AccountLoginResponse.</summary>
    public bool TicketLoginEncrypted { get; set; }

    /// <summary>
    /// NetConnectionInfo without the 2 trailing bytes horizon only writes for Medius &gt; 108 (154 bytes, not 156).
    /// Affects every login, JoinChannel and JoinGame reply — test logins and room/game joins after turning it on.
    /// </summary>
    public bool NetConnectionInfo154 { get; set; }

    /// <summary>A Lobby-class GetUniverse on MUIS is answered with the 0x120-byte GetUniverseResponse body, not the universe-status one.</summary>
    public bool MuisLegacyGetUniverse { get; set; }

    /// <summary>The empty game list is a full 0x190-byte row with EndOfList at 0x18C, where a real row has it.</summary>
    public bool EmptyGameListEndOfList { get; set; }
}
