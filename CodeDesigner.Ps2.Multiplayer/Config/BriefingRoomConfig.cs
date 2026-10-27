namespace CodeDesigner.Ps2.Multiplayer.Config;

/// <summary>
/// One online BRIEFING-screen room. Sent as a ChannelList_ExtraInfoResponse (0xED) entry whose layout
/// SOCOM II's RoomList callback (EE 0x003009B0) copies into its room object.
/// </summary>
public class BriefingRoomConfig
{
    /// <summary>Display name (wire 0x2C, 64 bytes incl. terminator).</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>MediusWorldID (wire 0x1C, must be ≥0). Also the channel id JoinChannel resolves.</summary>
    public int WorldId { get; set; }

    /// <summary>Max players (wire 0x22, u16).</summary>
    public int MaxPlayers { get; set; } = 256;

    /// <summary>SecurityLevel (wire 0x24). 0 on every retail room.</summary>
    public int SecurityLevel { get; set; }

    /// <summary>
    /// Packed room attributes (wire 0x28). byte0 = rank bitmask (1 Ensign, 2 Lieutenant, 4 Lt Commander,
    /// 8 Captain; 0 = open to all) — the client tests it with <c>&amp; 0xF</c>; byte3 = display order.
    /// ENSIGNS ONLY carries 0x10 in byte2 instead of an order byte; reproduced verbatim.
    /// </summary>
    public uint GenericField { get; set; }

    /// <summary>
    /// The 11 user-facing rooms from the retail (servers-online) SOCOM II memory dump, in retail order.
    /// The dump's other 14 entries were Sony-internal lobbies (MediusLobby01/02 1–5, MediusMonitorLobby,
    /// MediusStatusLobby*) and are not shown on the BRIEFING screen.
    /// </summary>
    public static List<BriefingRoomConfig> RetailDefaults() => new()
    {
        new() { WorldId = 0x40, Name = "ENSIGNS ONLY",       GenericField = 0x00100001 },
        new() { WorldId = 0x41, Name = "LIEUTENANTS ONLY",   GenericField = 0x02000002 },
        new() { WorldId = 0x42, Name = "LT COMMANDERS ONLY", GenericField = 0x03000004 },
        new() { WorldId = 0x43, Name = "CAPTAINS ONLY",      GenericField = 0x04000008 },
        new() { WorldId = 0x44, Name = "US EAST",            GenericField = 0x05000000 },
        new() { WorldId = 0x45, Name = "US CENTRAL",         GenericField = 0x06000000 },
        new() { WorldId = 0x46, Name = "US WEST",            GenericField = 0x07000000 },
        new() { WorldId = 0x47, Name = "CANADA EAST",        GenericField = 0x08000000 },
        new() { WorldId = 0x48, Name = "CANADA WEST",        GenericField = 0x09000000 },
        new() { WorldId = 0x49, Name = "CLAN GAMES",         GenericField = 0x0A000000 },
        new() { WorldId = 0x4A, Name = "E-SEALs",            GenericField = 0x0B000000 },
    };
}
