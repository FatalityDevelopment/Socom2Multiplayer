namespace CodeDesigner.Ps2.Multiplayer.Config;

/// <summary>
/// A retail "default room" — a permanent server-hosted game listed inside every briefing room.
/// Sent as a GameList_ExtraInfoResponse0 (0xEB) entry.
/// </summary>
public class DefaultGameConfig
{
    /// <summary>Game name; the wire name is "&lt;Name&gt;$~&lt;BRIEFING ROOM&gt;".</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Map ids in rotation order (1–4). The first is also the entry's GameLevel.</summary>
    public List<int> Maps { get; set; } = new();

    /// <summary>
    /// The 27 default rooms from the retail (servers-online) memory dump's US EAST game list, in retail
    /// order. GameStats index = 2 + list position (retail used 0x02..0x1C).
    /// </summary>
    public static List<DefaultGameConfig> RetailDefaults() => new()
    {
        new() { Name = "Breach Medley",      Maps = new() { 0x3D, 0x3E, 0x49 } },
        new() { Name = "Demolition Medley",  Maps = new() { 0x48, 0x53, 0x07, 0x09 } },
        new() { Name = "Escort Medley",      Maps = new() { 0x34, 0x35, 0x52 } },
        new() { Name = "Extraction Medley",  Maps = new() { 0x06, 0x0A, 0x0B, 0x47 } },
        new() { Name = "Suppression Medley", Maps = new() { 0x02, 0x05, 0x08, 0x33 } },
        new() { Name = "Vigilance",          Maps = new() { 0x33 } },
        new() { Name = "The Mixer",          Maps = new() { 0x34 } },
        new() { Name = "Foxhunt",            Maps = new() { 0x35 } },
        new() { Name = "Sujo",               Maps = new() { 0x3D } },
        new() { Name = "Enowapi",            Maps = new() { 0x3E } },
        new() { Name = "Shadow Falls",       Maps = new() { 0x40 } },
        new() { Name = "Fish Hook",          Maps = new() { 0x47 } },
        new() { Name = "Crossroads",         Maps = new() { 0x48 } },
        new() { Name = "Sandstorm",          Maps = new() { 0x49 } },
        new() { Name = "Chain Reaction",     Maps = new() { 0x51 } },
        new() { Name = "Guidance",           Maps = new() { 0x52 } },
        new() { Name = "Requiem",            Maps = new() { 0x53 } },
        new() { Name = "Blizzard",           Maps = new() { 0x01 } },
        new() { Name = "Frostfire",          Maps = new() { 0x02 } },
        new() { Name = "Abandoned",          Maps = new() { 0x05 } },
        new() { Name = "The Ruins",          Maps = new() { 0x0C } },
        new() { Name = "Desert Glory",       Maps = new() { 0x06 } },
        new() { Name = "Night Stalker",      Maps = new() { 0x07 } },
        new() { Name = "Rat's Nest",         Maps = new() { 0x08 } },
        new() { Name = "Bitter Jungle",      Maps = new() { 0x09 } },
        new() { Name = "Blood Lake",         Maps = new() { 0x0A } },
        new() { Name = "Death Trap",         Maps = new() { 0x0B } },
    };
}
