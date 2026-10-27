using static CodeDesigner.Ps2.Multiplayer.Protocol.MediusFieldType;
using C = CodeDesigner.Ps2.Multiplayer.Protocol.MediusConstants;

namespace CodeDesigner.Ps2.Multiplayer.Protocol;

/// <summary>
/// Medius/SCERT struct schemas for field-level packet dissection.
///
/// These describe the on-wire layout of Medius application messages so a
/// captured packet can be decoded into a list of named fields (Account Name,
/// Session Key, World Id, …) without per-message parser code.
///
/// Ported from the previous TypeScript dissector in packet-viewer.component.ts.
/// The schemas are the load-bearing artifact: porting the enums was mechanical,
/// porting these required matching the horizon-server / hashsploit Wireshark
/// dissector layouts against real packet captures.
///
/// Lookup keys:
///   <see cref="Medius"/>   keyed by (msgType &lt;&lt; 8) | msgClass
///   <see cref="ScertPayloads"/> keyed by SCERT msgType byte (0x00–0x36)
/// </summary>
public static class MediusStructSchemas
{
    /// <summary>
    /// Game IDs that appear in the App Id field of CONNECT_TCP / CreateGame
    /// payloads. Not a CLR enum because new titles get added as captures land.
    /// </summary>
    public static readonly IReadOnlyDictionary<uint, string> ApplicationIds = new Dictionary<uint, string>
    {
        [10411] = "Syphon Filter: The Omega Strain",
        [10683] = "Ratchet and Clank 3 (PAL)",
        [10684] = "Ratchet and Clank: Up Your Arsenal",
        [10782] = "Gran Turismo 4 (Beta)",
        [10994] = "Jak X: Combat Racing (NTSC-U)",
        [11184] = "Ratchet: Deadlocked",
        [11204] = "Jak X: Combat Racing (PAL)",
        [20624] = "Socom US Navy Seals Combined Assault",
        [20034] = "Socom 2 US Navy Seals",
        [20032] = "Socom US Navy Seals",
    };

    /// <summary>
    /// Medius application-layer struct schemas, keyed by (msgType &lt;&lt; 8) | msgClass.
    /// E.g. SessionBegin (Lobby class=0x01, type=0x03) → 0x0301.
    /// </summary>
    public static readonly IReadOnlyDictionary<int, MediusStructDef> Medius = BuildMedius();

    /// <summary>
    /// SCERT-layer struct schemas for non-APP message types where the payload
    /// has a fixed layout (CONNECT_TCP, CRYPTKEY_PUBLIC, CHEAT_QUERY, …).
    /// </summary>
    public static readonly IReadOnlyDictionary<byte, MediusStructDef> ScertPayloads = BuildScertPayloads();

    // ── Schema tables ────────────────────────────────────────────────────────
    //
    // Each `S(...)` call below is one packet shape. The pattern mirrors the
    // TypeScript originals to keep cross-referencing easy:
    //
    //     [0x0301, [          // (msgType<<8)|msgClass
    //         { name: 'Message Id',      type: 'bytes', length: 21 },
    //         { name: 'Connection Type', type: 'uint',  length: 4, enum: ... },
    //     ]]
    //
    // Becomes:
    //
    //     [0x0301] = S(
    //         F("Message Id",      Bytes, C.MESSAGEID_MAXLEN),
    //         F("Connection Type", UInt,  4, typeof(MediusConnectionType)) ),

    private static IReadOnlyDictionary<int, MediusStructDef> BuildMedius() => new Dictionary<int, MediusStructDef>
    {
        // ── Lobby class (0x01) ────────────────────────────────────────────────

        [0x0301] = S(
            F("Message Id",       Bytes, C.MESSAGEID_MAXLEN),
            F("Padding",          Bytes, 3),
            F("Connection Type",  UInt,  4, typeof(MediusConnectionType))),

        [0x0401] = S(
            F("Message Id",      Bytes, C.MESSAGEID_MAXLEN),
            F("Padding",         Bytes, 3),
            F("Callback Status", UInt,  4, typeof(MediusCallbackStatus)),
            F("Session Key",     Bytes, C.SESSIONKEY_MAXLEN),
            F("Padding",         Bytes, 3)),

        [0x0701] = S(
            F("Message Id",    Bytes,  C.MESSAGEID_MAXLEN),
            F("Session Key",   Bytes,  C.SESSIONKEY_MAXLEN),
            F("Account Name",  AsciiZ, C.ACCOUNTNAME_MAXLEN),
            F("Password",      AsciiZ, C.PASSWORD_MAXLEN)),

        [0x0801] = S(
            F("Message Id",      Bytes, C.MESSAGEID_MAXLEN),
            F("Padding",         Bytes, 3),
            F("Callback Status", UInt,  4, typeof(MediusCallbackStatus)),
            F("Account Id",      UInt,  4)),

        [0x1101] = S(
            F("Message Id",     Bytes, C.MESSAGEID_MAXLEN),
            F("Session Key",    Bytes, C.SESSIONKEY_MAXLEN),
            F("Account Stats",  Bytes, C.ACCOUNTSTATS_MAXLEN)),

        [0x1201] = S(
            F("Message Id",      Bytes, C.MESSAGEID_MAXLEN),
            F("Padding",         Bytes, 3),
            F("Callback Status", UInt,  4, typeof(MediusCallbackStatus))),

        [0x1901] = S(
            F("Message Id",      Bytes, C.MESSAGEID_MAXLEN),
            F("Session Key",     Bytes, C.SESSIONKEY_MAXLEN),
            F("Language Type",   UInt,  4, typeof(MediusLanguageType))),

        [0x1A01] = S(
            F("Message Id",      Bytes, C.MESSAGEID_MAXLEN),
            F("Padding",         Bytes, 3),
            F("Callback Status", UInt,  4, typeof(MediusCallbackStatus)),
            F("Account Id",      UInt,  4),
            F("Account Type",    UInt,  4, typeof(MediusAccountType)),
            F("World Id",        UInt,  4),
            F("Access Key",      Bytes, C.NET_ACCESS_KEY_LEN),
            F("Session Key",     Bytes, C.SESSIONKEY_MAXLEN)),

        [0x1B01] = S(
            F("Message Id",  Bytes, C.MESSAGEID_MAXLEN),
            F("Session Key", Bytes, C.SESSIONKEY_MAXLEN)),

        [0x1C01] = S(
            F("Message Id",      Bytes,  C.MESSAGEID_MAXLEN),
            F("Padding",         Bytes,  3),
            F("Callback Status", UInt,   4, typeof(MediusCallbackStatus)),
            F("IP Address",      AsciiZ, 16)),

        [0x1D01] = S(
            F("Message Id",      Bytes, C.MESSAGEID_MAXLEN),
            F("Session Key",     Bytes, C.SESSIONKEY_MAXLEN),
            F("Application Id",  UInt,  4, EnumDict: ApplicationIds),
            F("Min Players",     UInt,  4),
            F("Max Players",     UInt,  4),
            F("Game Level",      UInt,  4),
            F("Player Skill Lvl",UInt,  4),
            F("Rules Set",       UInt,  4),
            F("Generic Field 1", UInt,  4),
            F("Generic Field 2", UInt,  4),
            F("Generic Field 3", UInt,  4),
            F("Game Host Type",  UInt,  4, typeof(MediusGameHostType)),
            F("World Status",    UInt,  4, typeof(MediusWorldStatus), Optional: true)),

        [0x1E01] = S(
            F("Message Id",      Bytes, C.MESSAGEID_MAXLEN),
            F("Padding",         Bytes, 3),
            F("Status Code",     UInt,  4, typeof(MediusCallbackStatus)),
            F("Media World Id",  UInt,  4)),

        [0x2101] = S(
            F("Message Id",          Bytes,  C.MESSAGEID_MAXLEN),
            F("Session Key",         Bytes,  C.SESSIONKEY_MAXLEN),
            F("Lobby Channel Name",  AsciiZ, C.ACCOUNTNAME_MAXLEN),
            F("Min Players",         UInt,   4, Optional: true),
            F("Max Players",         UInt,   4, Optional: true),
            F("Genfield Lvl",        UInt,   4, Optional: true)),

        [0x2201] = S(
            F("Message Id",      Bytes, C.MESSAGEID_MAXLEN),
            F("Padding",         Bytes, 3),
            F("Status Code",     UInt,  4, typeof(MediusCallbackStatus)),
            F("Media World Id",  UInt,  4)),

        [0x2301] = S(
            F("Message Id",      Bytes,  C.MESSAGEID_MAXLEN),
            F("Session Key",     Bytes,  C.SESSIONKEY_MAXLEN),
            F("Padding",         Bytes,  2),
            F("Media World Id",  UInt,   4),
            F("Game Password",   AsciiZ, C.PASSWORD_MAXLEN, Optional: true),
            F("Join Type",       UInt,   4, typeof(MediusJoinType), Optional: true)),

        [0x2401] = S(
            F("Message Id",      Bytes,  C.MESSAGEID_MAXLEN),
            F("Padding",         Bytes,  3),
            F("Status Code",     UInt,   4, typeof(MediusCallbackStatus)),
            F("DME World Id",    UInt,   4),
            F("DME Server IP",   AsciiZ, 16),
            F("DME Server Port", UInt,   2),
            F("Padding2",        Bytes,  2)),

        [0x2501] = S(
            F("Message Id",      Bytes, C.MESSAGEID_MAXLEN),
            F("Session Key",     Bytes, C.SESSIONKEY_MAXLEN),
            F("Padding",         Bytes, 2),
            F("Media World Id",  UInt,  4)),

        [0x2601] = S(
            F("Message Id",      Bytes, C.MESSAGEID_MAXLEN),
            F("Padding",         Bytes, 3),
            F("Status Code",     UInt,  4, typeof(MediusCallbackStatus)),
            F("Media World Id",  UInt,  4)),

        [0x3501] = S(
            F("Message Id",      Bytes, C.MESSAGEID_MAXLEN),
            F("Session Key",     Bytes, C.SESSIONKEY_MAXLEN),
            F("Padding",         Bytes, 2),
            F("Media World Id",  UInt,  4)),

        [0x3601] = S(
            F("Message Id",        Bytes,  C.MESSAGEID_MAXLEN),
            F("Padding",           Bytes,  3),
            F("Status Code",       UInt,   4, typeof(MediusCallbackStatus)),
            F("Lobby Name",        AsciiZ, C.ACCOUNTNAME_MAXLEN, Optional: true),
            F("Active Players",    UInt,   4, Optional: true),
            F("Max Players",       UInt,   4, Optional: true),
            F("Game World Status", UInt,   4, typeof(MediusWorldStatus), Optional: true)),

        [0x3B01] = S(
            F("Message Id",   Bytes,  C.MESSAGEID_MAXLEN),
            F("Session Key",  Bytes,  C.SESSIONKEY_MAXLEN),
            F("Target Type",  UInt,   4, typeof(MediusChatMessageType)),
            F("Target Id",    UInt,   4),
            F("Chat Type",    UInt,   4, typeof(MediusChatMessageType)),
            F("Message",      AsciiZ, 512)),

        [0x4701] = S(
            F("Message Id",  Bytes, C.MESSAGEID_MAXLEN),
            F("Session Key", Bytes, C.SESSIONKEY_MAXLEN),
            F("Padding",     Bytes, 2),
            F("Policy Type", UInt,  4, typeof(MediusPolicyType))),

        [0x4801] = S(
            F("Message Id",      Bytes,  C.MESSAGEID_MAXLEN),
            F("Padding",         Bytes,  3),
            F("Callback Status", UInt,   4, typeof(MediusCallbackStatus)),
            F("Policy Message",  AsciiZ, C.POLICY_MAXLEN),
            F("End of Message",  Bool,   4)),

        [0x4901] = S(
            F("Session Key",  Bytes, C.SESSIONKEY_MAXLEN),
            F("Padding",      Bytes, 3),
            F("User Action",  UInt,  4, typeof(MediusUserAction))),

        [0x4E01] = S(
            F("Message Id",      Bytes, C.MESSAGEID_MAXLEN),
            F("Session Key",     Bytes, C.SESSIONKEY_MAXLEN),
            F("Padding",         Bytes, 2),
            F("Base/Comparison", UInt,  4),
            F("Filter Field",    UInt,  4, typeof(MediusGameListFilterField)),
            F("Mask",            UInt,  4),
            F("Comparison Op",   UInt,  4)),

        [0x4F01] = S(
            F("Message Id",      Bytes, C.MESSAGEID_MAXLEN),
            F("Padding",         Bytes, 3),
            F("Status Code",     UInt,  4, typeof(MediusCallbackStatus)),
            F("Filter Id",       UInt,  4)),

        [0x7C01] = S(
            F("Message Id",    Bytes, C.MESSAGEID_MAXLEN),
            F("Session Key",   Bytes, C.SESSIONKEY_MAXLEN),
            F("Padding",       Bytes, 2),
            F("Starting Page", UInt,  4),
            F("Page Size",     UInt,  4)),

        [0x7D01] = S(
            F("Message Id",          Bytes,  C.MESSAGEID_MAXLEN),
            F("Padding",             Bytes,  3),
            F("Callback Status",     UInt,   4, typeof(MediusCallbackStatus)),
            F("Clan Id",             UInt,   4),
            F("App Id",              UInt,   4, EnumDict: ApplicationIds),
            F("Clan Name",           AsciiZ, C.CLANNAME_MAXLEN),
            F("Leader Account Id",   UInt,   4),
            F("Leader Account Name", AsciiZ, C.ACCOUNTNAME_MAXLEN),
            F("Clan Stats",          Bytes,  C.CLANSTATS_MAXLEN),
            F("Clan Status",         UInt,   4, typeof(MediusClanStatus)),
            F("End of Message",      Bool,   4)),

        [0x8601] = S(
            F("Message Id",  Bytes, C.MESSAGEID_MAXLEN),
            F("Session Key", Bytes, C.SESSIONKEY_MAXLEN)),

        // VersionServerResponse: [msgId:21][version:56].
        // Matches horizon-server-public-extended's MediusVersionServerResponse.
        // No padding or status code on the wire — the C# field on the class
        // exists but isn't serialized.
        [0x8701] = S(
            F("Message Id", Bytes,  C.MESSAGEID_MAXLEN),
            F("Version",    AsciiZ, 56)),

        [0x8C01] = S(
            F("Message Id",  Bytes, C.MESSAGEID_MAXLEN),
            F("Session Key", Bytes, C.SESSIONKEY_MAXLEN)),

        [0x8E01] = S(
            F("Message Id",  Bytes, C.MESSAGEID_MAXLEN),
            F("Session Key", Bytes, C.SESSIONKEY_MAXLEN),
            F("Location Id", UInt,  4)),

        [0xC801] = S(
            F("Message Id",  Bytes, C.MESSAGEID_MAXLEN),
            F("Session Key", Bytes, C.SESSIONKEY_MAXLEN),
            F("Info Filter", UInt,  4, typeof(MediusUniverseVariableInformationInfoFilter))),

        [0xCB01] = S(
            F("Message Id",  Bytes, C.MESSAGEID_MAXLEN),
            F("Session Key", Bytes, C.SESSIONKEY_MAXLEN),
            F("Machine Sig", Bytes, 16)),

        // ── DME class (0x00) — server-to-server MGCL ──────────────────────────

        [0x0300] = S(
            F("Message Id", Bytes, C.MESSAGEID_MAXLEN),
            F("Padding",    Bytes, 3),
            F("App Id",     UInt,  4, EnumDict: ApplicationIds),
            F("Server Key", Bytes, C.SESSIONKEY_MAXLEN, Optional: true)),

        [0x0400] = S(
            F("Message Id",   Bytes, C.MESSAGEID_MAXLEN),
            F("Padding",      Bytes, 3),
            F("Confirmation", UInt,  4, typeof(MGCL_ERROR_CODE))),

        [0x0700] = S(
            F("Message Id",     Bytes, C.MESSAGEID_MAXLEN),
            F("Game World Id",  UInt,  4),
            F("World Status",   UInt,  4, typeof(MediusWorldStatus)),
            F("Max Clients",    UInt,  4)),

        [0x0800] = S(
            F("Message Id",    Bytes, C.MESSAGEID_MAXLEN),
            F("Padding",       Bytes, 3),
            F("Confirmation",  UInt,  4, typeof(MGCL_ERROR_CODE)),
            F("Game World Id", UInt,  4),
            F("World Status",  UInt,  4, typeof(MediusWorldStatus))),

        [0x0B00] = S(
            F("Message Id",    Bytes, C.MESSAGEID_MAXLEN),
            F("Padding",       Bytes, 3),
            F("Game World Id", UInt,  4)),

        [0x0C00] = S(
            F("Message Id",   Bytes, C.MESSAGEID_MAXLEN),
            F("Padding",      Bytes, 3),
            F("Confirmation", UInt,  4, typeof(MGCL_ERROR_CODE))),

        [0x0D00] = S(
            F("Message Id",    Bytes, C.MESSAGEID_MAXLEN),
            F("Padding",       Bytes, 3),
            F("Game World Id", UInt,  4),
            F("World Status",  UInt,  4, typeof(MediusWorldStatus))),

        [0x1C00] = S(
            F("Message Id",         Bytes, C.MESSAGEID_MAXLEN),
            F("Padding",            Bytes, 3),
            F("Game World Id",      UInt,  4),
            F("Player Id",          UInt,  4),
            F("Account Id",         UInt,  4),
            F("Connect Event Type", UInt,  4, typeof(MGCL_EVENT_TYPE))),

        // ── LobbyExt class (0x04) ─────────────────────────────────────────────

        [0x0A04] = S(
            F("Message Id",    Bytes, C.MESSAGEID_MAXLEN),
            F("Session Key",   Bytes, C.SESSIONKEY_MAXLEN),
            F("DNAS Category", UInt,  4, typeof(MediusDnasCategory)),
            F("DNAS Sig",      Bytes, 32)),

        [0x1604] = S(
            F("Message Id",        Bytes, C.MESSAGEID_MAXLEN),
            F("Session Key",       Bytes, C.SESSIONKEY_MAXLEN),
            F("Padding",           Bytes, 2),
            F("Target Account Id", UInt,  4),
            F("Message Type",      UInt,  4, typeof(MediusBinaryMessageType)),
            F("Message Size",      UInt,  2),
            F("Padding2",          Bytes, 2),
            F("Message",           Bytes, 256, Optional: true)),

        [0x1704] = S(
            F("Origin Account Id", UInt,  4),
            F("Message Type",      UInt,  4, typeof(MediusBinaryMessageType)),
            F("Message Size",      UInt,  2),
            F("Padding",           Bytes, 2),
            F("Message",           Bytes, 256, Optional: true)),

        [0x2304] = S(
            F("Message Id",   Bytes,  C.MESSAGEID_MAXLEN),
            F("Session Key",  Bytes,  C.SESSIONKEY_MAXLEN),
            F("Message Type", UInt,   4, typeof(MediusChatMessageType)),
            F("Target Id",    UInt,   4),
            F("Message",      AsciiZ, 512, Optional: true)),

        [0x2704] = S(
            F("Message Id",      Bytes,  C.MESSAGEID_MAXLEN),
            F("Padding",         Bytes,  3),
            F("Connection Type", UInt,   4, typeof(MediusConnectionType)),
            F("Client Version",  AsciiZ, 64, Optional: true),
            F("Locale",          UInt,   4, typeof(MediusLanguageType), Optional: true)),

        [0x2804] = S(
            F("Message Id",     Bytes, C.MESSAGEID_MAXLEN),
            F("Session Key",    Bytes, C.SESSIONKEY_MAXLEN),
            F("Token Action",   UInt,  4, typeof(MediusTokenActionType)),
            F("Token Category", UInt,  4, typeof(MediusTokenCategoryType)),
            F("Token Value",    UInt,  4)),

        [0x2A04] = S(
            F("Message Id",  Bytes, C.MESSAGEID_MAXLEN),
            F("Session Key", Bytes, C.SESSIONKEY_MAXLEN),
            F("Time Zone",   UInt,  4, typeof(MediusTimeZone), Optional: true)),

        [0x2B04] = S(
            F("Message Id",  Bytes, C.MESSAGEID_MAXLEN),
            F("Padding",     Bytes, 3),
            F("Status Code", UInt,  4, typeof(MediusCallbackStatus)),
            F("Time Zone",   UInt,  4, typeof(MediusTimeZone)),
            F("Local Time",  Bytes, 16, Optional: true)),

        [0x2F04] = S(
            F("Message Id",      Bytes, C.MESSAGEID_MAXLEN),
            F("Session Key",     Bytes, C.SESSIONKEY_MAXLEN),
            F("Application Id",  UInt,  4, EnumDict: ApplicationIds),
            F("Min Players",     UInt,  4),
            F("Max Players",     UInt,  4),
            F("Game Level",      UInt,  4),
            F("Player Skill Lvl",UInt,  4),
            F("Rules Set",       UInt,  4),
            F("Generic Field 1", UInt,  4),
            F("Generic Field 2", UInt,  4),
            F("Generic Field 3", UInt,  4),
            F("Game Host Type",  UInt,  4, typeof(MediusGameHostType)),
            F("Attributes",      UInt,  4, typeof(MediusWorldAttributesType), Optional: true),
            F("Security Level",  UInt,  4, typeof(MediusWorldSecurityLevelType), Optional: true)),

        [0x3004] = S(
            F("Media World Id", UInt, 4),
            F("World Status",   UInt, 4, typeof(MediusWorldStatus)),
            F("Total Players",  UInt, 4),
            F("Game Level",     UInt, 4, Optional: true)),

        [0x5804] = S(
            F("Message Id",   Bytes,  C.MESSAGEID_MAXLEN),
            F("Session Key",  Bytes,  C.SESSIONKEY_MAXLEN),
            F("Account Name", AsciiZ, C.ACCOUNTNAME_MAXLEN),
            F("Ticket Data",  Bytes,  256)),

        [0x5904] = S(
            F("Message Id",      Bytes, C.MESSAGEID_MAXLEN),
            F("Padding",         Bytes, 3),
            F("Callback Status", UInt,  4, typeof(MediusCallbackStatus)),
            F("Account Id",      UInt,  4),
            F("Account Type",    UInt,  4, typeof(MediusAccountType)),
            F("World Id",        UInt,  4),
            F("Access Key",      Bytes, C.NET_ACCESS_KEY_LEN),
            F("Session Key",     Bytes, C.SESSIONKEY_MAXLEN)),
    };

    private static IReadOnlyDictionary<byte, MediusStructDef> BuildScertPayloads() => new Dictionary<byte, MediusStructDef>
    {
        // RT_MSG_CLIENT_CONNECT_TCP — Medius 1.10 layout (PS2)
        [0x00] = S(
            F("World Id",    UInt,  4),
            F("App Id",      UInt,  4, EnumDict: ApplicationIds),
            F("RSA Key",     Bytes, 64),
            F("Session Key", Bytes, C.SESSIONKEY_MAXLEN, Optional: true),
            F("Access Key",  Bytes, C.NET_ACCESS_KEY_LEN, Optional: true)),

        // RT_MSG_SERVER_CONNECT_ACCEPT_TCP — server tells client its IP
        [0x07] = S(
            F("Client IP", AsciiZ, 16),
            F("World Id",  UInt,   4)),

        // RT_MSG_CLIENT_CRYPTKEY_PUBLIC
        [0x12] = S(
            F("RSA Key", Bytes, 64)),

        // RT_MSG_SERVER_CRYPTKEY_PEER
        [0x13] = S(
            F("Session Key", Bytes, C.SESSIONKEY_MAXLEN)),

        // RT_MSG_CLIENT_SET_RECV_FLAG
        [0x0D] = S(
            F("Recv Flags", UInt, 4, typeof(RT_RECV_FLAG))),

        // RT_MSG_SERVER_CHEAT_QUERY
        [0x1D] = S(
            F("Cheat Query Type", UInt,  1, typeof(CheatQueryType)),
            F("Sequence",         UInt,  1),
            F("Padding",          Bytes, 2),
            F("Address",          UInt,  4),
            F("Length",           UInt,  4),
            F("Salt / Extra",     Bytes, 64, Optional: true)),

        // RT_MSG_CLIENT_DISCONNECT_WITH_REASON
        [0x20] = S(
            F("Reason", UInt, 4)),
    };

    // ── Shorthand constructors ───────────────────────────────────────────────

    private static MediusStructDef S(params MediusFieldDef[] fields) => new(fields);

    private static MediusFieldDef F(
        string name,
        MediusFieldType type,
        int length,
        Type? EnumType = null,
        IReadOnlyDictionary<uint, string>? EnumDict = null,
        bool Optional = false)
        => new(name, type, length, EnumType, EnumDict, Optional);
}
