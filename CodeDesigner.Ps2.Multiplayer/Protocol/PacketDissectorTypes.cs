using System.Text.Json;
using System.Text.Json.Serialization;

namespace CodeDesigner.Ps2.Multiplayer.Protocol;

/// <summary>
/// One field within a <see cref="DissectedLayer"/>, e.g. ("Source Port", "10078").
/// Values are formatted strings — the dissector renders enums as
/// "123 (EnumName)" so consumers (webview, MCP) can display directly.
/// </summary>
/// <remarks>
/// JSON property names are lowercase to match the webview's existing
/// <c>DissectedField</c> interface in packet-viewer.component.ts. This
/// keeps the bridge → webview wire format stable while the parsing logic
/// moves server-side.
/// </remarks>
public sealed record DissectedField(
    [property: JsonPropertyName("name")]  string Name,
    [property: JsonPropertyName("value")] string Value);

/// <summary>
/// One protocol layer of a dissected Ethernet frame, ready for display
/// in a Wireshark-style tree. Offset/length point back into the raw frame
/// so the UI can highlight bytes in the hex view.
/// </summary>
public sealed class DissectedLayer
{
    /// <summary>Display label, e.g. "Ethernet II", "Internet Protocol Version 4".</summary>
    [JsonPropertyName("label")]
    public string Label { get; set; } = string.Empty;

    /// <summary>Accent colour suggestion (CSS hex) for the row.</summary>
    [JsonPropertyName("color")]
    public string Color { get; set; } = "#909399";

    /// <summary>Decoded fields for this layer.</summary>
    [JsonPropertyName("fields")]
    public IList<DissectedField> Fields { get; set; } = new List<DissectedField>();

    /// <summary>Byte offset of this layer's header within the raw frame.</summary>
    [JsonPropertyName("offset")]
    public int Offset { get; set; }

    /// <summary>Byte length of this layer's header within the raw frame.</summary>
    [JsonPropertyName("length")]
    public int Length { get; set; }
}

/// <summary>
/// Field type tag for <see cref="MediusFieldDef"/>.
/// Mirrors the four wire encodings the SCERT/Medius dissector understands.
/// </summary>
public enum MediusFieldType
{
    /// <summary>Raw bytes — rendered as hex + optional ASCII when printable.</summary>
    Bytes,
    /// <summary>Little-endian unsigned integer (1, 2, or 4 bytes).</summary>
    UInt,
    /// <summary>NUL-terminated ASCII string within a fixed-size slot.</summary>
    AsciiZ,
    /// <summary>Unsigned int rendered as "true"/"false".</summary>
    Bool,
}

/// <summary>
/// One field of a Medius/SCERT struct schema.
/// </summary>
/// <param name="Name">Display name for the dissection tree.</param>
/// <param name="Type">Wire encoding.</param>
/// <param name="Length">Number of bytes consumed.</param>
/// <param name="EnumType">
/// Optional CLR enum type used to resolve UInt values to symbolic names
/// (e.g. <see cref="MediusCallbackStatus"/>). Looked up via reflection.
/// </param>
/// <param name="EnumDict">
/// Optional explicit number→name map used when no CLR enum exists
/// (e.g. APPLICATION_ID — those are game IDs, not a fixed enum).
/// </param>
/// <param name="Optional">
/// When true, missing trailing bytes are silently skipped. Used for fields
/// that only appear in newer Medius versions.
/// </param>
public sealed record MediusFieldDef(
    string Name,
    MediusFieldType Type,
    int Length,
    Type? EnumType = null,
    IReadOnlyDictionary<uint, string>? EnumDict = null,
    bool Optional = false);

/// <summary>Ordered list of <see cref="MediusFieldDef"/> describing one Medius/SCERT struct.</summary>
public sealed class MediusStructDef
{
    public MediusFieldDef[] Fields { get; }
    public MediusStructDef(params MediusFieldDef[] fields) => Fields = fields;
}

/// <summary>
/// Parsed Medius application-layer message (the inner payload of an
/// RT_MSG_*_APP_* SCERT message).
/// </summary>
public sealed class ParsedMediusMessage
{
    public byte MsgClass { get; set; }
    public string MsgClassName { get; set; } = string.Empty;
    public byte MsgType { get; set; }
    public string MsgTypeName { get; set; } = string.Empty;
    /// <summary>Absolute byte offset of the Medius class byte within the full Ethernet frame.</summary>
    public int FrameOffset { get; set; }
    /// <summary>Field-level dissection of the Medius payload. Empty if no schema is registered.</summary>
    public IList<DissectedField> PayloadFields { get; set; } = new List<DissectedField>();
}

/// <summary>
/// One message from a DME app payload on a game connection: a <see cref="DmeAppMessageId"/>
/// (class 0) or a SOCOM II application message from <see cref="GameMessageCatalog"/> (class 2).
/// A single APP record usually packs several of these.
/// </summary>
public sealed class ParsedDmeMessage
{
    public byte MsgClass { get; set; }
    public byte MsgId { get; set; }
    /// <summary>Catalog name: the <see cref="DmeAppMessageId"/> member or the game message name.</summary>
    public string Name { get; set; } = string.Empty;
    /// <summary>Name plus detail for display, e.g. "ObjectUpdate SealState #3".</summary>
    public string Display { get; set; } = string.Empty;
    /// <summary>True for class-2 game messages, false for DME library messages.</summary>
    public bool IsGame { get; set; }
    /// <summary>Absolute offset of the class byte within the frame.</summary>
    public int FrameOffset { get; set; }
    /// <summary>Length including the 2-byte [class][id] header.</summary>
    public int Length { get; set; }
    public IList<DissectedField> Fields { get; set; } = new List<DissectedField>();
}

/// <summary>
/// One-line summary of a frame for the packet table, built by <see cref="PacketDissector.Summarize"/>
/// from the same decode as the layer tree so the row and the tree always agree.
/// </summary>
public sealed class PacketSummary
{
    /// <summary>Multiplayer server the frame talks to (MUIS, MAS, MLS, DME, NAT, DNAS, DNS) or empty.</summary>
    public string Server { get; set; } = string.Empty;
    /// <summary>Innermost protocol: Game, DME, Medius, SCERT, TCP, UDP, DNS, ICMP, ARP, …</summary>
    public string Protocol { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string Destination { get; set; } = string.Empty;
    /// <summary>Message names (or a transport description when there is no application message).</summary>
    public string Info { get; set; } = string.Empty;
    /// <summary>Every application message name in the frame, in order.</summary>
    public IList<string> Messages { get; } = new List<string>();
}

/// <summary>
/// One parsed SCERT message extracted from a TCP segment.
/// </summary>
public sealed class ParsedScertMessage
{
    /// <summary>Raw type byte including the 0x80 encrypted flag.</summary>
    public byte RawTypeByte { get; set; }
    /// <summary>SCERT message type with the encrypted flag stripped.</summary>
    public RT_MSG_TYPE MsgType { get; set; }
    public string MsgTypeName { get; set; } = string.Empty;
    public bool IsEncrypted { get; set; }
    public ushort PayloadLen { get; set; }
    /// <summary>4-byte per-packet hash when <see cref="IsEncrypted"/> is true.</summary>
    public uint? Hash { get; set; }
    /// <summary>Parsed Medius layer for APP messages (class + type bytes + payload).</summary>
    public ParsedMediusMessage? Medius { get; set; }
    /// <summary>Decoded fields for non-APP SCERT messages with a known schema (CONNECT_TCP, CRYPTKEY_PUBLIC, etc.).</summary>
    public IList<DissectedField>? ScertPayloadFields { get; set; }
    /// <summary>DME app messages packed in an APP record on a DME connection (object updates, game messages, …).</summary>
    public IList<ParsedDmeMessage>? Dme { get; set; }
    /// <summary>Absolute byte offset of the SCERT header within the full Ethernet frame.</summary>
    public int FrameOffset { get; set; }
    /// <summary>Total length of this SCERT record (header + optional hash + payload).</summary>
    public int FrameLength { get; set; }
}

/// <summary>
/// Maps a TCP port number to a Medius server name and tells the dissector
/// whether traffic on that port carries the SCERT binary protocol.
/// Populated from <c>Multiplayer/config.json</c> at runtime so user-overridden
/// ports are still recognised.
/// </summary>
public sealed record MediusPortEntry(int Port, string Name, bool Scert);

/// <summary>
/// Resolved port map used by <see cref="PacketDissector"/>. Built once from
/// the multiplayer config (or defaults) and reused per-dissection.
/// </summary>
public sealed class MediusPortMap
{
    public IReadOnlyDictionary<int, string> PortNames { get; }
    public IReadOnlySet<int>                ScertPorts { get; }

    public MediusPortMap(IEnumerable<MediusPortEntry> entries)
    {
        var names  = new Dictionary<int, string>();
        var scert  = new HashSet<int>();
        foreach (var e in entries)
        {
            names[e.Port] = e.Name;
            if (e.Scert) scert.Add(e.Port);
        }
        PortNames  = names;
        ScertPorts = scert;
    }

    /// <summary>
    /// Default port map. Used when no config is loaded — packet dissection
    /// still works against stock port assignments.
    /// </summary>
    /// <remarks>
    /// Note: <see cref="LoadFromMultiplayerConfig"/> returns this exact set
    /// whenever the multiplayer config file is missing or malformed. Keep the
    /// fallback ports in sync with the matching defaults in
    /// <see cref="Config.MultiplayerConfig"/>.
    /// </remarks>
    public static MediusPortMap Defaults { get; } = new(
    [
        new(10071, "MUIS", true),
        new(10078, "MAS",  true),
        new(10075, "MLS",  true),
        new(10070, "DME",  true),
        new(10069, "NAT",  true),
        new(443,   "DNAS", false),
        new(53,    "DNS",  false),
    ]);

    /// <summary>Returns the Medius server name for a TCP port pair, preferring the destination.</summary>
    public string ServerFromPorts(int srcPort, int dstPort)
    {
        if (PortNames.TryGetValue(srcPort, out var srcName) && srcName == "DNS") return "DNS";
        if (PortNames.TryGetValue(dstPort, out var dstName)) return dstName;
        if (PortNames.TryGetValue(srcPort, out var srcName2)) return srcName2;
        return string.Empty;
    }

    /// <summary>
    /// Build a <see cref="MediusPortMap"/> from the running multiplayer
    /// server's <c>config.json</c>. This is the canonical bridge between the
    /// server config and the packet dissector — without it, captures show
    /// blank "Server" columns whenever the user has overridden the default
    /// ports (e.g. MasPort 10077 vs the stock 10078).
    ///
    /// Searches:
    ///   1. <c>%LOCALAPPDATA%/CodeDesigner/Multiplayer/config.json</c> (Windows deploy)
    ///   2. <c>$HOME/.local/share/CodeDesigner/Multiplayer/config.json</c> (Linux/macOS deploy)
    ///   3. <see cref="Defaults"/> if neither is readable.
    /// </summary>
    public static MediusPortMap LoadFromMultiplayerConfig()
    {
        var candidates = new List<string>(2);
        var local = Environment.GetEnvironmentVariable("LOCALAPPDATA");
        if (!string.IsNullOrEmpty(local))
            candidates.Add(Path.Combine(local, "CodeDesigner", "Multiplayer", "config.json"));
        var home = Environment.GetEnvironmentVariable("HOME");
        if (!string.IsNullOrEmpty(home))
            candidates.Add(Path.Combine(home, ".local", "share", "CodeDesigner", "Multiplayer", "config.json"));

        foreach (var path in candidates)
        {
            if (!File.Exists(path)) continue;
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllBytes(path));
                if (!doc.RootElement.TryGetProperty("Online", out var online)) continue;

                int muis = online.TryGetProperty("MuisPort", out var p) ? p.GetInt32() : 10071;
                int mas  = online.TryGetProperty("MasPort",  out p)     ? p.GetInt32() : 10078;
                int mls  = online.TryGetProperty("MlsPort",  out p)     ? p.GetInt32() : 10075;
                int dme  = online.TryGetProperty("DmePort",  out p)     ? p.GetInt32() : 10070;
                int nat  = online.TryGetProperty("NatPort",  out p)     ? p.GetInt32() : 10069;
                int dnasHttps = online.TryGetProperty("DnasHttpsPort", out p) ? p.GetInt32() : 443;
                int dnsDnas   = online.TryGetProperty("DnsDnasPort",   out p) ? p.GetInt32() : 53;

                return new MediusPortMap(
                [
                    new(muis,      "MUIS", true),
                    new(mas,       "MAS",  true),
                    new(mls,       "MLS",  true),
                    new(dme,       "DME",  true),
                    new(nat,       "NAT",  true),
                    new(dnasHttps, "DNAS", false),
                    new(dnsDnas,   "DNS",  false),
                ]);
            }
            catch
            {
                // Fall through to next candidate (or defaults).
            }
        }

        return Defaults;
    }
}
