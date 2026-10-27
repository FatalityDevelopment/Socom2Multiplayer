using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace CodeDesigner.Ps2.Multiplayer.Protocol;

/// <summary>
/// One field of a <see cref="CatalogEntry"/>. <see cref="Type"/> is one of
/// uint, int, bool, f32, vec3, string (NUL-padded, <see cref="Length"/> bytes), bytes
/// (fixed), cstr (NUL-terminated tail) or hex (raw tail).
/// </summary>
public sealed record CatalogField(
    [property: JsonPropertyName("name")]    string Name,
    [property: JsonPropertyName("type")]    string Type,
    [property: JsonPropertyName("offset")]  int Offset,
    [property: JsonPropertyName("length")]  int Length,
    [property: JsonPropertyName("options")] IReadOnlyList<string>? Options = null,
    [property: JsonPropertyName("auto")]    string? Auto = null,
    [property: JsonPropertyName("optional")] bool Optional = false);

/// <summary>
/// One message the multiplayer server knows about. <see cref="Protocol"/> is one of the
/// <c>MessageCatalog.*</c> protocol names; <see cref="Name"/> is exactly what the packet
/// viewer labels the message with.
/// </summary>
public sealed record CatalogEntry(
    [property: JsonPropertyName("protocol")]    string Protocol,
    [property: JsonPropertyName("cls")]         byte Class,
    [property: JsonPropertyName("id")]          byte Id,
    [property: JsonPropertyName("name")]        string Name,
    [property: JsonPropertyName("description")] string Description,
    [property: JsonPropertyName("size")]        int? Size,
    [property: JsonPropertyName("fields")]      IReadOnlyList<CatalogField> Fields);

/// <summary>
/// Every message the multiplayer server defines, built from its own definitions rather than a
/// hand-kept list: the SCERT <see cref="RT_MSG_TYPE"/> enum, the Medius Lobby / LobbyExt / MGCL
/// enums the servers dispatch on (with <see cref="MediusStructSchemas"/> field layouts), the
/// <see cref="DmeAppMessageId"/> enum, and the SOCOM II game messages and DME object classes
/// from <see cref="GameMessageCatalog"/>. Adding a member to one of those enums or an entry to
/// packets.json / objects.json adds it here, to the packet viewer's labels and to its composer.
/// </summary>
public static class MessageCatalog
{
    public const string Scert    = "SCERT";
    public const string Lobby    = "Lobby";
    public const string LobbyExt = "LobbyExt";
    public const string Mgcl     = "MGCL";
    public const string Dme      = "DME";
    public const string Game     = "Game";
    public const string Object   = "Object";

    public static IReadOnlyList<CatalogEntry> Build(GameMessageCatalog game)
    {
        var list = new List<CatalogEntry>();

        foreach (var rt in DistinctValues<RT_MSG_TYPE>())
        {
            var fields = MediusStructSchemas.ScertPayloads.TryGetValue((byte)rt, out var def) ? FromStruct(def) : [];
            list.Add(new CatalogEntry(Scert, 0, (byte)rt, rt.ToString(), "", null, fields));
        }

        AddMedius<MediusLobbyMessageId>(list, Lobby, (byte)NetMessageClass.MessageClassLobby);
        AddMedius<MediusLobbyExtMessageId>(list, LobbyExt, (byte)NetMessageClass.MessageClassLobbyExt);
        AddMedius<MediusDmeMessageIds>(list, Mgcl, (byte)NetMessageClass.MessageClassDME);

        foreach (var id in DistinctValues<DmeAppMessageId>())
            list.Add(new CatalogEntry(Dme, (byte)NetMessageClass.MessageClassDME, (byte)id, id.ToString(),
                DmeDescription(id), null, DmeFields(id)));

        foreach (var m in game.Messages.Values.OrderBy(m => m.Id))
            list.Add(new CatalogEntry(Game, (byte)NetMessageClass.MessageClassApplication, m.Id, m.Name,
                m.Description, m.Size, m.Fields.Select(FromGameField).ToList()));

        foreach (var c in game.Classes.Values.OrderBy(c => c.Type))
        {
            int off = 0;
            var fields = new List<CatalogField>();
            foreach (var f in c.Fields)
            {
                fields.Add(new CatalogField($"[{f.Index:X2}] {f.Name}", MapGameType(f.Type), off, f.Size));
                off += f.Size;
            }
            list.Add(new CatalogEntry(Object, (byte)NetMessageClass.MessageClassDME, c.Type, c.Name,
                $"DME object class {c.Type}: {c.Fields.Count} fields, state {c.StateSize} bytes. Sent as ObjectCreate (every field) and ObjectUpdate (changed fields by index).",
                c.RecordSize, fields));
        }
        return list;
    }

    // ── Encoding ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Encode one message: the app payload <c>[class][id][body]</c> for Medius/DME/Game entries, or
    /// the SCERT record body for SCERT entries. Missing values are zero; <c>values["Payload"]</c>
    /// (hex) is appended after the fields, which is how a message without a schema gets a body.
    /// </summary>
    public static byte[] Encode(CatalogEntry entry, IReadOnlyDictionary<string, string> values)
    {
        if (entry.Protocol == Object)
            throw new ArgumentException("Object classes aren't messages: build an ObjectCreate/ObjectUpdate (DME) and put the fields in Payload");

        var body = EncodeFields(entry, values);
        if (values.TryGetValue("Payload", out var extra) && !string.IsNullOrWhiteSpace(extra))
            body = [.. body, .. GameMessageCatalog.ParseHex(extra)];
        return entry.Protocol == Scert ? body : [entry.Class, entry.Id, .. body];
    }

    /// <summary>
    /// Wrap an app payload (or SCERT body) in a plaintext SCERT record:
    /// <c>[type][len:u16 LE][target prefix][payload]</c>. <paramref name="target"/> fills the u16
    /// of APP_SINGLE (target or, server → client, source) and the one-entry list of APP_LIST.
    /// </summary>
    public static byte[] WrapScert(RT_MSG_TYPE type, byte[] payload, int target = 0)
    {
        byte[] prefix = type switch
        {
            RT_MSG_TYPE.RT_MSG_CLIENT_APP_SINGLE or RT_MSG_TYPE.RT_MSG_CLIENT_APP_SINGLE_QOS => [(byte)target, (byte)(target >> 8)],
            RT_MSG_TYPE.RT_MSG_CLIENT_APP_LIST or RT_MSG_TYPE.RT_MSG_CLIENT_APP_LIST_QOS     => [1, (byte)target, (byte)(target >> 8)],
            _ => [],
        };
        int len = prefix.Length + payload.Length;
        if (len > ushort.MaxValue) throw new ArgumentException("SCERT payload too long");
        return [(byte)type, (byte)len, (byte)(len >> 8), .. prefix, .. payload];
    }

    private static readonly Regex s_autoLen = new(@"^len\((\w+)\)\s*\+\s*(\d+)$", RegexOptions.Compiled);

    private static byte[] EncodeFields(CatalogEntry entry, IReadOnlyDictionary<string, string> values)
    {
        int fixedEnd = 0;
        foreach (var f in entry.Fields)
            if (!IsTail(f.Type) && (!f.Optional || values.ContainsKey(f.Name)))
                fixedEnd = Math.Max(fixedEnd, f.Offset + f.Length);
        var buf = new byte[Math.Max(entry.Size ?? 0, fixedEnd)];
        byte[] tail = [];
        int tailAt = buf.Length;

        foreach (var f in entry.Fields)
        {
            if (!values.TryGetValue(f.Name, out var v) || (v.Length == 0 && !IsTail(f.Type))) continue;
            if (IsTail(f.Type))
            {
                tailAt = Math.Min(tailAt, f.Offset);
                tail = f.Type == "cstr" ? [.. Encoding.Latin1.GetBytes(v), 0] : GameMessageCatalog.ParseHex(v);
                continue;
            }
            byte[] enc = EncodeValue(f, v);
            enc.AsSpan(0, Math.Min(enc.Length, f.Length)).CopyTo(buf.AsSpan(f.Offset));
        }

        byte[] data = [.. buf.AsSpan(0, Math.Min(tailAt, buf.Length)), .. tail];

        // Derived fields (chat size = len(text)+6): filled unless the user typed a value.
        foreach (var f in entry.Fields)
        {
            if (f.Auto == null || values.ContainsKey(f.Name) && values[f.Name].Length > 0) continue;
            var m = s_autoLen.Match(f.Auto.Trim());
            if (!m.Success) continue;
            values.TryGetValue(m.Groups[1].Value, out var src);
            long size = Encoding.Latin1.GetByteCount(src ?? "") + long.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture);
            if (f.Offset + f.Length > data.Length) Array.Resize(ref data, f.Offset + f.Length);
            for (int i = 0; i < f.Length; i++) data[f.Offset + i] = (byte)(size >> (i * 8));
            if (f.Name == "size" && data.Length < size) Array.Resize(ref data, (int)size);   // the game sends exactly `size` bytes
        }
        return data;
    }

    private static byte[] EncodeValue(CatalogField f, string v)
    {
        v = v.Trim();
        switch (f.Type)
        {
            case "bool":
                return Le(v is "true" or "True" or "yes" ? 1 : v is "false" or "False" or "no" ? 0 : GameMessageCatalog.ParseInt(v), f.Length);
            case "uint":
            case "int":
            {
                // Enum fields accept the option name ("MediusSuccess") or a number.
                if (f.Options != null)
                {
                    var hit = f.Options.FirstOrDefault(o => o.EndsWith($"({v})", StringComparison.Ordinal) || o.StartsWith(v + " ", StringComparison.Ordinal) || o == v);
                    if (hit != null && hit.LastIndexOf('(') is int lp and >= 0)
                        v = hit[(lp + 1)..^1];
                }
                return Le(GameMessageCatalog.ParseInt(v), f.Length);
            }
            case "string":
                return GameMessageCatalog.EncodeValue($"str:{f.Length}", v, f.Length);
            case "bytes":
                try { return GameMessageCatalog.ParseHex(v); }
                catch (FormatException) { return Encoding.Latin1.GetBytes(v); }   // text typed into a bytes field (message ids, keys)
            default:
                return GameMessageCatalog.EncodeValue(f.Type, v, f.Length);
        }
    }

    private static byte[] Le(long v, int width)
    {
        var b = new byte[width];
        for (int i = 0; i < width; i++) b[i] = (byte)(v >> (i * 8));
        return b;
    }

    private static bool IsTail(string type) => type is "cstr" or "hex";

    // ── Builders ─────────────────────────────────────────────────────────────

    private static void AddMedius<TEnum>(List<CatalogEntry> list, string protocol, byte cls) where TEnum : struct, Enum
    {
        foreach (var v in DistinctValues<TEnum>())
        {
            byte id = Convert.ToByte(v, CultureInfo.InvariantCulture);
            var fields = MediusStructSchemas.Medius.TryGetValue((id << 8) | cls, out var def) ? FromStruct(def) : [];
            list.Add(new CatalogEntry(protocol, cls, id, PacketDissector.MediusTypeName(cls, id), "", null, fields));
        }
    }

    /// <summary>Enum values with duplicates (aliases such as TicketLogin/InvitePlayerToClan) collapsed.</summary>
    private static IEnumerable<T> DistinctValues<T>() where T : struct, Enum
        => Enum.GetValues<T>().Distinct().OrderBy(v => Convert.ToUInt64(v, CultureInfo.InvariantCulture));

    private static List<CatalogField> FromStruct(MediusStructDef def)
    {
        var list = new List<CatalogField>();
        int off = 0;
        foreach (var f in def.Fields)
        {
            IReadOnlyList<string>? options = null;
            if (f.EnumDict != null) options = f.EnumDict.Select(kv => $"{kv.Value} ({kv.Key})").ToList();
            else if (f.EnumType != null)
                options = Enum.GetValues(f.EnumType).Cast<object>()
                    .Select(o => $"{Enum.GetName(f.EnumType, o)} ({Convert.ToInt64(o, CultureInfo.InvariantCulture)})").Distinct().ToList();
            string type = f.Type switch
            {
                MediusFieldType.UInt   => "uint",
                MediusFieldType.Bool   => "bool",
                MediusFieldType.AsciiZ => "string",
                _                      => "bytes",
            };
            list.Add(new CatalogField(f.Name, type, off, f.Length, options, Optional: f.Optional));
            off += f.Length;
        }
        return list;
    }

    private static CatalogField FromGameField(GameFieldDef f)
        => new(f.Name, MapGameType(f.Type), f.Offset, GameMessageCatalog.TypeWidth(f.Type), Auto: f.Auto);

    private static string MapGameType(string t) => t switch
    {
        "u8" or "u16" or "u32" => "uint",
        "s8" or "s16" or "s32" => "int",
        _ when t.StartsWith("str:", StringComparison.Ordinal) => "string",
        _ => t,
    };

    private static List<CatalogField> DmeFields(DmeAppMessageId id) => id switch
    {
        DmeAppMessageId.ServerVersion => [new("Version", "string", 0, MediusConstants.DME_VERSION_LENGTH)],
        DmeAppMessageId.Ping =>
        [
            new("Time Of Send",  "uint", 0, 4),
            new("Ping Instance", "uint", 4, 1),
            new("Request Echo",  "bool", 5, 1),
            new("Padding",       "bytes", 6, 2),
        ],
        DmeAppMessageId.ObjectDestroy => [new("Object Id", "uint", 0, 2)],
        DmeAppMessageId.ObjectUpdate =>
        [
            new("Class",       "uint", 0, 1),
            new("Field Count", "uint", 1, 1),
            new("Object Id",   "uint", 2, 2),
        ],
        DmeAppMessageId.ObjectCreate =>
        [
            new("Owner",       "uint",   0, 1),
            new("Class",       "uint",   1, 1),
            new("Reserved",    "bytes",  2, 2),
            new("Two",         "uint",   4, 4),
            new("Object Id",   "uint",   8, 4),
            new("Stamp",       "uint",   12, 4),
            new("Zero",        "uint",   16, 4),
            new("Object Name", "string", 20, 16),
        ],
        _ => [],
    };

    private static string DmeDescription(DmeAppMessageId id) => id switch
    {
        DmeAppMessageId.ObjectUpdate => "Then Field Count × [field index:1][value] in Payload (sizes from the object class).",
        DmeAppMessageId.ObjectCreate => "Then every field of the class in index order in Payload.",
        _ => "",
    };
}
