using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using System.Text.Json;

namespace CodeDesigner.Ps2.Multiplayer.Protocol;

/// <summary>One field of a game message: <c>type</c> is u8 s8 u16 s16 u32 s32 f32 str:N cstr or hex.</summary>
/// <c>Auto</c> is a derived-value rule such as <c>len(text)+6</c> (chat size).
public sealed record GameFieldDef(string Name, int Offset, string Type, bool Confirmed, string? Auto = null);

/// <summary>One SOCOM II application message: <c>[0x02][Id][data]</c> inside a DME app payload.</summary>
public sealed record GameMessageDef(byte Id, string Name, int? Size, string Target, string Description, IReadOnlyList<GameFieldDef> Fields, int? MinSize = null);

/// <summary>One field of a DME object class. On the wire it is referred to by <see cref="Index"/>.</summary>
public sealed record ObjectFieldDef(int Index, string Name, string Type, int Size);

/// <summary>One DME object class (SealState, GrenadeState, …) from the game's class table at 0x0067BE08.</summary>
public sealed record ObjectClassDef(byte Type, string Name, int StateSize, IReadOnlyList<ObjectFieldDef> Fields)
{
    /// <summary>Bytes an ObjectCreate carries after its 38-byte header: every field, in index order.</summary>
    public int RecordSize => Fields.Sum(f => f.Size);
}

/// <summary>
/// The game-specific half of the DME protocol: SOCOM II application messages (class 2) and DME
/// object classes. Loaded from <c>Mods/SOCOM2/packets/packets.json</c> and <c>objects.json</c>, the
/// same files <c>dme_objects.py</c>, <c>socom_bots.py</c> and <c>socom_server.py</c> read, so a
/// message added there is labelled by the packet viewer without touching C#.
/// </summary>
/// <remarks>
/// The files live outside this project (whose Docker build context is this folder only), so the
/// bridge embeds them and hands them to <see cref="Load(Stream, Stream)"/>.
/// </remarks>
public sealed class GameMessageCatalog
{
    public IReadOnlyDictionary<byte, GameMessageDef> Messages { get; }
    public IReadOnlyDictionary<byte, ObjectClassDef> Classes { get; }

    public GameMessageCatalog(IReadOnlyDictionary<byte, GameMessageDef> messages, IReadOnlyDictionary<byte, ObjectClassDef> classes)
    {
        Messages = messages;
        Classes  = classes;
    }

    public static GameMessageCatalog Empty { get; } = new(new Dictionary<byte, GameMessageDef>(), new Dictionary<byte, ObjectClassDef>());

    /// <summary>Parse packets.json and objects.json. Either stream may be null.</summary>
    public static GameMessageCatalog Load(Stream? packetsJson, Stream? objectsJson)
    {
        var messages = new Dictionary<byte, GameMessageDef>();
        if (packetsJson != null)
        {
            using var doc = JsonDocument.Parse(packetsJson);
            foreach (var p in doc.RootElement.GetProperty("packets").EnumerateArray())
            {
                byte id = (byte)ParseInt(p.GetProperty("id").GetString()!);
                int? size = p.TryGetProperty("size", out var s) && s.ValueKind == JsonValueKind.Number ? s.GetInt32() : null;
                var fields = new List<GameFieldDef>();
                if (p.TryGetProperty("fields", out var fs))
                    foreach (var f in fs.EnumerateArray())
                        fields.Add(new GameFieldDef(
                            f.GetProperty("name").GetString() ?? "?",
                            f.GetProperty("offset").GetInt32(),
                            f.GetProperty("type").GetString() ?? "hex",
                            f.TryGetProperty("confirmed", out var c) && c.ValueKind == JsonValueKind.True,
                            f.TryGetProperty("auto", out var a) && a.ValueKind == JsonValueKind.String ? a.GetString() : null));
                messages[id] = new GameMessageDef(
                    id,
                    p.GetProperty("name").GetString() ?? $"msg{id:X2}",
                    size,
                    p.TryGetProperty("target", out var t) ? t.GetString() ?? "" : "",
                    p.TryGetProperty("description", out var d) ? d.GetString() ?? "" : "",
                    fields,
                    p.TryGetProperty("minSize", out var ms) && ms.ValueKind == JsonValueKind.Number ? ms.GetInt32() : null);
            }
        }

        var classes = new Dictionary<byte, ObjectClassDef>();
        if (objectsJson != null)
        {
            using var doc = JsonDocument.Parse(objectsJson);
            foreach (var cls in doc.RootElement.GetProperty("classes").EnumerateObject())
            {
                byte type = (byte)ParseInt(cls.Name);
                var fields = new List<ObjectFieldDef>();
                foreach (var f in cls.Value.GetProperty("fields").EnumerateArray())
                {
                    int index = f.GetProperty("index").GetInt32();
                    string? name = f.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String ? n.GetString() : null;
                    fields.Add(new ObjectFieldDef(index, name ?? $"f{index:X2}", f.GetProperty("type").GetString() ?? "hex", f.GetProperty("size").GetInt32()));
                }
                fields.Sort((a, b) => a.Index.CompareTo(b.Index));
                classes[type] = new ObjectClassDef(type, cls.Value.GetProperty("name").GetString() ?? $"Class{type}",
                    cls.Value.TryGetProperty("stateSize", out var ss) ? ss.GetInt32() : 0, fields);
            }
        }
        return new GameMessageCatalog(messages, classes);
    }

    /// <summary>Bytes a game message's fixed part needs: its declared size, or the end of its last fixed field.</summary>
    public static int FixedSize(GameMessageDef def)
    {
        int end = 0;
        foreach (var f in def.Fields)
        {
            int w = TypeWidth(f.Type);
            if (w > 0) end = Math.Max(end, f.Offset + w);
        }
        return Math.Max(Math.Max(def.Size ?? 0, def.MinSize ?? 0), end);
    }

    /// <summary>Fixed width of a field type in bytes; 0 for the variable cstr/hex tails.</summary>
    public static int TypeWidth(string type) => type switch
    {
        "u8" or "s8"   => 1,
        "u16" or "s16" => 2,
        "u32" or "s32" or "f32" => 4,
        "vec3" => 12,
        _ when type.StartsWith("str:", StringComparison.Ordinal) => int.Parse(type.AsSpan(4), CultureInfo.InvariantCulture),
        _ => 0,
    };

    /// <summary>Render a field value the way <c>dme_objects.decode_value</c> does.</summary>
    public static string DecodeValue(string type, ReadOnlySpan<byte> data)
    {
        if (type.StartsWith("str:", StringComparison.Ordinal) || type == "cstr")
        {
            int end = data.IndexOf((byte)0);
            return $"\"{Encoding.Latin1.GetString(end < 0 ? data : data[..end])}\"";
        }
        if (type == "hex") return Convert.ToHexString(data);
        if (data.Length < TypeWidth(type)) return "?";
        return type switch
        {
            "u8"   => data[0].ToString(CultureInfo.InvariantCulture),
            "s8"   => ((sbyte)data[0]).ToString(CultureInfo.InvariantCulture),
            "u16"  => BinaryPrimitives.ReadUInt16LittleEndian(data).ToString(CultureInfo.InvariantCulture),
            "s16"  => BinaryPrimitives.ReadInt16LittleEndian(data).ToString(CultureInfo.InvariantCulture),
            "u32"  => FormatU32(BinaryPrimitives.ReadUInt32LittleEndian(data)),
            "s32"  => BinaryPrimitives.ReadInt32LittleEndian(data).ToString(CultureInfo.InvariantCulture),
            "f32"  => BinaryPrimitives.ReadSingleLittleEndian(data).ToString("0.##", CultureInfo.InvariantCulture),
            "vec3" => "(" + string.Join(", ",
                          BinaryPrimitives.ReadSingleLittleEndian(data).ToString("0.##", CultureInfo.InvariantCulture),
                          BinaryPrimitives.ReadSingleLittleEndian(data[4..]).ToString("0.##", CultureInfo.InvariantCulture),
                          BinaryPrimitives.ReadSingleLittleEndian(data[8..]).ToString("0.##", CultureInfo.InvariantCulture)) + ")",
            _      => Convert.ToHexString(data),
        };
    }

    /// <summary>Encode a field value typed by the user (decimal, 0x hex, float, text or hex bytes).</summary>
    public static byte[] EncodeValue(string type, string value, int width)
    {
        value = value.Trim();
        if (type.StartsWith("str:", StringComparison.Ordinal) || type == "cstr")
        {
            var raw = Encoding.Latin1.GetBytes(Unquote(value));
            if (type == "cstr") return [.. raw, 0];
            var buf = new byte[width];
            raw.AsSpan(0, Math.Min(raw.Length, width - 1)).CopyTo(buf);
            return buf;
        }
        if (type == "hex") return ParseHex(value);
        var outBuf = new byte[width];
        switch (type)
        {
            case "f32":
                BinaryPrimitives.WriteSingleLittleEndian(outBuf, float.Parse(value, CultureInfo.InvariantCulture));
                break;
            case "vec3":
            {
                var parts = value.Trim('(', ')').Split(',');
                for (int i = 0; i < 3 && i < parts.Length; i++)
                    BinaryPrimitives.WriteSingleLittleEndian(outBuf.AsSpan(i * 4), float.Parse(parts[i], CultureInfo.InvariantCulture));
                break;
            }
            default:
            {
                long v = ParseInt(value);
                for (int i = 0; i < width; i++) outBuf[i] = (byte)(v >> (i * 8));
                break;
            }
        }
        return outBuf;
    }

    /// <summary>Parse decimal or 0x-prefixed hex (negative allowed).</summary>
    public static long ParseInt(string s)
    {
        s = s.Trim();
        bool neg = s.StartsWith('-');
        if (neg) s = s[1..];
        long v = s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? long.Parse(s.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture)
            : long.Parse(s, CultureInfo.InvariantCulture);
        return neg ? -v : v;
    }

    /// <summary>Parse hex bytes, ignoring whitespace, commas and an optional 0x prefix.</summary>
    public static byte[] ParseHex(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var part in s.Split((char[])[' ', '\t', '\r', '\n', ','], StringSplitOptions.RemoveEmptyEntries))
            sb.Append(part.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? part[2..] : part);
        if (sb.Length % 2 != 0) throw new FormatException("Hex string has an odd number of digits");
        return Convert.FromHexString(sb.ToString());
    }

    private static string FormatU32(uint v) => v > 0xFFFF ? $"0x{v:X}" : v.ToString(CultureInfo.InvariantCulture);

    private static string Unquote(string s) => s.Length >= 2 && s[0] == '"' && s[^1] == '"' ? s[1..^1] : s;
}
