using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>
/// One observed serial-to-disc-location mapping. The optional digest describes
/// the captured EE RAM fixture, NOT necessarily raw ISO bytes: the game can
/// modify sector content after loading it. No hidden hash check is imposed.
/// </summary>

public sealed class GameImageCatalog
{
    private readonly Dictionary<string, GameImageLocation> _entries = new(StringComparer.OrdinalIgnoreCase);

    public void Add(string serial, long lba, int sectorCount = DiscImage.ImageSectors, string sha256 = "")
    {
        GameImageLocation item = new(serial, lba, sectorCount, sha256);
        if (!_entries.TryAdd(item.Serial, item)) throw new ArgumentException("The game serial already has an image mapping.", nameof(serial));
    }

    public bool TryGet(string serial, out GameImageLocation? entry) => _entries.TryGetValue(Identity.NormalizeGameSerial(serial), out entry);

    public byte[] ReadImage(Stream iso, string gameSerial)
    {
        if (!TryGet(gameSerial, out GameImageLocation? location) || location == null) throw new KeyNotFoundException("No observed disc LBA has been registered for this serial.");
        return DiscImage.ReadSectors(iso, location.Lba, location.SectorCount);
    }

    public static GameImageCatalog Load(Stream json)
    {
        if (json == null) throw new ArgumentNullException(nameof(json));
        using JsonDocument doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Array) throw new FormatException("Expected a JSON array of known disc image locations.");
        GameImageCatalog catalog = new();
        foreach (JsonElement item in doc.RootElement.EnumerateArray())
        {
            string serial = item.GetProperty("serial").GetString() ?? throw new FormatException("Missing serial.");
            long lba = item.GetProperty("lba").GetInt64();
            int count = item.TryGetProperty("sectors", out JsonElement sc) ? sc.GetInt32() : DiscImage.ImageSectors;
            string hash = item.TryGetProperty("sha256", out JsonElement h) ? h.GetString() ?? "" : "";
            catalog.Add(serial, lba, count, hash);
        }
        return catalog;
    }

    /// <summary>Load user-provided mappings; the SDK never bundles title-specific disc offsets.</summary>
    public static GameImageCatalog LoadKnownGames(string path)
    {
        using Stream stream = File.OpenRead(path);
        return Load(stream);
    }
}
