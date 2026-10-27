using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text.Json;

namespace DNAS;

/// <summary>
/// One observed serial-to-disc-location mapping. The optional digest describes
/// the captured EE RAM fixture, NOT necessarily raw ISO bytes: the game can
/// modify sector content after loading it. No hidden hash check is imposed.
/// </summary>

public sealed class GameImageLocation
{
    public readonly string Serial;
    public readonly long Lba;
    public readonly int SectorCount;
    public readonly string CapturedRamSha256;

    public GameImageLocation(string serial, long lba, int sectorCount, string sha256)
    {
        Serial = Identity.NormalizeGameSerial(serial);
        if (lba < 0 || lba > long.MaxValue / DiscImage.SectorBytes) throw new ArgumentOutOfRangeException(nameof(lba));
        if (sectorCount <= 0 || sectorCount > int.MaxValue / DiscImage.SectorBytes) throw new ArgumentOutOfRangeException(nameof(sectorCount));
        if (!string.IsNullOrEmpty(sha256) && (sha256.Length != 64 || Convert.FromHexString(sha256).Length != 32)) throw new FormatException("Expected 32-byte SHA-256 in hex.");
        Lba = lba;
        SectorCount = sectorCount;
        CapturedRamSha256 = sha256.ToUpperInvariant();
    }
}

/// <summary>
/// External metadata for known DNAS sector locations. This dictionary can be
/// updated without changing or rebuilding the cryptographic SDK.
/// </summary>
