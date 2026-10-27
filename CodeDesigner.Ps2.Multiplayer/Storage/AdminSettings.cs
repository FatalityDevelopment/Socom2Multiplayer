using System.Globalization;
using System.Net;
using System.Text.Json;
using CodeDesigner.Ps2.Multiplayer.Config;
using Microsoft.Extensions.Logging;

namespace CodeDesigner.Ps2.Multiplayer.Storage;

/// <summary>A ban on an account name and/or an IP address. Until = null means permanent.</summary>
public class BanEntry
{
    public string Name { get; set; } = "";
    public string Reason { get; set; } = "";
    public DateTime? Until { get; set; }
    public DateTime Added { get; set; } = DateTime.UtcNow;

    [System.Text.Json.Serialization.JsonIgnore] public bool IsActive => Until == null || Until > DateTime.UtcNow;
}

/// <summary>bans.json — edited by hand (or by the cheat scanner); reloaded live.</summary>
public class BanList
{
    /// <summary>Banned account names (case-insensitive).</summary>
    public List<BanEntry> Accounts { get; set; } = new();
    /// <summary>Banned client IP addresses (the address the console connects from).</summary>
    public List<BanEntry> IpAddresses { get; set; } = new();

    public BanEntry? FindAccount(string name) =>
        Accounts.FirstOrDefault(b => b.IsActive && b.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

    public BanEntry? FindIp(IPAddress? ip) =>
        ip == null ? null
        : IpAddresses.FirstOrDefault(b => b.IsActive && IPAddress.TryParse(b.Name, out var banned)
                                          && banned.MapToIPv4().Equals(ip.MapToIPv4()));
}

/// <summary>One EE memory range the cheat scanner walks.</summary>
public class ScanRange
{
    public string Label { get; set; } = "";
    /// <summary>First address (hex "0x..." or decimal).</summary>
    public string Start { get; set; } = "0x00100000";
    /// <summary>End address, exclusive.</summary>
    public string End { get; set; } = "0x00110000";

    [System.Text.Json.Serialization.JsonIgnore] public uint StartAddress => AdminSettings.ParseAddress(Start);
    [System.Text.Json.Serialization.JsonIgnore] public uint EndAddress   => AdminSettings.ParseAddress(End);
}

/// <summary>
/// cheat-scan.json — the lobby memory scanner (reloaded live; a change restarts every client's scan from the
/// first range). Reads client memory through the Medius anti-cheat channel with RAW_MEMORY cheat queries,
/// ChunkSize bytes every IntervalMs, cycling through Ranges. Runs alongside (never instead of) the salted
/// anti-cheat heartbeat that keeps the lobby session alive.
/// </summary>
public class CheatScanSettings
{
    public bool Enabled { get; set; }
    public List<ScanRange> Ranges { get; set; } = new()
    {
        new ScanRange { Label = "SOCOM II code start", Start = "0x00100000", End = "0x00110000" },
    };
    /// <summary>Bytes per query (keep small — replies ride the lobby connection).</summary>
    public int ChunkSize { get; set; } = 256;
    /// <summary>Delay between queries per client, in milliseconds.</summary>
    public int IntervalMs { get; set; } = 1000;
    /// <summary>Write what each client returns into data/scans/&lt;account&gt;/&lt;rangeStart&gt;.bin (file offset = address - range start).</summary>
    public bool SaveDumps { get; set; } = true;
    /// <summary>Optional clean memory image to compare against (e.g. a known-good EE dump). Empty = no comparison.</summary>
    public string ReferenceImage { get; set; } = "";
    /// <summary>EE address of the reference image's first byte (0 for a full 32 MB EE dump).</summary>
    public string ReferenceBase { get; set; } = "0x00000000";
    /// <summary>What to do when scanned bytes differ from the reference: Log, Kick or Ban.</summary>
    public string OnMismatch { get; set; } = "Log";
}

/// <summary>
/// Hot-reloaded admin files in <see cref="MultiplayerConfig.DataDirectory"/>: bans.json and cheat-scan.json.
/// Missing files are created with defaults. Edits apply within ~1 s without a restart; a malformed file is
/// logged and the previous settings stay in force.
/// </summary>
public sealed class AdminSettings : IDisposable
{
    public const string BansFile = "bans.json";
    public const string CheatScanFile = "cheat-scan.json";

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, PropertyNameCaseInsensitive = true };

    private readonly ILogger<AdminSettings> _log;
    private readonly FileSystemWatcher _watcher;
    private readonly Timer _reloadTimer;
    private readonly object _writeLock = new();

    public string Directory { get; }
    public BanList Bans { get; private set; } = new();
    public CheatScanSettings CheatScan { get; private set; } = new();
    /// <summary>Bumped whenever cheat-scan.json reloads — clients restart their scan cursor on change.</summary>
    public int CheatScanVersion { get; private set; }

    /// <summary>Raised after bans.json reloads (servers kick newly banned players).</summary>
    public event Action<BanList>? BansChanged;

    public AdminSettings(MultiplayerConfig config, ILogger<AdminSettings> log)
    {
        _log = log;
        Directory = string.IsNullOrWhiteSpace(config.DataDirectory)
            ? Path.Combine(AppContext.BaseDirectory, "data")
            : config.DataDirectory;
        System.IO.Directory.CreateDirectory(Directory);

        EnsureDefault(BansFile, new BanList());
        EnsureDefault(CheatScanFile, new CheatScanSettings());
        Reload();

        _reloadTimer = new Timer(_ => Reload(), null, Timeout.Infinite, Timeout.Infinite);
        _watcher = new FileSystemWatcher(Directory, "*.json")
        {
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size,
            EnableRaisingEvents = true,
        };
        _watcher.Changed += OnFileEvent;
        _watcher.Created += OnFileEvent;
        _watcher.Renamed += OnFileEvent;
    }

    private void OnFileEvent(object sender, FileSystemEventArgs e)
    {
        var name = Path.GetFileName(e.FullPath);
        if (name.Equals(BansFile, StringComparison.OrdinalIgnoreCase) || name.Equals(CheatScanFile, StringComparison.OrdinalIgnoreCase))
            _reloadTimer.Change(500, Timeout.Infinite);   // debounce editor save bursts
    }

    private void Reload()
    {
        var bans = TryLoad<BanList>(BansFile);
        if (bans != null)
        {
            bool changed = JsonSerializer.Serialize(bans) != JsonSerializer.Serialize(Bans);
            Bans = bans;
            if (changed)
            {
                _log.LogInformation("[Admin] bans.json loaded: {Accounts} account ban(s), {Ips} IP ban(s)",
                    bans.Accounts.Count(b => b.IsActive), bans.IpAddresses.Count(b => b.IsActive));
                BansChanged?.Invoke(bans);
            }
        }

        var scan = TryLoad<CheatScanSettings>(CheatScanFile);
        if (scan != null && JsonSerializer.Serialize(scan) != JsonSerializer.Serialize(CheatScan))
        {
            CheatScan = scan;
            CheatScanVersion++;
            _log.LogInformation("[Admin] cheat-scan.json loaded: {State}, {Ranges} range(s), {Chunk} B every {Ms} ms, dumps={Dumps}, reference='{Ref}', on mismatch={Action}",
                scan.Enabled ? "ENABLED" : "disabled", scan.Ranges.Count, scan.ChunkSize, scan.IntervalMs,
                scan.SaveDumps, scan.ReferenceImage, scan.OnMismatch);
        }
    }

    private T? TryLoad<T>(string file) where T : class
    {
        var path = Path.Combine(Directory, file);
        for (int attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                return JsonSerializer.Deserialize<T>(File.ReadAllText(path), Json);
            }
            catch (IOException) { Thread.Sleep(100); }   // editor still writing
            catch (Exception ex)
            {
                _log.LogError("[Admin] {File} is invalid — keeping the previous settings: {Msg}", file, ex.Message);
                return null;
            }
        }
        return null;
    }

    private void EnsureDefault<T>(string file, T value)
    {
        var path = Path.Combine(Directory, file);
        if (!File.Exists(path)) File.WriteAllText(path, JsonSerializer.Serialize(value, Json));
    }

    /// <summary>Add an account ban and persist bans.json (the reload then kicks the player).</summary>
    public void BanAccount(string name, string reason)
    {
        lock (_writeLock)
        {
            var bans = TryLoad<BanList>(BansFile) ?? Bans;
            if (bans.FindAccount(name) != null) return;
            bans.Accounts.Add(new BanEntry { Name = name, Reason = reason });
            File.WriteAllText(Path.Combine(Directory, BansFile), JsonSerializer.Serialize(bans, Json));
        }
        _reloadTimer.Change(100, Timeout.Infinite);
    }

    public static uint ParseAddress(string text)
    {
        text = (text ?? "").Trim();
        return text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? uint.Parse(text[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture)
            : uint.Parse(text, CultureInfo.InvariantCulture);
    }

    public void Dispose()
    {
        _watcher.Dispose();
        _reloadTimer.Dispose();
    }
}
