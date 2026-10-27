using System.Collections.Concurrent;
using System.Net.Sockets;
using CodeDesigner.Ps2.Multiplayer.Models;
using CodeDesigner.Ps2.Multiplayer.Protocol;
using CodeDesigner.Ps2.Multiplayer.Storage;
using Microsoft.Extensions.Logging;

namespace CodeDesigner.Ps2.Multiplayer.Servers;

/// <summary>
/// Lobby memory scanner. While cheat-scan.json has Enabled = true, every logged-in lobby connection is walked
/// through the configured EE ranges with RAW_MEMORY cheat queries (ChunkSize bytes every IntervalMs), wrapping
/// back to the first range after the last. Replies are written to data/scans/&lt;account&gt;/&lt;range&gt;.bin
/// (file offset = address - range start, so the file lines up with the range in CodeDesigner) and, when a
/// ReferenceImage is set, compared byte-for-byte; mismatches are logged to data/scans/mismatches.log and
/// handled per OnMismatch (Log / Kick / Ban). The salted heartbeat keeping the lobby alive is untouched.
/// </summary>
public partial class MlsServer
{
    private static readonly ConcurrentDictionary<string, object> DumpLocks = new();
    private (string Path, DateTime Stamp, byte[] Bytes)? _reference;

    private async Task RunCheatScanLoopAsync(MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested && tcp.Connected && Clients.ContainsKey(state.ConnectionId))
            {
                var cfg = _admin.CheatScan;
                var ranges = cfg.Ranges.Where(r => SafeRange(r) is { } v && v.End > v.Start).ToList();
                if (!cfg.Enabled || ranges.Count == 0 || !state.ClientEchoSeen || state.AccountId == null)
                {
                    await Task.Delay(2000, ct);
                    continue;
                }

                if (state.ScanVersion != _admin.CheatScanVersion)
                {
                    state.ScanVersion    = _admin.CheatScanVersion;
                    state.ScanRangeIndex = 0;
                    state.ScanCursor     = ranges[0].StartAddress;
                    _log.LogInformation("[SCAN] {Acct}: scanning {Count} range(s) from 0x{Start:X8}", state.AccountName, ranges.Count, state.ScanCursor);
                }

                var range = ranges[state.ScanRangeIndex % ranges.Count];
                uint start = range.StartAddress, end = range.EndAddress;
                if (state.ScanCursor < start || state.ScanCursor >= end) state.ScanCursor = start;

                int chunk = (int)Math.Min((uint)Math.Clamp(cfg.ChunkSize, 4, 1024), end - state.ScanCursor);
                int seq = state.CheatSeq++;
                await SendPacketAsync(tcp, ScertPacket.CreateRawMemoryQuery(seq, state.ScanCursor, chunk), state, ct);

                state.ScanCursor += (uint)chunk;
                if (state.ScanCursor >= end)
                {
                    state.ScanRangeIndex = (state.ScanRangeIndex + 1) % ranges.Count;
                    state.ScanCursor = ranges[state.ScanRangeIndex].StartAddress;
                    if (state.ScanRangeIndex == 0)
                        _log.LogInformation("[SCAN] {Acct}: full pass complete, starting over", state.AccountName);
                }

                await Task.Delay(Math.Max(50, cfg.IntervalMs), ct);
            }
        }
        catch (OperationCanceledException) { /* disconnect / shutdown */ }
        catch (Exception ex)
        {
            _log.LogWarning("[SCAN] Scan loop for {Conn} stopped: {Msg}", state.ConnectionId, ex.Message);
        }
    }

    /// <summary>
    /// Cheat-query replies: [QueryType][SequenceId][Address][Length][Data]. RAW_MEMORY replies are scanner data;
    /// the salted-hash heartbeat replies need nothing.
    /// </summary>
    protected override Task HandleCheatQueryResponseAsync(ScertPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var p = packet.Payload;
        if (p.Length <= 13 || p[0] != (byte)CheatQueryType.DME_SERVER_CHEAT_QUERY_RAW_MEMORY)
            return Task.CompletedTask;

        uint address = BitConverter.ToUInt32(p, 5);
        var data = p[13..];
        if (PendingPeeks.TryRemove((state.ConnectionId, BitConverter.ToInt32(p, 1)), out var waiter))
        {
            waiter.TrySetResult(data);                    // debug-API peek, not scanner data
            return Task.CompletedTask;
        }
        try
        {
            ProcessScanChunk(state, tcp, address, data);
        }
        catch (Exception ex)
        {
            _log.LogWarning("[SCAN] Processing 0x{Addr:X8} from {Acct} failed: {Msg}", address, state.AccountName, ex.Message);
        }
        return Task.CompletedTask;
    }

    private void ProcessScanChunk(MediusClientState state, TcpClient tcp, uint address, byte[] data)
    {
        var cfg = _admin.CheatScan;
        string account = SafeFileName(state.AccountName is { Length: > 0 } n ? n : state.ConnectionId);
        _log.LogDebug("[SCAN] {Acct}: 0x{Addr:X8} +{Len}", account, address, data.Length);

        // Dump into the file of the range that holds this chunk.
        if (cfg.SaveDumps && cfg.Ranges.FirstOrDefault(r => SafeRange(r) is { } v && address >= v.Start && address < v.End) is { } range)
        {
            var dir = Path.Combine(_admin.Directory, "scans", account);
            Directory.CreateDirectory(dir);
            string label = SafeFileName(string.IsNullOrWhiteSpace(range.Label) ? "" : range.Label + "_");
            var path = Path.Combine(dir, $"{label}{range.StartAddress:X8}.bin");
            lock (DumpLocks.GetOrAdd(path, _ => new object()))
            {
                using var fs = new FileStream(path, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite);
                fs.Position = address - range.StartAddress;
                fs.Write(data);
            }
        }

        // Compare with the clean reference image.
        var reference = LoadReference(cfg);
        if (reference == null) return;
        uint refBase = AdminSettings.ParseAddress(cfg.ReferenceBase);
        if (address < refBase) return;
        long refOffset = address - refBase;
        int comparable = (int)Math.Min(data.Length, reference.Length - refOffset);
        if (comparable <= 0) return;

        int diffs = 0, firstDiff = -1;
        for (int i = 0; i < comparable; i++)
        {
            if (data[i] == reference[refOffset + i]) continue;
            diffs++;
            if (firstDiff < 0) firstDiff = i;
        }
        if (diffs == 0) return;

        uint at = address + (uint)firstDiff;
        int show = Math.Min(16, comparable - firstDiff);
        string got = Convert.ToHexString(data, firstDiff, show);
        string want = Convert.ToHexString(reference, (int)(refOffset + firstDiff), show);
        string line = $"{DateTime.UtcNow:u} {account} ({state.RemoteEndpoint}) 0x{address:X8}+{data.Length}: {diffs} byte(s) differ, first at 0x{at:X8} got {got} expected {want}";
        _log.LogWarning("[SCAN] MISMATCH {Line}", line);
        lock (DumpLocks.GetOrAdd("mismatches", _ => new object()))
        {
            Directory.CreateDirectory(Path.Combine(_admin.Directory, "scans"));
            File.AppendAllText(Path.Combine(_admin.Directory, "scans", "mismatches.log"), line + Environment.NewLine);
        }

        switch (cfg.OnMismatch.Trim().ToLowerInvariant())
        {
            case "ban" when state.AccountName is { Length: > 0 } name:
                _admin.BanAccount(name, $"cheat scan: {diffs} byte(s) differ at 0x{at:X8}");   // reload kicks them
                break;
            case "kick":
            case "ban":
                try { tcp.Close(); } catch { /* already gone */ }
                break;
        }
    }

    private byte[]? LoadReference(CheatScanSettings cfg)
    {
        if (string.IsNullOrWhiteSpace(cfg.ReferenceImage)) return null;
        var path = Path.IsPathRooted(cfg.ReferenceImage) ? cfg.ReferenceImage : Path.Combine(_admin.Directory, cfg.ReferenceImage);
        if (!File.Exists(path)) return null;

        var stamp = File.GetLastWriteTimeUtc(path);
        var cached = _reference;
        if (cached is { } c && c.Path == path && c.Stamp == stamp) return c.Bytes;

        var bytes = File.ReadAllBytes(path);
        _reference = (path, stamp, bytes);
        _log.LogInformation("[SCAN] Reference image loaded: {Path} ({Len} bytes)", path, bytes.Length);
        return bytes;
    }

    private static (uint Start, uint End)? SafeRange(ScanRange r)
    {
        try { return (r.StartAddress, r.EndAddress); }
        catch { return null; }
    }

    private static string SafeFileName(string name)
    {
        var bad = Path.GetInvalidFileNameChars();
        return new string(name.Select(ch => bad.Contains(ch) || ch == ' ' ? '_' : ch).ToArray());
    }
}
