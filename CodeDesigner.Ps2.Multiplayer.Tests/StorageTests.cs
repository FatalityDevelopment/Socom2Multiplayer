using CodeDesigner.Ps2.Multiplayer.Config;
using CodeDesigner.Ps2.Multiplayer.Storage;
using Microsoft.Extensions.Logging.Abstractions;

namespace CodeDesigner.Ps2.Multiplayer.Tests;

public sealed class StorageTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "socom2-tests-" + Guid.NewGuid().ToString("N"));

    private InMemoryStorage NewStore() =>
        new(new MultiplayerConfig { DataDirectory = _dir }, NullLogger<InMemoryStorage>.Instance);

    [Fact]
    public void Snapshot_RoundTripsAccounts()
    {
        using (var store = NewStore())
        {
            var a = store.TryCreateAccount("Masquarr", "hash")!;
            a.Buddies.Add(42);
            store.MarkDirty();
            store.Flush();
        }

        using var reloaded = NewStore();
        var back = reloaded.GetAccountByName("masquarr");
        Assert.NotNull(back);
        Assert.Equal("hash", back!.PasswordHash);
        Assert.Contains(42, back.Buddies);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }
}
