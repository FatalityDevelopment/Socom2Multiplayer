using CodeDesigner.Ps2.Multiplayer.Config;
using CodeDesigner.Ps2.Multiplayer.Models;
using CodeDesigner.Ps2.Multiplayer.Storage;
using Microsoft.Extensions.Logging.Abstractions;

namespace CodeDesigner.Ps2.Multiplayer.Tests;

// DmeWorld keeps a static registry; keep the tests that sweep it from running alongside other world tests.
[Collection("DmeWorlds")]
public class DmeLifecycleTests
{
    [Fact]
    public void Sweep_ReleasesStaleReservationsAndDestroysEmptyWorlds()
    {
        var world = new DmeWorld(0x2001, 10683, 4) { SelfDestructFlag = true };
        world.Reserve("never-connects", 1);

        var destroyed = DmeWorld.Sweep(reservationTtl: TimeSpan.Zero, emptyGrace: TimeSpan.Zero);

        Assert.Contains(world, destroyed);
        Assert.True(world.IsDestroyed);
        Assert.Null(DmeWorld.GetById(world.WorldId));
        Assert.Null(world.Reserve("late", 2));   // a destroyed world takes no new players
    }

    [Fact]
    public void Sweep_KeepsConnectedPlayers()
    {
        var world = new DmeWorld(0x2002, 10683, 4) { SelfDestructFlag = true };
        try
        {
            var slot = world.Reserve("s", 1)!;
            Assert.NotNull(world.TryBind(slot.AccessKey, "conn-1"));

            DmeWorld.Sweep(TimeSpan.Zero, TimeSpan.Zero);

            Assert.False(world.IsDestroyed);
            Assert.Single(world.Clients);
        }
        finally { world.Destroy(); }
    }

    [Fact]
    public void TryBind_RefusesSecondConnectionOnSameSlot()
    {
        var world = new DmeWorld(0x2003, 10683, 4);
        try
        {
            var slot = world.Reserve("s", 1)!;
            Assert.Same(slot, world.TryBind(slot.AccessKey, "first"));
            Assert.Null(world.TryBind(slot.AccessKey, "second"));
            Assert.Equal("first", slot.BoundConnectionId);
        }
        finally { world.Destroy(); }
    }

    [Fact]
    public void RemoveClient_StaleHandleDoesNotEvictNewPlayer()
    {
        var world = new DmeWorld(0x2004, 10683, 1);
        try
        {
            var old = world.Reserve("a", 1)!;
            world.RemoveClient(old);
            var newer = world.Reserve("b", 2)!;
            Assert.Equal(old.DmeId, newer.DmeId);

            world.RemoveClient(old);   // late cleanup from the first connection

            Assert.Same(newer, world.Clients[newer.DmeId]);
        }
        finally { world.Destroy(); }
    }
}

public sealed class SnapshotRecoveryTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "socom2-tests-" + Guid.NewGuid().ToString("N"));

    private InMemoryStorage NewStore() =>
        new(new MultiplayerConfig { DataDirectory = _dir }, NullLogger<InMemoryStorage>.Instance);

    [Fact]
    public void CorruptSnapshot_FallsBackToBackup()
    {
        using (var store = NewStore())
        {
            store.TryCreateAccount("First", "h");
            store.Flush();
            store.TryCreateAccount("Second", "h");
            store.Flush();   // the first snapshot is now server-data.json.bak
        }
        File.WriteAllText(Path.Combine(_dir, "server-data.json"), "{ not json");

        using var reloaded = NewStore();
        Assert.NotNull(reloaded.GetAccountByName("First"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }
}

public class PresenceTests
{
    [Fact]
    public async Task RoomHops_LeaveThePlayerOnline()
    {
        var presence = new PresenceRegistry();
        presence.Connected(7, 1, "Community");

        // Each hop: the new connection comes up while the old one goes down.
        await Task.WhenAll(Enumerable.Range(0, 200).Select(i => Task.Run(() =>
        {
            presence.Connected(7, 0x44, "US EAST");
            presence.Disconnected(7);
        })));

        Assert.True(presence.IsOnline(7));
        presence.Disconnected(7);
        Assert.False(presence.IsOnline(7));
    }

    [Fact]
    public void RealLogin_TakesOverVirtualPlayer()
    {
        var presence = new PresenceRegistry();
        presence.AddVirtual(9, 0x44, "US EAST");
        presence.Connected(9, 0x44, "US EAST");
        Assert.False(presence.IsVirtual(9));
        presence.Disconnected(9);
        Assert.False(presence.IsOnline(9));
    }
}
