using CodeDesigner.Ps2.Multiplayer.Models;

namespace CodeDesigner.Ps2.Multiplayer.Tests;

public class DmeWorldTests
{
    [Fact]
    public void Reserve_ReusesSlotForSameSession()
    {
        var world = new DmeWorld(0x1234, 10683, 4);
        try
        {
            var a = world.Reserve("session-a", 1);
            var again = world.Reserve("session-a", 1);
            var b = world.Reserve("session-b", 2);

            Assert.Same(a, again);
            Assert.NotEqual(a!.DmeId, b!.DmeId);
        }
        finally { world.Destroy(); }
    }

    [Fact]
    public void Reserve_ReturnsNullWhenFull()
    {
        var world = new DmeWorld(0x1235, 10683, 2);
        try
        {
            Assert.NotNull(world.Reserve("a", 1));
            Assert.NotNull(world.Reserve("b", 2));
            Assert.Null(world.Reserve("c", 3));
        }
        finally { world.Destroy(); }
    }

    [Fact]
    public async Task Reserve_IsAtomicPerSession()
    {
        var world = new DmeWorld(0x1236, 10683, 32);
        try
        {
            var slots = await Task.WhenAll(Enumerable.Range(0, 16)
                .Select(_ => Task.Run(() => world.Reserve("same-session", 1))));
            Assert.Single(slots.Select(s => s!.DmeId).Distinct());
            Assert.Single(world.Clients);
        }
        finally { world.Destroy(); }
    }
}
