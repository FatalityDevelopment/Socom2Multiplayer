using CodeDesigner.Ps2.Multiplayer.Config;
using Microsoft.Extensions.Configuration;

namespace CodeDesigner.Ps2.Multiplayer.Tests;

public class ConfigTests
{
    private static MultiplayerConfig Load(string json)
    {
        var path = Path.Combine(Path.GetTempPath(), $"socom2-config-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, json);
        try { return MultiplayerConfig.Load(new ConfigurationBuilder().AddJsonFile(path).Build()); }
        finally { File.Delete(path); }
    }

    [Fact]
    public void ConfiguredList_ReplacesDefaults()
    {
        var config = Load("""{ "Online": { "AllowedAppIds": [ 10472 ], "BriefingRooms": [ { "Name": "ONLY ROOM", "WorldId": 80 } ] } }""");

        Assert.Equal(new[] { 10472 }, config.AllowedAppIds);
        Assert.Single(config.BriefingRooms);
        Assert.Equal("ONLY ROOM", config.BriefingRooms[0].Name);
    }

    [Fact]
    public void MissingLists_KeepDefaults()
    {
        var config = Load("""{ "Online": { "ServerIp": "10.0.0.5" } }""");

        Assert.Empty(config.AllowedAppIds);
        Assert.Equal(BriefingRoomConfig.RetailDefaults().Count, config.BriefingRooms.Count);
        Assert.Equal(DefaultGameConfig.RetailDefaults().Count, config.DefaultGames.Count);
        Assert.Equal("10.0.0.5", config.ServerIp);
    }

    [Fact]
    public void EmptyList_ClearsDefaults()
    {
        var config = Load("""{ "Online": { "DefaultGames": [] } }""");
        Assert.Empty(config.DefaultGames);
    }

    [Fact]
    public void LegacyMediusSection_StillLoads()
    {
        var config = Load("""{ "Medius": { "ServerIp": "192.168.1.9", "MasPort": 12000 } }""");
        Assert.Equal("192.168.1.9", config.ServerIp);
        Assert.Equal(12000, config.MasPort);
    }

    [Fact]
    public void Defaults_MatchShippedPorts()
    {
        var config = new MultiplayerConfig();
        Assert.Equal(10077, config.MasPort);
        Assert.False(config.DnsForwardUnknown);
    }
}
