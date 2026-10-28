using CodeDesigner.Ps2.Multiplayer.Models;
using CodeDesigner.Ps2.Multiplayer.Protocol;

namespace CodeDesigner.Ps2.Multiplayer.Tests;

public class GameListFilterTests
{
    [Theory]
    [InlineData(MediusComparisonOperator.LessThan, 5, 6, true)]
    [InlineData(MediusComparisonOperator.LessThan, 6, 6, false)]
    [InlineData(MediusComparisonOperator.LessThanOrEqualTo, 6, 6, true)]
    [InlineData(MediusComparisonOperator.EqualTo, 0x44, 0x44, true)]
    [InlineData(MediusComparisonOperator.GreaterThanOrEqualTo, 6, 6, true)]
    [InlineData(MediusComparisonOperator.GreaterThan, 6, 6, false)]
    [InlineData(MediusComparisonOperator.NotEquals, 1, 2, true)]
    public void Matches_AppliesOperator(MediusComparisonOperator op, int value, int baseline, bool expected)
    {
        var f = new GameListFilter(MediusGameListFilterField.MEDIUS_FILTER_PLAYER_COUNT, 0xFFFFFFFF, op, baseline);
        Assert.Equal(expected, f.Matches(value));
    }

    [Fact]
    public void Matches_AppliesMaskFirst()
    {
        var f = new GameListFilter(MediusGameListFilterField.MEDIUS_FILTER_GENERIC_FIELD_1, 0xFF, MediusComparisonOperator.EqualTo, 0x44);
        Assert.True(f.Matches(0x05000044));
    }

    [Fact]
    public void Parse_ReadsV108Layout()
    {
        var p = new byte[0x38];
        BitConverter.GetBytes(10).CopyTo(p, 0x28);          // LOBBY_WORLDID
        BitConverter.GetBytes(0xFFu).CopyTo(p, 0x2C);
        BitConverter.GetBytes(2).CopyTo(p, 0x30);           // EqualTo
        BitConverter.GetBytes(0x44).CopyTo(p, 0x34);

        var f = GameListFilter.Parse(p)!;
        Assert.Equal(MediusGameListFilterField.MEDIUS_FILTER_LOBBY_WORLDID, f.Field);
        Assert.Equal(0xFFu, f.Mask);
        Assert.Equal(MediusComparisonOperator.EqualTo, f.Op);
        Assert.Equal(0x44, f.BaselineValue);
        Assert.Null(GameListFilter.Parse(new byte[10]));
    }
}
