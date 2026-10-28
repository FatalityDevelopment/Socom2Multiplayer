using CodeDesigner.Ps2.Multiplayer.Protocol;

namespace CodeDesigner.Ps2.Multiplayer.Models;

/// <summary>Medius comparison operators, in wire order (horizon MediusComparisonOperator).</summary>
public enum MediusComparisonOperator
{
    LessThan             = 0,
    LessThanOrEqualTo    = 1,
    EqualTo              = 2,
    GreaterThanOrEqualTo = 3,
    GreaterThan          = 4,
    NotEquals            = 5,
}

/// <summary>
/// One SetGameListFilter0 condition: a game passes when <c>(field &amp; Mask) Op BaselineValue</c>.
/// </summary>
public sealed record GameListFilter(MediusGameListFilterField Field, uint Mask, MediusComparisonOperator Op, int BaselineValue)
{
    /// <summary>
    /// SetGameListFilter0 (v108): MessageID[21] | SessionKey[17] | pad2 | FilterField @0x28 | Mask @0x2C |
    /// ComparisonOperator @0x30 | BaselineValue @0x34 (horizon MediusSetGameListFilterRequest0). Null if too short.
    /// </summary>
    public static GameListFilter? Parse(byte[] payload)
    {
        const int at = MediusConstants.MESSAGEID_MAXLEN + MediusConstants.SESSIONKEY_MAXLEN + 2;
        if (payload.Length < at + 16) return null;
        return new GameListFilter(
            (MediusGameListFilterField)BitConverter.ToInt32(payload, at),
            BitConverter.ToUInt32(payload, at + 4),
            (MediusComparisonOperator)BitConverter.ToInt32(payload, at + 8),
            BitConverter.ToInt32(payload, at + 12));
    }

    public bool Matches(int value)
    {
        long v = value & Mask, b = BaselineValue;
        return Op switch
        {
            MediusComparisonOperator.LessThan             => v <  b,
            MediusComparisonOperator.LessThanOrEqualTo    => v <= b,
            MediusComparisonOperator.EqualTo              => v == b,
            MediusComparisonOperator.GreaterThanOrEqualTo => v >= b,
            MediusComparisonOperator.GreaterThan          => v >  b,
            MediusComparisonOperator.NotEquals            => v != b,
            _                                             => true,   // unknown operator: don't hide games
        };
    }
}
