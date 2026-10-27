using System;
using System.Buffers.Binary;
using System.IO;
using System.Numerics;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>
/// Instruction-level recovery of the protected entry block reached from the
/// PS2's second server-reply handler (EE 0x0052DAF0). This is research code:
/// it decodes MIPS instructions, NOT the response payload itself.
/// </summary>
public static class SecondReplyCode
{
    public const uint BodyPc = 0x0052DB5C;
    public const int BodyBytes = 24;
    public const uint TransformWord = 0xFEECF3B0;
    public const uint CodebookSelector = 0x440711BA;

    // Runtime EE log 669 proves that these two words are already decoded in
    // the saved snapshot. The other four undergo all seven transform stages.
    // In particular, this is verified against the *executed* opcode stream,
    // rather than relying exclusively on a static skip-table interpretation.
    private static bool Skip(int offset) => offset == 4 || offset == 12;

    /// <summary>
    /// Exact six decoded instructions at 0x0052DB5C: returns 144 when the
    /// native global word at 0x00560698 is 1, otherwise -8. This is merely
    /// an entry-status predicate, NOT proof that the server's 128-byte field
    /// was authenticated. The local initialization path is now decoded in NativeClientReadiness.
    /// </summary>
    public const uint SecondReplyStatusAddress = 0x00560698;

    /// <summary>
    /// Decoded protected 0x0052D8A4 entry, reached first from the original
    /// server-proof dispatcher at 0x004CBDF4. It sets return value to 16
    /// exactly when the previously initialized local readiness word is 1;
    /// otherwise returns -8. Neither branch consumes the 128-byte field.
    /// </summary>
    public static int EvaluatePrimaryEntryStatus(uint nativeGlobalStatus) => nativeGlobalStatus == 1 ? 16 : -8;
    public static int EvaluateDecodedEntryStatus(uint nativeGlobalStatus) => nativeGlobalStatus == 1 ? 144 : -8;

    /// <summary>
    /// Original outer handler's *observed register/status decision* at
    /// 0x004CBE24..0x004CBE54. The inner status check returns 144 when the
    /// native global is one; the outer handler returns 130 when bit zero of
    /// its independent working status is clear, otherwise -2. If inner is
    /// negative the outer caller propagates that failure. No response bytes
    /// are validated by these six opcodes or this helper: DO NOT use this as
    /// a retail proof validator or fabricated success path.
    /// </summary>
    public static int EvaluateObservedHandlerState(uint nativeGlobalStatus, uint callerWorkingStatus)
    {
        int inner = EvaluateDecodedEntryStatus(nativeGlobalStatus);
        if (inner < 0) return inner;
        return (callerWorkingStatus & 1) != 0 ? -2 : 130;
    }

    public static byte[] Decode(byte[] source) => Transform(source, false);
    public static byte[] Encode(byte[] source) => Transform(source, true);

    private static byte[] Transform(byte[] source, bool inverse)
    {
        if (source == null || source.Length != BodyBytes) throw new ArgumentException("Expected 24 bytes of original PS2 MIPS code.", nameof(source));
        byte[] result = (byte[])source.Clone();
        int count = (int)((TransformWord >> 28) & 7);
        for (int index = 0; index < count; index++)
        {
            int stage = inverse ? count - 1 - index : index;
            int op = (int)((TransformWord >> (stage * 4)) & 7);
            for (int offset = 0; offset < result.Length; offset += 4)
            {
                if (Skip(offset)) continue;
                uint word = BinaryPrimitives.ReadUInt32LittleEndian(result.AsSpan(offset, 4));
                BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(offset, 4), inverse ? Undo(word, op) : Apply(word, op));
            }
        }
        return result;
    }

    private static uint Apply(uint word, int op) => op switch
    {
        0 => word ^ 0x09F8ED17U,
        3 => BitOperations.RotateRight(word, 8),
        4 => Swap(word),
        6 => BitOperations.RotateRight(Swap(word) ^ 0xA95128C3U, 8),
        7 => Swap(BitOperations.RotateRight(word ^ 0x09F8ED17U, 21)),
        _ => throw new InvalidDataException("Unexpected second-reply entry transform stage.")
    };

    private static uint Undo(uint word, int op) => op switch
    {
        0 => word ^ 0x09F8ED17U,
        3 => BitOperations.RotateLeft(word, 8),
        4 => Unswap(word),
        6 => Unswap(BitOperations.RotateLeft(word, 8) ^ 0xA95128C3U),
        7 => BitOperations.RotateLeft(Unswap(word), 21) ^ 0x09F8ED17U,
        _ => throw new InvalidDataException("Unexpected second-reply entry transform stage.")
    };

    private static uint Swap(uint word) => ((word & 0x00FF0000U) >> 16) | ((word & 0x000000FFU) << 8) | ((word & 0xFF000000U) >> 8) | ((word & 0x0000FF00U) << 16);
    private static uint Unswap(uint word) => ((word & 0x0000FF00U) >> 8) | ((word & 0xFF000000U) >> 16) | ((word & 0x000000FFU) << 16) | ((word & 0x00FF0000U) << 8);
}
