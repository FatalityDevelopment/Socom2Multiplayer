using System;

namespace DNAS;

/// <summary>
/// Original shared-core output copy at 0x00533C88..0x00533D00, executed
/// after the long 0x00533C74 native pass and before the middle pass.
/// This is the verified buffer assembly, not a complete proof producer.
/// </summary>
public static class NativeProofAssembly
{
    public static byte[] AssembleAfterLongPass(byte[] scratch, int outputBytes)
    {
        if (scratch == null) throw new ArgumentNullException(nameof(scratch));
        if (outputBytes < 24 || (outputBytes & 7) != 0) throw new ArgumentOutOfRangeException(nameof(outputBytes));
        if (scratch.Length < outputBytes) throw new ArgumentException("The native scratch buffer does not cover the middle pass source.", nameof(scratch));
        byte[] result = new byte[outputBytes];
        // 0x533C88: scratch[0..8) -> out[0..8)
        Buffer.BlockCopy(scratch, 0, result, 0, 8);
        // 0x533CAC: scratch[16..(outputBytes)] -> out[8..(outputBytes-8)]
        Buffer.BlockCopy(scratch, 16, result, 8, outputBytes - 16);
        // 0x533CDC: scratch[8..16) -> out[(outputBytes-8)..outputBytes]
        Buffer.BlockCopy(scratch, 8, result, outputBytes - 8, 8);
        return result;
    }
}
