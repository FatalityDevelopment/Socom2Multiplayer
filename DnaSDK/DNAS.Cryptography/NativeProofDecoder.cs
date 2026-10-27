using System;
using System.Security.Cryptography;

namespace DNAS;

/// <summary>
/// Mathematical inverse of the recovered 0x533AE8 shared-core pass ordering.
/// Extracts the original input without knowing the native RNG seed: the random
/// work areas are inside the invertible cipher envelope. This does not prove
/// historical server-side acceptance policy or trust in the caller's key bank.
/// </summary>
public static class NativeProofDecoder
{
    public sealed class Decoded
    {
        public readonly byte[] PlainInputPadded;
        public readonly byte[] RandomWork8;
        public readonly byte[] RandomWorkSecond8;
        public readonly byte[] FirstBlock8;
        public readonly bool FirstBlockValid;
        public readonly bool ParameterBitsValid;

        internal Decoded(byte[] input, byte[] first8, byte[] second8, byte[] firstBlock, bool firstValid, bool parameterValid)
        {
            PlainInputPadded = input;
            RandomWork8 = first8;
            RandomWorkSecond8 = second8;
            FirstBlock8 = firstBlock;
            FirstBlockValid = firstValid;
            ParameterBitsValid = parameterValid;
        }
    }

    public static Decoded Decode(byte[] ciphertext, int logicalInputLength, byte parameter, NativeProofCore.Material bank)
        => DecodeInternal(ciphertext, logicalInputLength, parameter, bank, true);

    /// <summary>
    /// Original inverse calculation when the per-stage CDVD first-block source
    /// is not yet known. The source is recovered from FirstBlock8 with the
    /// original module's fixed key/IV. FirstBlockValid is intentionally FALSE
    /// until the recovered source is rebound and verified by Decode().
    /// </summary>
    public static Decoded DecodeWithoutKnownFirstBlockSource(byte[] ciphertext, int logicalInputLength, byte parameter, NativeProofCore.Material bank)
        => DecodeInternal(ciphertext, logicalInputLength, parameter, bank, false);

    private static Decoded DecodeInternal(byte[] ciphertext, int logicalInputLength, byte parameter, NativeProofCore.Material bank, bool checkFirstBlock)
    {
        if (bank == null) throw new ArgumentNullException(nameof(bank));
        if (logicalInputLength < 0 || logicalInputLength > int.MaxValue - 31) throw new ArgumentOutOfRangeException(nameof(logicalInputLength));
        int padded = (logicalInputLength + 7) & ~7;
        if (ciphertext == null || ciphertext.Length != padded + 24) throw new ArgumentException("Unexpected original proof ciphertext length.", nameof(ciphertext));
        int length = ciphertext.Length;
        byte[] output = (byte[])ciphertext.Clone();

        // Invert 0x533D90, with K1=fp+32, K2=fp+48, K3=fp+40, IV=fp+56.
        byte[] finalFrame = DES.Encrypt(bank.FinalEcbSource32, bank.FinalEcbKey8);
        byte[] finalKey = Combine(finalFrame.AsSpan(0, 8), finalFrame.AsSpan(16, 8), finalFrame.AsSpan(8, 8));
        DES.Decrypt3(output.AsSpan(8, length - 8).ToArray(), finalKey, finalFrame.AsSpan(24, 8).ToArray()).CopyTo(output, 8);

        // Invert 0x533D20 after acquiring the original middle key/IV snapshots.
        byte[] first = output.AsSpan(0, 8).ToArray();
        byte[] middleKey = Combine(first, output.AsSpan(16, 8), first);
        byte[] middleIv = output.AsSpan(8, 8).ToArray();
        DES.Decrypt3(output.AsSpan(24, length - 24).ToArray(), middleKey, middleIv).CopyTo(output, 24);

        // Undo the exact three copy loops at 0x533C88..0x533D00.
        byte[] scratch = new byte[length];
        Buffer.BlockCopy(output, 0, scratch, 0, 8);
        Buffer.BlockCopy(output, length - 8, scratch, 8, 8);
        Buffer.BlockCopy(output, 8, scratch, 16, length - 16);

        // Invert 0x533C74 using fp[0..32) as prepared by 0x530500.
        byte[] frame = DES.Encrypt(bank.InitialEcbSource32, bank.InitialEcbKey8);
        byte[] longKey = Combine(frame.AsSpan(24, 8), frame.AsSpan(8, 8), frame.AsSpan(16, 8));
        DES.Decrypt3(scratch.AsSpan(8, length - 8).ToArray(), longKey, frame.AsSpan(0, 8).ToArray()).CopyTo(scratch, 8);

        byte[] recoveredBlock = scratch.AsSpan(16, 8).ToArray();
        bool blockValid = false;
        if (checkFirstBlock)
        {
            byte[] expectedBlock = DES.Encrypt3(bank.FirstBlockSource8, bank.FirstBlockKeyIv32.AsSpan(0, 24).ToArray(), bank.FirstBlockKeyIv32.AsSpan(24, 8).ToArray());
            blockValid = CryptographicOperations.FixedTimeEquals(recoveredBlock, expectedBlock);
        }
        byte[] work = scratch.AsSpan(0, 8).ToArray();
        return new Decoded(scratch.AsSpan(24, padded).ToArray(), work, scratch.AsSpan(8, 8).ToArray(), recoveredBlock, blockValid, (work[0] & 3) == (parameter & 3));
    }

    /// <summary>
    /// Recover the eight-byte native t2 input from a captured proof by
    /// reversing its first original EDE3-CBC block with the common DNAS key.
    /// This is forensic extraction, not a source of new-session clock data or
    /// evidence that the original server authorized the request.
    /// </summary>
    public static byte[] RecoverFirstBlockSource8(byte[] ciphertext, int logicalInputLength, byte parameter, NativeProofCore.Material bank)
    {
        Decoded decoded = Decode(ciphertext, logicalInputLength, parameter, bank);
        byte[] keys = bank.FirstBlockKeyIv32.AsSpan(0, 24).ToArray();
        byte[] vector = bank.FirstBlockKeyIv32.AsSpan(24, 8).ToArray();
        return DES.Decrypt3(decoded.FirstBlock8, keys, vector);
    }

    /// <summary>
    /// Checks original plaintext identity and the recovered native first-block
    /// relationship without assuming the caller's unused stack padding is zero.
    /// Verification of these calculations is NOT an authorization decision.
    /// </summary>
    public static bool VerifyIdentity(byte[] ciphertext, byte[] expectedLogicalInput, byte parameter, NativeProofCore.Material bank)
    {
        if (expectedLogicalInput == null) throw new ArgumentNullException(nameof(expectedLogicalInput));
        Decoded r = Decode(ciphertext, expectedLogicalInput.Length, parameter, bank);
        return r.FirstBlockValid && r.ParameterBitsValid &&
            CryptographicOperations.FixedTimeEquals(r.PlainInputPadded.AsSpan(0, expectedLogicalInput.Length), expectedLogicalInput);
    }

    /// <summary>
    /// Compare the ORIGINAL 16 RNG bytes embedded in each decrypted proof with
    /// the exact successful-stage 0x533B28/0x533B90 and cleanup schedule.
    /// Unlike the seed-free inverse, this requires a separately established
    /// native RNG state at entry. It assumes no intervening native RNG calls
    /// or reseeds between stages; use only when that premise is supported by
    /// the calling session trace. It does not establish server authorization.
    /// </summary>
    public static bool VerifySequentialRng(InitialFields fields, NativeProofCore.Material[] banks, ulong nativeEntryState, byte parameter = 2)
    {
        if (fields == null) throw new ArgumentNullException(nameof(fields));
        if (banks == null || banks.Length != 4) throw new ArgumentException("Four independent A/B/C/D native banks required.", nameof(banks));
        byte[][] encrypted = { fields.A40, fields.B56, fields.Disc32, fields.Serial40 };
        int[] lengths = { 16, 32, 5, 9 };
        NativeProofRandom rng = new(nativeEntryState);
        bool valid = true;
        for (int stage = 0; stage < 4; stage++)
        {
            Decoded recovered = Decode(encrypted[stage], lengths[stage], parameter, banks[stage]);
            NativeProofStageRandomTrace original = rng.TraceSuccessfulStage(lengths[stage], encrypted[stage].Length, parameter);
            valid &= CryptographicOperations.FixedTimeEquals(recovered.RandomWork8, original.First8);
            valid &= CryptographicOperations.FixedTimeEquals(recovered.RandomWorkSecond8, original.Second8);
        }
        return valid;
    }

    /// <summary>
    /// Validate captured proof-work bytes against a SINGLE original seeded
    /// LCG, including independently measured caller draws between stages.
    /// The cipher inverse also checks the real first-block/identity relation
    /// via VerifyIdentity before this method is used to authorize any stage.
    /// </summary>
    public static bool VerifyScheduledRng(InitialFields fields, NativeProofCore.Material[] banks, ulong nativeEntryState, NativeProofDrawSchedule schedule, byte parameter = 2)
    {
        if (fields == null) throw new ArgumentNullException(nameof(fields));
        if (banks == null || banks.Length != 4) throw new ArgumentException("Four A/B/C/D native material banks required.", nameof(banks));
        if (schedule == null) throw new ArgumentNullException(nameof(schedule));
        byte[][] encrypted = { fields.A40, fields.B56, fields.Disc32, fields.Serial40 };
        int[] lengths = { 16, 32, 5, 9 };
        NativeProofRandom rng = new(nativeEntryState);
        rng.Skip(schedule.BeforeFirst);
        bool valid = true;
        for (int stage = 0; stage < 4; stage++)
        {
            Decoded recovered = Decode(encrypted[stage], lengths[stage], parameter, banks[stage]);
            NativeProofStageRandomTrace original = rng.TraceSuccessfulStage(lengths[stage], encrypted[stage].Length, parameter);
            valid &= CryptographicOperations.FixedTimeEquals(recovered.RandomWork8, original.First8);
            valid &= CryptographicOperations.FixedTimeEquals(recovered.RandomWorkSecond8, original.Second8);
            rng.Skip(schedule.AfterStages[stage]);
        }
        return valid;
    }

    private static byte[] Combine(ReadOnlySpan<byte> k1, ReadOnlySpan<byte> k2, ReadOnlySpan<byte> k3)
    {
        byte[] result = new byte[24];
        k1.CopyTo(result.AsSpan(0, 8));
        k2.CopyTo(result.AsSpan(8, 8));
        k3.CopyTo(result.AsSpan(16, 8));
        return result;
    }
}
