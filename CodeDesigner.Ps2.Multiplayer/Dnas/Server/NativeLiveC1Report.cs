using System;
using System.Security.Cryptography;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>
/// Decoded C1 diagnostic evidence, with explicit separation between client-
/// recovered plaintext and independently configured identity expectations.
/// A correctly inverted encrypted request is not itself server authorization.
/// The proof's embedded clock bytes are reported without attempting to infer
/// how the client seeded or advanced its random-number generator.
/// </summary>

public sealed class NativeLiveC1Report
{
    public readonly byte[][] Actual;
    public readonly byte[][]? Expected;
    public readonly bool[] ParameterValid;
    public readonly bool[] FirstBlockValid;
    public readonly byte[][] FirstBlockSource8;
    public readonly bool EnvelopeValid;
    public readonly byte[] EnvelopeRandom16;
    public readonly byte[] ProofClock8;
    public readonly ProofInputPlan Identity;
    public readonly string[] Problems;

    private NativeLiveC1Report(byte[][] actual, byte[][]? expected, bool[] parameters, bool[] blocks, byte[][] sources, bool envelope, byte[] random16, byte[] proofClock, ProofInputPlan identity, string[] problems)
    {
        Actual = actual;
        Expected = expected;
        ParameterValid = parameters;
        FirstBlockValid = blocks;
        FirstBlockSource8 = sources;
        EnvelopeValid = envelope;
        EnvelopeRandom16 = random16;
        ProofClock8 = proofClock;
        Identity = identity;
        Problems = problems;
    }

    public static NativeLiveC1Report Inspect(byte[] request, ProofInputPlan? pinned = null)
    {
        UnwrappedInitial packet = new Server().InspectInitialClientProof(request);
        bool envelopeValid = packet.ZeroPaddingValid && packet.FixedTrailerValid;
        byte[][] encrypted = { packet.Fields.A40, packet.Fields.B56, packet.Fields.Disc32, packet.Fields.Serial40 };
        int[] lengths = { 16, 32, 5, 9 };
        byte[][] placeholders = { new byte[8], new byte[8], new byte[8], new byte[8] };
        NativeProofCore.Material[] banks = DnasProofConstants.CreateMaterials(placeholders);
        byte[][] actual = new byte[4][], sources = new byte[4][];
        bool[] parameterValid = new bool[4], firstBlockValid = new bool[4];
        var problems = new System.Collections.Generic.List<string>();
        if (!envelopeValid) problems.Add("C1 3DES envelope: zero-pad region or fixed trailer is incorrect.");
        for (int i = 0; i < 4; i++)
        {
            NativeProofDecoder.Decoded decoded = NativeProofDecoder.DecodeWithoutKnownFirstBlockSource(encrypted[i], lengths[i], 2, banks[i]);
            actual[i] = decoded.PlainInputPadded.AsSpan(0, lengths[i]).ToArray();
            parameterValid[i] = decoded.ParameterBitsValid;
            if (!parameterValid[i]) problems.Add($"Proof {"ABCD"[i]}: original parameter bits are invalid (expected 2).");
            byte[] key = banks[i].FirstBlockKeyIv32.AsSpan(0, 24).ToArray();
            byte[] iv = banks[i].FirstBlockKeyIv32.AsSpan(24, 8).ToArray();
            sources[i] = DES.Decrypt3(decoded.FirstBlock8, key, iv);
            byte[][] boundSources = { new byte[8], new byte[8], new byte[8], new byte[8] };
            boundSources[i] = sources[i];
            NativeProofCore.Material bound = DnasProofConstants.CreateMaterials(boundSources)[i];
            firstBlockValid[i] = NativeProofDecoder.VerifyIdentity(encrypted[i], actual[i], 2, bound);
            if (!firstBlockValid[i]) problems.Add($"Proof {"ABCD"[i]}: first-block native inverse relationship failed.");
        }
        if (!actual[0].AsSpan(8, 8).SequenceEqual(new byte[8]))
            problems.Add("Proof A: original producer requires eight zero tail bytes.");
        if (!actual[1].AsSpan().SequenceEqual(ProofInputs.InitialB32()))
            problems.Add("Proof B: original producer requires 32 bytes of FF.");
        string serial = System.Text.Encoding.ASCII.GetString(actual[3]);
        bool serialValid = serial.Length == 9;
        for (int j = 0; j < serial.Length; j++)
            serialValid &= j < 4 ? (serial[j] >= 'A' && serial[j] <= 'Z') : (serial[j] >= '0' && serial[j] <= '9');
        if (!serialValid) problems.Add("Proof D: game serial must contain four capital letters and five digits.");
        byte[][]? expected = pinned?.InputOrder();
        if (expected != null)
        {
            for (int i = 0; i < 4; i++)
                if (!actual[i].AsSpan().SequenceEqual(expected[i]))
                    problems.Add($"Proof {"ABCD"[i]}: recovered client identity differs from explicitly configured --console-id/--disc-id/--serial policy.");
        }
        ProofInputPlan inferred = ProofInputPlan.FromClientProofs(actual[0], actual[1], actual[2], actual[3]);
        return new NativeLiveC1Report(actual, expected, parameterValid, firstBlockValid, sources, envelopeValid, (byte[])packet.Random16.Clone(), (byte[])sources[0].Clone(), inferred, problems.ToArray());
    }

    /// <summary>Reject invalid C1 envelope, proof calculations, or configured identity.</summary>
    public void RequireValid()
    {
        if (Problems.Length != 0)
            throw new CryptographicException(string.Join(" ", Problems));
    }
}
