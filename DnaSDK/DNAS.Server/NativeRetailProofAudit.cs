using System;
using System.Security.Cryptography;

namespace DNAS;

/// <summary>
/// Validates the four original encrypted C1 identity proofs without making
/// assumptions about the client's random-number generator. C1 proof validity
/// and original backend authorization are separate concerns.
/// </summary>

public sealed class NativeRetailProofAudit
{
    public readonly byte[][] RecoveredFirstBlockSources8;
    public readonly byte[] ScratchTailC3;
    public readonly byte[] ScratchTailD7;
    public readonly byte[] EnvelopeRandom16;
    private NativeRetailProofAudit(byte[][] sources, byte[] tailC, byte[] tailD, byte[] envelope)
    {
        RecoveredFirstBlockSources8 = sources;
        ScratchTailC3 = tailC;
        ScratchTailD7 = tailD;
        EnvelopeRandom16 = envelope;
    }

    /// <summary>
    /// Independently verify four encrypted identity proofs and recover their
    /// first-block inputs. No RNG seed or draw schedule is required or inferred.
    /// Passing this check does not, on its own, establish backend authorization.
    /// </summary>
    public static NativeRetailProofAudit Inspect(byte[] request308, ProofInputPlan identity, byte parameter = 2)
    {
        if (identity == null) throw new ArgumentNullException(nameof(identity));
        UnwrappedInitial wire = new Server().InspectInitialClientProof(request308);
        if (!wire.ZeroPaddingValid || !wire.FixedTrailerValid) throw new CryptographicException("Original initial envelope integrity markers are invalid.");
        byte[][] ciphertext = { wire.Fields.A40, wire.Fields.B56, wire.Fields.Disc32, wire.Fields.Serial40 };
        byte[][] input = identity.InputOrder();
        // The first-block input is deliberately unknown here. Its placeholder
        // is NEVER used to calculate a proof or assert its validity: the
        // unbound inverse decrypts the independent 3DES key/IV and recovers
        // that exact input, then rebuilds materials and verifies every stage.
        byte[][] unboundSources = { new byte[8], new byte[8], new byte[8], new byte[8] };
        NativeProofCore.Material[] fixedBanks = DnasProofConstants.CreateMaterials(unboundSources);
        byte[][] sources = new byte[4][];
        NativeProofDecoder.Decoded[] decoded = new NativeProofDecoder.Decoded[4];
        for (int i = 0; i < 4; i++)
        {
            decoded[i] = NativeProofDecoder.DecodeWithoutKnownFirstBlockSource(ciphertext[i], input[i].Length, parameter, fixedBanks[i]);
            if (!decoded[i].ParameterBitsValid || !CryptographicOperations.FixedTimeEquals(decoded[i].PlainInputPadded.AsSpan(0, input[i].Length), input[i]))
                throw new CryptographicException($"Original native proof {i} does not recover the expected identity.");
            byte[] key24 = fixedBanks[i].FirstBlockKeyIv32.AsSpan(0, 24).ToArray();
            byte[] iv8 = fixedBanks[i].FirstBlockKeyIv32.AsSpan(24, 8).ToArray();
            sources[i] = DES.Decrypt3(decoded[i].FirstBlock8, key24, iv8);
        }
        NativeProofCore.Material[] boundBanks = DnasProofConstants.CreateMaterials(sources);
        for (int i = 0; i < 4; i++)
            if (!NativeProofDecoder.VerifyIdentity(ciphertext[i], input[i], parameter, boundBanks[i]))
                throw new CryptographicException($"Native proof {i} failed first-block verification.");

        byte[] cTail = decoded[2].PlainInputPadded.AsSpan(input[2].Length).ToArray();
        byte[] dTail = decoded[3].PlainInputPadded.AsSpan(input[3].Length).ToArray();
        return new NativeRetailProofAudit(sources, cTail, dTail, (byte[])wire.Random16.Clone());
    }
}
