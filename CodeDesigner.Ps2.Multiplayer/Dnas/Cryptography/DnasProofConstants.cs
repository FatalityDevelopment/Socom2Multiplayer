using System;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>
/// Static key and source material for the four standard DNAS C1 identity-proof transformations.
/// These are shared protocol cipher parameters, not per-title keys, game images or captured packets.
/// The caller-derived eight-byte source for each proof is decoded from THAT client request,
/// never substituted by a historical recording. All returned material banks own their buffers.
/// </summary>
public static class DnasProofConstants
{
    private static readonly byte[] ProofASource32 = Convert.FromHexString("45FE2794D89B48ED608502DD2FF7E0FFF283FFE046B488680D06C1211B3259D4");

    private static readonly byte[] ProofBSource32 = Convert.FromHexString("D23395E071E22179932EF2D8C03603BB0FA10C0FC228D8A56E95DFD2226AFFDC");

    private static readonly byte[] ProofCSource32 = Convert.FromHexString("1D8F6B07E857E4D2513B08A6BEEA990590D4984FC2395E9F5585ABF4CA109B46");

    private static readonly byte[] ProofDSource32 = Convert.FromHexString("0CAEDC67DEA75417633933766BB23292033815F0CF738DDFD72E57D037B44E8F");

    private static readonly byte[] FirstPairKeyIv32 = Convert.FromHexString("CE803ACA095A09864EA7C1D9FDD4B5EC23CEC571069FB6FDE1244E50AA7D8CB1");

    private static readonly byte[] SecondPairKeyIv32 = Convert.FromHexString("8948594D383CB87FFCCC795764A93E1A9C50E120FB59EA3F7FF82C09D60F9139");

    private static readonly byte[] FirstPairDesKey8 = Convert.FromHexString("50A776870FD1EA94");

    private static readonly byte[] SecondPairDesKey8 = Convert.FromHexString("E8ECB3027B1A7AC5");

    private static readonly byte[] FinalSource32 = Convert.FromHexString("4B1D507828F5273BD5BE93CE8C5D3AD88BB27470A0EB31712C1D02459E40397F");

    private static readonly byte[] FinalDesKey8 = Convert.FromHexString("82702B872D16B8F8");

    /// <summary>Build the four material banks in A/B/C/D execution order.</summary>
    public static NativeProofCore.Material[] CreateMaterials(byte[][] firstBlockSources8)
    {
        if (firstBlockSources8 == null || firstBlockSources8.Length != 4)
            throw new ArgumentException("Four eight-byte per-request source values are required.", nameof(firstBlockSources8));

        for (int i = 0; i < 4; i++)
            if (firstBlockSources8[i] == null || firstBlockSources8[i].Length != 8)
                throw new ArgumentException($"First-block source {i} must contain eight bytes.", nameof(firstBlockSources8));

        return new NativeProofCore.Material[]
        {
            new(ProofASource32, FirstPairDesKey8, firstBlockSources8[0], FirstPairKeyIv32, FinalSource32, FinalDesKey8),
            new(ProofBSource32, FirstPairDesKey8, firstBlockSources8[1], FirstPairKeyIv32, FinalSource32, FinalDesKey8),
            new(ProofCSource32, SecondPairDesKey8, firstBlockSources8[2], SecondPairKeyIv32, FinalSource32, FinalDesKey8),
            new(ProofDSource32, SecondPairDesKey8, firstBlockSources8[3], SecondPairKeyIv32, FinalSource32, FinalDesKey8)
        };
    }

    /// <summary>Use explicit final-pass snapshots only when the protocol caller supplies them.</summary>
    public static NativeProofCore.Material[] CreateMaterials(byte[][] firstBlockSources8, byte[][] finalSources32, byte[][] finalKeys8)
    {
        if (finalSources32 == null || finalSources32.Length != 4 || finalKeys8 == null || finalKeys8.Length != 4)
            throw new ArgumentException("Expected four final-pass sources and keys.");

        NativeProofCore.Material[] standard = CreateMaterials(firstBlockSources8);
        NativeProofCore.Material[] result = new NativeProofCore.Material[4];
        for (int i = 0; i < 4; i++)
        {
            NativeProofCore.Material source = standard[i];
            result[i] = new NativeProofCore.Material(source.InitialEcbSource32, source.InitialEcbKey8, source.FirstBlockSource8, source.FirstBlockKeyIv32, finalSources32[i], finalKeys8[i]);
        }
        return result;
    }
}
