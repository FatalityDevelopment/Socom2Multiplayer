using System;
using System.Buffers.Binary;

namespace DNAS;

/// <summary>
/// Original DNAS CDVDMAN identity derivations on the normal hardware boot path.
/// RPC 0x24 calls sceCdReadGUID (eight bytes); RPC 0x26 calls
/// sceCdReadModelID (four bytes). Both derive from sceCdRI's eight-byte
/// i.Link ID when QueryBootMode(6) is absent. Special boot modes may use
/// ROM identity data or an IOP system-time fallback instead.
///
/// These methods calculate meaningful CDVD output data, not the surrounding
/// RPC success word or unspecified tail bytes of a reused 16-byte buffer.
/// </summary>
public static class CdvdIdentity
{
    public static byte[] ReadGuid24(ReadOnlySpan<byte> iLinkId)
    {
        if (iLinkId.Length != 8) throw new ArgumentException("The full i.Link ID must contain eight bytes.", nameof(iLinkId));
        byte[] result = new byte[8];
        BinaryPrimitives.WriteUInt32LittleEndian(result, 0x08004600U | iLinkId[0]);
        iLinkId[4..8].CopyTo(result.AsSpan(4));
        return result;
    }

    public static byte[] ReadModelId26(ReadOnlySpan<byte> iLinkId)
    {
        if (iLinkId.Length != 8) throw new ArgumentException("The full i.Link ID must contain eight bytes.", nameof(iLinkId));
        byte[] result = new byte[4];
        uint modelId = BinaryPrimitives.ReadUInt32LittleEndian(iLinkId[..4]) >> 8;
        BinaryPrimitives.WriteUInt32LittleEndian(result, modelId);
        return result;
    }
}
