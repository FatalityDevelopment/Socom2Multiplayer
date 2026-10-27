using System;
using System.Security.Cryptography;

namespace DNAS;

/// <summary>
/// Four encrypted C1 identity proofs in on-wire A/B/D/C order. Their
/// ciphertext is decoded by the native proof engine before use by the server.
/// </summary>

public sealed class InitialFields
{
    public readonly byte[] A40;
    public readonly byte[] B56;
    public readonly byte[] Serial40;
    public readonly byte[] Disc32;

    public InitialFields(byte[] a40, byte[] b56, byte[] serial40, byte[] disc32)
    {
        Guard.Size(a40, 40, nameof(a40));
        Guard.Size(b56, 56, nameof(b56));
        Guard.Size(serial40, 40, nameof(serial40));
        Guard.Size(disc32, 32, nameof(disc32));
        A40 = (byte[])a40.Clone();
        B56 = (byte[])b56.Clone();
        Serial40 = (byte[])serial40.Clone();
        Disc32 = (byte[])disc32.Clone();
    }

    public byte[] Join()
    {
        byte[] output = new byte[168];
        Buffer.BlockCopy(A40, 0, output, 0, 40);
        Buffer.BlockCopy(B56, 0, output, 40, 56);
        Buffer.BlockCopy(Serial40, 0, output, 96, 40);
        Buffer.BlockCopy(Disc32, 0, output, 136, 32);
        return output;
    }
}
