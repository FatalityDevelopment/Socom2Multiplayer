using System.Security.Cryptography;

namespace DNAS;

/// <summary>Generates server-side response framing and common result fields.</summary>
internal static class DnasServerConstants
{
    // This is the completion status used by the currently reconstructed
    // successful result path; historical backend authorization is not reconstructed.
    internal const byte CompatibleFinalResultFlag = 0x00;

    /// <summary>
    /// Generates a new 40-byte S1 header without captured metadata.
    /// Operation and body length are serialized by Packet.Make.
    /// The 23 metadata bytes, eight-byte session ID and header suffix
    /// are all freshly generated; each has been independently mutation-tested.
    /// </summary>
    internal static byte[] CreateS1Header40()
    {
        byte[] header = new byte[40];
        RandomNumberGenerator.Fill(header.AsSpan(4, 32));
        return header;
    }
}
