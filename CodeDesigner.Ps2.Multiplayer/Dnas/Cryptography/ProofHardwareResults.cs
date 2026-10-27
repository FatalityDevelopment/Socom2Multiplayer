using System;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>
/// Exact CDVD command results used by the recorded upstream proof helpers.
/// They are kept as three independent hardware readouts: command 0x24,
/// command 0x26, and the five-byte DNAS identifier from ReadKey.
/// 0x24 contains the eight-byte ReadGUID result; 0x26 contains the
/// four-byte ModelID (or an eight-byte caller buffer whose last four
/// bytes are independently observed). Preserve the supplied length:
/// do not invent unobserved tail bytes, or conflate these with RTC.
/// </summary>
public sealed class ProofHardwareResults
{
    public readonly byte[] CDVD_READ_24;
    public readonly byte[] CDVD_READ_26;
    public readonly byte[] CDVD_READ_KEY;

    public ProofHardwareResults(byte[] cdvdRead24, byte[] cdvdRead26, byte[] cdvdReadKey)
    {
        if (cdvdRead24 == null || cdvdRead24.Length != 8) throw new ArgumentException("CDVD_READ_24 must contain eight result bytes.", nameof(cdvdRead24));
        if (cdvdRead26 == null || (cdvdRead26.Length != 4 && cdvdRead26.Length != 8)) throw new ArgumentException("CDVD_READ_26 needs four ModelID bytes or an actual eight-byte RPC buffer.", nameof(cdvdRead26));
        if (cdvdReadKey == null || cdvdReadKey.Length != 5) throw new ArgumentException("CDVD_READ_KEY must contain five identifier bytes.", nameof(cdvdReadKey));
        CDVD_READ_24 = (byte[])cdvdRead24.Clone();
        CDVD_READ_26 = (byte[])cdvdRead26.Clone();
        CDVD_READ_KEY = (byte[])cdvdReadKey.Clone();
    }
}
