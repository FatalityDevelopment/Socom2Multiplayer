using System;

namespace DNAS;

/// <summary>
/// Byte layout of the original PS2 sceCdCLOCK structure returned by CDVD.
/// Its time fields are packed BCD, not ordinary integer bytes.
/// The initial DNAS proof producer reads this value through the game's
/// CDVD/subsystem wrapper at EE 0x0018F6E0.
/// </summary>
public static class Clock
{
    /// <summary>
    /// Packs the date/time into the original PS2 eight-byte CDVD clock format.
    /// The time supplied here must represent the PS2's RTC time, not necessarily
    /// the host's local or UTC time (those depend on console RTC configuration).
    /// </summary>
    public static byte[] Encode(DateTime ps2Time)
    {
        if (ps2Time.Year < 2000 || ps2Time.Year > 2099) throw new ArgumentOutOfRangeException(nameof(ps2Time), "PS2 CDVD clock uses a two-digit year relative to 2000.");
        return new byte[] { 0, Bcd(ps2Time.Second), Bcd(ps2Time.Minute), Bcd(ps2Time.Hour), 0, Bcd(ps2Time.Day), Bcd(ps2Time.Month), Bcd(ps2Time.Year % 100) };
    }

    /// <summary>
    /// Host-local clock adapter for standalone tools. It is not substituted for
    /// a real PS2 CDVD clock during proof verification unless that clock basis
    /// has been established for the running client.
    /// </summary>
    public static byte[] FromHostLocalTime() => Encode(DateTime.Now);

    private static byte Bcd(int value) => (byte)(((value / 10) << 4) | (value % 10));
}
