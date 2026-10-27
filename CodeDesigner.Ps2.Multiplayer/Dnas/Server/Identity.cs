using System;
using System.Text.RegularExpressions;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>
/// Input parsing for the identifiers that a client obtains from SYSTEM.CNF and
/// CDVD ReadKey (N-command 0x4B). Parsing is proven; the SDK's subsequent
/// cryptographic binding of these identifiers is still being reconstructed.
/// </summary>
public static class Identity
{
    /// <summary>Converts SCUS_972.75, SCUS-97275 and similar PS2 serial forms to SCUS-97275.</summary>
    public static string NormalizeGameSerial(string gameSerial)
    {
        if (string.IsNullOrWhiteSpace(gameSerial)) throw new ArgumentException("Game serial is required.", nameof(gameSerial));
        string value = gameSerial.Trim().ToUpperInvariant();
        Match match = Regex.Match(value, @"^([A-Z]{4})[-_]?([0-9]{3})\.?([0-9]{2})$");
        if (!match.Success) throw new ArgumentException("Expected a PS2 serial such as SCUS-97275 or SLUS_206.68.", nameof(gameSerial));
        return $"{match.Groups[1].Value}-{match.Groups[2].Value}{match.Groups[3].Value}";
    }

    /// <summary>
    /// Extracts BOOT2 from SYSTEM.CNF, e.g. BOOT2 = cdrom0:\\SCUS_972.75;1.
    /// This is text parsing, not a claim that every DNAS proof uses the same
    /// representation of the executable or its serial internally.
    /// </summary>
    public static string ReadSerialFromSystemCnf(string systemCnf)
    {
        if (string.IsNullOrWhiteSpace(systemCnf)) throw new ArgumentException("SYSTEM.CNF text is required.", nameof(systemCnf));
        Match line = Regex.Match(systemCnf, @"(?im)^\s*BOOT2?\s*=\s*[^\r\n]*?([A-Z]{4}[-_][0-9]{3}\.[0-9]{2})(?:\s*;\s*[0-9]+)?\s*$", RegexOptions.IgnoreCase);
        if (!line.Success) throw new FormatException("SYSTEM.CNF contains no recognized PS2 BOOT/BOOT2 serial.");
        return NormalizeGameSerial(line.Groups[1].Value);
    }

    /// <summary>
    /// Extracts five ID bytes at +4 in the *observed CDVD ReadKey result
    /// structure* [32-bit status][5 ID bytes]. Hardware and SDK callers that
    /// already have the five bytes should pass those directly to BuildRequest.
    /// Other N-command result layouts must not silently use this offset.
    /// </summary>
    public static byte[] ReadDiscIdFromObservedReadKeyBuffer(byte[] response)
    {
        if (response == null || response.Length < 9) throw new ArgumentException("Expected status word and five disc-ID bytes.", nameof(response));
        return response.AsSpan(4, 5).ToArray();
    }
}
