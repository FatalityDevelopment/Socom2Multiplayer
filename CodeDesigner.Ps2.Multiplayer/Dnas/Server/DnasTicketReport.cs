using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>
/// Formats a single, fixed-width RSA ticket report for Notepad.
/// This is diagnostic output only; it never influences the DNAS handshake.
/// </summary>
internal static class DnasTicketReport
{
    private const string Title = "DnaSDK / RSA SIGNATURE RECORD";
    private const string DecodeHeading = "RSA PUBLIC DECODE (OPTIONAL)";
    private const string Rule = "===============================================================================\r\n";
    private const string ThinRule = "-------------------------------------------------------------------------------\r\n";
    private const int LabelWidth = 28;

    public static string Create(string serial, C1Packet c1, byte[] signature, byte[]? template, string? previous, byte[]? publicBlock, byte[]? message117, string? decodeError, bool hasModulus)
    {
        string preserved = ReadCurrentBase(previous);
        string body = preserved.Length != 0 ? preserved : CreateBase(serial, c1, signature, template, previous);
        StringBuilder report = new(body);

        Heading(report, DecodeHeading);
        if (!hasModulus)
        {
            Field(report, "Status", "Unavailable - RSA/Moduli/SERIAL.BIN not present");
            Field(report, "Decoded signature", "Not generated; live authentication is unaffected");
        }
        else if (decodeError != null)
        {
            Field(report, "Status", "Unable to decode using the optional modulus");
            Field(report, "Details", decodeError);
        }
        else
        {
            Field(report, "Status", "PKCS#1 type-1 record verified");
            Hex(report, "RSA public block", publicBlock!);
            Hex(report, "RSA signed message", message117!);
            Field(report, "Decoded file", "RSA/Signatures/SERIAL_DC.BIN");
        }

        report.Append(ThinRule);
        report.Append("NOTE: Archived S1 values are historical evidence, not the live session output.\r\n");
        return report.ToString();
    }

    /// <summary>
    /// Keep the base of an already formatted document unchanged when a modulus
    /// is installed later. Only the optional diagnostic section is regenerated.
    /// </summary>
    private static string ReadCurrentBase(string? previous)
    {
        if (previous == null || !previous.StartsWith(Rule + Title, StringComparison.Ordinal))
            return string.Empty;

        int marker = previous.IndexOf("\r\n" + DecodeHeading, StringComparison.Ordinal);
        if (marker < 0)
            return string.Empty;

        // The diagnostic heading starts with a line break. Everything before
        // that line is stable, including archived S1 fields and separators.
        return previous[..marker];
    }

    private static string CreateBase(string serial, C1Packet c1, byte[] signature, byte[]? template, string? oldReport)
    {
        Dictionary<string, string> legacy = ParseLegacy(oldReport);
        StringBuilder report = new();
        report.Append(Rule).Append(Title).Append("\r\n").Append(Rule).Append("\r\n");

        Heading(report, "IDENTITY / RECORD SOURCE");
        Field(report, "Game serial", serial);
        Field(report, "Source", Value(legacy, "Source", template == null ? "Locally cached RSA signature" : "DNASRep S1 archive template"));

        Heading(report, "CLIENT REQUEST (C1)");
        Field(report, "Operation", Value(legacy, "C1 operation", $"0x{c1.Header.Operation:X8}"));
        HexText(report, "Lookup ID", Value(legacy, "C1 lookup ID (8)", Convert.ToHexString(c1.LookupId8)));
        HexText(report, "Session ID", Value(legacy, "C1 session ID (8)", Convert.ToHexString(c1.Header.SessionId8)));
        Field(report, "Initial parameter", Value(legacy, "C1 parameter", $"0x{c1.InitialParameter:X8}"));
        Field(report, "Encrypted proofs SHA-256", Value(legacy, "C1 encrypted proofs SHA-256", Convert.ToHexString(SHA256.HashData(c1.WrappedProofs256))));

        Heading(report, "RSA SIGNATURE (ORIGINAL)");
        Hex(report, "RSA signed operand", signature);
        Field(report, "Signature SHA-256", Convert.ToHexString(SHA256.HashData(signature)));

        bool hasS1 = template != null || legacy.ContainsKey("S1 operation");
        Heading(report, "ARCHIVED SERVER RESPONSE (S1)");
        if (!hasS1)
        {
            Field(report, "Status", "Unavailable; only the signature was cached");
        }
        else
        {
            Field(report, "Operation", GetS1(legacy, "S1 operation", template, 0, 4));
            HexText(report, "Header metadata", GetS1(legacy, "S1 metadata (23)", template, 4, 23));
            HexText(report, "Session ID", GetS1(legacy, "S1 session ID (8)", template, 27, 8));
            Field(report, "Header suffix", GetS1(legacy, "S1 suffix", template, 35, 1));
            Field(report, "Body length (bytes)", Value(legacy, "S1 body length", "288"));
            HexText(report, "Challenge A", GetS1(legacy, "Challenge A (8)", template, 0x28, 8));
            HexText(report, "DES challenge", GetS1(legacy, "DES challenge (16)", template, 0x30, 16));
            HexText(report, "Challenge B", GetS1(legacy, "Challenge B (8)", template, 0x40, 8));
            HexText(report, "Nested field", GetS1(legacy, "Nested field (32)", template, 0xC8, 32));
            HexText(report, "Remaining field", GetS1(legacy, "S1 remaining field (96)", template, 0xE8, 96));
        }
        report.Append(ThinRule);
        return report.ToString();
    }

    private static string GetS1(Dictionary<string, string> legacy, string key, byte[]? template, int offset, int length)
    {
        if (legacy.TryGetValue(key, out string? value))
            return value;
        if (template == null)
            return "Unavailable";
        if (key == "S1 operation")
            return $"0x{BinaryPrimitives.ReadUInt32BigEndian(template.AsSpan(0, 4)):X8}";
        if (key == "S1 suffix")
            return template[35].ToString("X2");
        return Convert.ToHexString(template.AsSpan(offset, length));
    }

    private static string Value(Dictionary<string, string> legacy, string key, string fallback)
    {
        return legacy.TryGetValue(key, out string? value) ? value : fallback;
    }

    /// <summary>
    /// Migrate the previous unaligned TXT format without discarding its original
    /// archived S1 values. Duplicate appended RSA sections are intentionally
    /// ignored because the current external modulus is authoritative here.
    /// </summary>
    private static Dictionary<string, string> ParseLegacy(string? oldReport)
    {
        Dictionary<string, string> fields = new(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(oldReport))
            return fields;

        foreach (string raw in oldReport.Split('\n'))
        {
            int separator = raw.IndexOf(':');
            if (separator < 1)
                continue;
            string key = raw[..separator].Trim();
            string value = raw[(separator + 1)..].Trim();
            if (key.Length == 0 || value.Length == 0 || fields.ContainsKey(key))
                continue;
            fields.Add(key, value);
        }
        return fields;
    }

    private static void Heading(StringBuilder report, string title)
    {
        report.Append("\r\n").Append(title).Append("\r\n").Append(ThinRule);
    }

    private static void Field(StringBuilder report, string label, string value)
    {
        report.Append("  ").Append(label.PadRight(LabelWidth)).Append(": ").Append(value).Append("\r\n");
    }

    private static void HexText(StringBuilder report, string label, string value)
    {
        try
        {
            byte[] bytes = Convert.FromHexString(value);
            Hex(report, label, bytes);
        }
        catch (FormatException)
        {
            Field(report, label, value);
        }
    }

    private static void Hex(StringBuilder report, string label, ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length <= 16)
        {
            Field(report, label, SpacedHex(bytes));
            return;
        }

        Field(report, label, $"{bytes.Length} bytes");
        for (int offset = 0; offset < bytes.Length; offset += 16)
        {
            ReadOnlySpan<byte> line = bytes.Slice(offset, Math.Min(16, bytes.Length - offset));
            report.Append("      +").Append(offset.ToString("X4")).Append("  ").Append(SpacedHex(line)).Append("\r\n");
        }
    }

    private static string SpacedHex(ReadOnlySpan<byte> bytes)
    {
        StringBuilder hex = new(bytes.Length * 3 + 2);
        for (int i = 0; i < bytes.Length; i++)
        {
            if (i != 0)
                hex.Append(i == 8 ? "  " : " ");
            hex.Append(bytes[i].ToString("X2"));
        }
        return hex.ToString();
    }
}
