using System;
using System.Linq;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using DNAS;

namespace TCP.Server;

/// <summary>
/// Human-readable C1 proof, RTC and packet dump output. Packet saving and
/// connection/session indexing remain in PacketJournal.cs.
/// </summary>
internal sealed partial class PacketJournal
{
    private static bool DecodeBcd(byte value, out int result)
    {
        int high = value >> 4, low = value & 15;
        result = high * 10 + low;
        return high <= 9 && low <= 9;
    }

    // Original eight-byte sceCdCLOCK layout: [status, seconds, minutes, hours,
    // reserved, day, month, year]. These fields use BCD, not a 64-bit timestamp.
    // PS2 clock does not encode a time zone. Never substitute DateTime.Now.
    internal static string FormatCdvdClock(ReadOnlySpan<byte> clock8)
    {
        if (clock8.Length != 8) return $"invalid CDVD clock length ({clock8.Length}; expected 8 bytes)";
        if (!DecodeBcd(clock8[1], out int seconds) || !DecodeBcd(clock8[2], out int minutes) ||
            !DecodeBcd(clock8[3], out int hours) || !DecodeBcd(clock8[5], out int day) ||
            !DecodeBcd(clock8[6], out int month) || !DecodeBcd(clock8[7], out int year))
            return "CDVD clock contains invalid BCD digits; raw bytes retained below";
        try
        {
            DateTime value = new(2000 + year, month, day, hours, minutes, seconds, DateTimeKind.Unspecified);
            return value.ToString("dddd, MMMM d, yyyy 'at' h:mm:ss tt", System.Globalization.CultureInfo.InvariantCulture) +
                " (PS2 console clock; timezone not encoded)";
        }
        catch (ArgumentOutOfRangeException)
        {
            return "CDVD clock contains an invalid date/time; raw bytes retained below";
        }
    }

    private static string FormatProof(int index, byte[] bytes)
    {
        if (index == 3)
        {
            string raw = Encoding.ASCII.GetString(bytes);
            bool printable = raw.All(ch => ch >= 32 && ch <= 126);
            return printable && raw.Length == 9
                ? $"{raw[..4]}-{raw[4..]} (raw: {raw})"
                : Convert.ToHexString(bytes) + " (nonprintable serial bytes)";
        }
        return Convert.ToHexString(bytes);
    }

    internal void RecordDecodedC1(Transaction tx, NativeLiveC1Report report)
    {
        lock (OutputGate)
        {
            Line(ConsoleColor.Magenta, $"[SESSION {tx.SessionNumber} / #{tx.Sequence}] DECODED C1", tx);
            string[] labels = { "Console", "Fixed", "Disc", "Serial" };
            for (int i = 0; i < 4; i++)
            {
                byte[] actual = report.Actual[i];
                byte[]? pinned = report.Expected?[i];
                bool matchesPin = pinned == null || actual.AsSpan().SequenceEqual(pinned);
                bool fixedOk = i != 1 || actual.AsSpan().SequenceEqual(ProofInputs.InitialB32());
                bool consoleTailOk = i != 0 || (actual.Length >= 16 && actual.AsSpan(8, 8).SequenceEqual(new byte[8]));
                bool serialFormatOk = true;
                if (i == 3)
                {
                    string serial = Encoding.ASCII.GetString(actual);
                    serialFormatOk = serial.Length == 9;
                    for (int j = 0; j < serial.Length; j++)
                        serialFormatOk &= j < 4 ? serial[j] >= 'A' && serial[j] <= 'Z' : serial[j] >= '0' && serial[j] <= '9';
                }
                bool valid = matchesPin && fixedOk && consoleTailOk && serialFormatOk &&
                    report.ParameterValid[i] && report.FirstBlockValid[i];
                Line(valid ? ConsoleColor.Green : ConsoleColor.Red,
                    $"  Proof {"ABCD"[i]} ({labels[i]}): {FormatProof(i, actual)}", tx);

                // A green line is a pass. Expectations and reasons are emitted
                // ONLY for failing checks. There is no noisy [OK / NOT PINNED].
                if (valid) continue;
                if (!matchesPin)
                {
                    Line(ConsoleColor.DarkGray, $"    Expected: {FormatProof(i, pinned!)}", tx);
                    Line(ConsoleColor.Red, "    Reason: Client identity does not match explicit server policy.", tx);
                }
                if (!fixedOk)
                {
                    Line(ConsoleColor.DarkGray, $"    Expected: {Convert.ToHexString(ProofInputs.InitialB32())}", tx);
                    Line(ConsoleColor.Red, "    Reason: Fixed proof B is not 32 bytes of FF.", tx);
                }
                if (!consoleTailOk)
                {
                    Line(ConsoleColor.DarkGray, "    Expected: final eight console bytes = 0000000000000000", tx);
                    Line(ConsoleColor.Red, "    Reason: Console proof A contains a nonzero tail.", tx);
                }
                if (!serialFormatOk)
                {
                    Line(ConsoleColor.DarkGray, "    Expected: four uppercase letters followed by five digits (e.g. SCUS-97275)", tx);
                    Line(ConsoleColor.Red, "    Reason: Serial does not match the original nine-character format.", tx);
                }
                if (!report.ParameterValid[i])
                {
                    Line(ConsoleColor.DarkGray, "    Expected: original proof parameter = 2", tx);
                    Line(ConsoleColor.Red, "    Reason: Native proof parameter bits differ.", tx);
                }
                if (!report.FirstBlockValid[i])
                    Line(ConsoleColor.Red, "    Reason: Native first-block inverse verification failed.", tx);
            }
            byte[] disc = report.Actual[2];
            if (disc.Length >= 5)
            {
                string readKey4 = Convert.ToHexString(new byte[] { disc[4], disc[3], disc[2], (byte)((disc[0] << 4) | disc[1]) });
                Line(ConsoleColor.Cyan, $"  CDVD ReadKey: {readKey4} ?? (fifth byte unavailable in C1)", tx);
            }
            if (report.ProofClock8 is byte[] proofClock)
            {
                Line(ConsoleColor.Cyan, "  Client proof RTC: " + FormatCdvdClock(proofClock), tx);
                Line(ConsoleColor.DarkGray, $"    Raw client RTC: {Convert.ToHexString(proofClock)}", tx);
            }
            Line(ConsoleColor.DarkGray, "  Envelope random: " + Convert.ToHexString(report.EnvelopeRandom16), tx);
            Line(report.EnvelopeValid ? ConsoleColor.Green : ConsoleColor.Red,
                "  3DES envelope: " + (report.EnvelopeValid ? "valid" : "invalid"), tx);
            foreach (string problem in report.Problems)
            {
                Line(ConsoleColor.Red, "  Failure: " + problem, tx);
            }
        }
    }

    private static string FieldHex(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length <= 32) return Convert.ToHexString(bytes);
        return $"{Convert.ToHexString(bytes[..24])} ... {Convert.ToHexString(bytes[^8..])} SHA256={Convert.ToHexString(SHA256.HashData(bytes))[..16]}...";
    }

    private static void PrintPacket(Transaction tx, string direction, byte[] raw, string note, bool isDnas, DateTimeOffset utc, string file)
    {
        DnasWirePacket p = new(raw);
        lock (OutputGate)
        {
            Line(direction == "Incoming" ? ConsoleColor.Cyan : ConsoleColor.Green,
                $"\n[{utc:yyyy-MM-dd HH:mm:ss.fff} UTC] SESSION {tx.SessionNumber} / EXCHANGE {tx.Sequence} / {direction.ToUpperInvariant()} ({raw.Length} bytes)", tx);
            Line(ConsoleColor.DarkGray, $"  Saved: {file}", tx);
            if (!isDnas)
            {
                Line(ConsoleColor.Yellow, $"  {note} (raw HTTP error, not a DNAS packet)", tx);
                Line(ConsoleColor.Gray, $"  Bytes: {FieldHex(raw)}", tx);
                return;
            }
            Line(ConsoleColor.White, $"  {note} | {p.TypeName} | opcode=0x{p.Operation:X8}", tx);
            Line(ConsoleColor.DarkCyan, $"  Operation fields: {p.OperationFields}", tx);
            if (!p.HasCompleteHeader)
            {
                Line(ConsoleColor.Red, $"  MALFORMED: {raw.Length} bytes; minimum header = 40 bytes", tx);
                Line(ConsoleColor.Gray, $"  Raw: {FieldHex(raw)}", tx);
                return;
            }
            Line(p.BodyLengthMatches ? ConsoleColor.DarkGray : ConsoleColor.Red,
                $"  Header=40, body declared={p.DeclaredBodyLength}, actual={p.ActualBodyLength}, total={raw.Length} {(p.BodyLengthMatches ? "[length OK]" : "[LENGTH MISMATCH]")}", tx);
            Line(ConsoleColor.DarkCyan, $"  Session ID=0x{p.WireSessionId}, suffix=0x{p.HeaderSuffix:X2}; metadata=0x{Convert.ToHexString(p.HeaderMetadata.Span)}", tx);
            if (!p.HasKnownOperation)
            {
                string desc = p.Operation is 0x01228003 or 0x01228007 or 0x01A28003 or 0x01A28007
                    ? "Replay-observed operation; body semantics not fully mapped"
                    : "Unrecognized operation";
                Line(ConsoleColor.Yellow, $"  {desc}: {FieldHex(p.Body.Span)}", tx);
                return;
            }
            if (Public.ToConnectOperation(p.Operation) == Public.ServerConnect)
                Line(ConsoleColor.Yellow, "  S1 offsets below are RAW 3DES CIPHERTEXT; plaintext Challenge A/B is logged separately after decryption.", tx);
            else if (Public.ToConnectOperation(p.Operation) == Public.ClientConnect)
                Line(ConsoleColor.Yellow, "  C1 proof payload is encrypted; decoded values appear in the proof section below.", tx);
            foreach (PacketField f in PacketByteMap.Fields(p.Operation))
            {
                if (f.Offset >= raw.Length)
                {
                    Line(ConsoleColor.Red, $"  0x{f.Offset:X3} +{f.Length,3}: {f.Name,-34} MISSING", tx);
                    continue;
                }
                int count = Math.Min(f.Length, raw.Length - f.Offset);
                Line(count == f.Length ? ConsoleColor.Gray : ConsoleColor.Red,
                    $"  0x{f.Offset:X3} +{f.Length,3}: {f.Name,-34} {FieldHex(raw.AsSpan(f.Offset, count))}{(count == f.Length ? "" : " [TRUNCATED]")}", tx);
            }
        }
    }

}
