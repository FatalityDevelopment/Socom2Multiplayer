using DNAS;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace TCP.Server;

/// <summary>
/// Stores the EXACT decrypted DNAS HTTP bodies, not TLS records and not plaintext
/// derived by decryption. Uses the same transaction number for incoming/outgoing.
/// HTTP errors are explicitly marked in the journal; they are not DNAS frames.
/// </summary>
internal sealed partial class PacketJournal
{
    internal sealed class SessionRecord
    {
        internal readonly int Number;
        internal readonly string DirectoryPath;
        internal readonly object Gate = new();
        internal int NextSequence;
        internal SessionRecord(int number, string directoryPath)
        {
            Number = number;
            DirectoryPath = directoryPath;
        }
    }

    internal sealed class Transaction
    {
        internal readonly SessionRecord _record;
        internal readonly int Sequence;
        internal int SessionNumber => _record.Number;
        private Transaction(SessionRecord record, int sequence)
        {
            _record = record;
            Sequence = sequence;
        }
        internal static Transaction Create(SessionRecord record)
        {
            lock (record.Gate) return new Transaction(record, ++record.NextSequence);
        }
    }

    private static readonly object OutputGate = new();
    private readonly ConcurrentDictionary<string, SessionRecord> _byWireSession = new(StringComparer.Ordinal);
    private int _nextNumber;
    internal readonly string DirectoryPath;

    internal PacketJournal(string path)
    {
        DirectoryPath = Path.GetFullPath(path);
        Directory.CreateDirectory(DirectoryPath);
        // Preserve captures from previous runs: do not overwrite old SessionX files.
        foreach (string file in Directory.EnumerateFiles(DirectoryPath, "Session*"))
        {
            string name = Path.GetFileName(file);
            int end = name.IndexOfAny(new[] { '_', '.' }, 7);
            if (name.StartsWith("Session", StringComparison.Ordinal) && end > 7 && int.TryParse(name.AsSpan(7, end - 7), out int n))
                _nextNumber = Math.Max(_nextNumber, n);
        }
    }

    // Pre-DNAS connection trace. A SessionX file cannot exist until the HTTP body is complete.
    // Logging failure must never abort or hold open the TLS connection.
    internal void ConnectionEvent(string message)
    {
        try
        {
            File.AppendAllText(Path.Combine(DirectoryPath, "Connections.log"),
                $"[{DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm:ss.fff} UTC] {message}{Environment.NewLine}");
        }
        catch (IOException ex) { Console.Error.WriteLine($"[TRANSPORT LOG ERROR] {ex.Message}"); }
        catch (UnauthorizedAccessException ex) { Console.Error.WriteLine($"[TRANSPORT LOG ERROR] {ex.Message}"); }
    }

    // The same plaintext lines are printed in color and appended to SessionX.log.
    // This sink is serialised for concurrent client sessions; ANSI color codes never
    // enter the file. Keep the session record lock OUTSIDE any network callbacks.
    internal static void Line(ConsoleColor color, string message, Transaction? tx = null)
    {
        lock (OutputGate)
        {
            ConsoleColor before = Console.ForegroundColor;
            try
            {
                Console.ForegroundColor = color;
                Console.WriteLine(message);
            }
            finally { Console.ForegroundColor = before;
            }
            if (tx != null)
            {
                lock (tx._record.Gate)
                {
                    File.AppendAllText(Path.Combine(tx._record.DirectoryPath, $"Session{tx.SessionNumber}.log"), message + Environment.NewLine);
                }
            }
        }
    }

    internal void Log(Transaction tx, ConsoleColor color, string message) => Line(color, message, tx);

    // Used for connection messages already displayed before their DNAS session
    // could be identified. Include them in the file without reprinting them.
    private static void AppendTranscript(Transaction tx, string message)
    {
        lock (tx._record.Gate)
            File.AppendAllText(Path.Combine(tx._record.DirectoryPath, $"Session{tx.SessionNumber}.log"), message + Environment.NewLine);
    }

    internal Transaction BeginIncoming(byte[] body, long connection, string requestLine, IReadOnlyList<string>? transportLines = null)
    {
        DnasWirePacket packet = new(body);
        bool beginsSession = Public.ToConnectOperation(packet.Operation) == Public.ClientConnect;
        string wireId = packet.WireSessionId;
        SessionRecord record = beginsSession || !packet.HasCompleteHeader
            ? new SessionRecord(System.Threading.Interlocked.Increment(ref _nextNumber), DirectoryPath)
            : _byWireSession.GetOrAdd(wireId, _ => new SessionRecord(System.Threading.Interlocked.Increment(ref _nextNumber), DirectoryPath));
        Transaction tx = Transaction.Create(record);
        // TCP/TLS lines were emitted live before the session ID existed. Record
        // them here so the complete connection transcript appears in SessionX.log.
        if (transportLines != null)
        {
            AppendTranscript(tx, $"\n[{DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm:ss.fff} UTC] SESSION {tx.SessionNumber} / EXCHANGE {tx.Sequence} / TCP+TLS");
            foreach (string entry in transportLines) AppendTranscript(tx, entry);
        }
        Save(tx, "Incoming", body, "DNAS HTTP request: " + requestLine, true);
        return tx;
    }

    internal void RegisterServerSession(Transaction tx, byte[] response)
    {
        DnasWirePacket p = new(response);
        if (Public.ToConnectOperation(p.Operation) != Public.ServerConnect || !p.HasCompleteHeader) return;
        _byWireSession[p.WireSessionId] = tx._record;
        Append(tx, $"Issued server session ID {p.WireSessionId}; subsequent connections reuse Session{tx.SessionNumber}.");
    }

    internal void RecordOutgoing(Transaction tx, byte[] data, string note, bool isDnas = true)
        => Save(tx, "Outgoing", data, note, isDnas);

    internal void RecordRejection(Transaction tx, Exception ex)
        => Append(tx, $"REJECT {ex.GetType().Name}: {ex.Message}");

    internal void RecordTlsHello(long connection, byte[] hello)
    {
        // TLS diagnostics are NOT DNAS application packets; keep separate.
        string path = Path.Combine(DirectoryPath, $"TCP{connection}_ClientHello.bin");
        File.WriteAllBytes(path, hello);
        Line(ConsoleColor.DarkCyan, $"[TCP #{connection}] TLS ClientHello saved: {path}");
    }

    private void Save(Transaction tx, string direction, byte[] data, string note, bool isDnas)
    {
        string file = Path.Combine(DirectoryPath, $"Session{tx.SessionNumber}_{direction}_{tx.Sequence}.bin");
        DateTimeOffset now = DateTimeOffset.UtcNow;
        lock (tx._record.Gate)
        {
            File.WriteAllBytes(file, data);
            File.SetLastWriteTimeUtc(file, now.UtcDateTime);
            AppendLocked(tx, $"{direction} {data.Length} bytes; {note}; saved {Path.GetFileName(file)}", now);
        }
        PrintPacket(tx, direction, data, note, isDnas, now, file);
    }

    private void Append(Transaction tx, string message)
    {
        lock (tx._record.Gate) AppendLocked(tx, message, DateTimeOffset.UtcNow);
    }

    private void AppendLocked(Transaction tx, string message, DateTimeOffset utc)
    {
        string file = Path.Combine(DirectoryPath, $"Session{tx.SessionNumber}.log");
        File.AppendAllText(file, $"{utc:yyyy-MM-ddTHH:mm:ss.fffZ} exchange={tx.Sequence} {message}{Environment.NewLine}");
    }


}
