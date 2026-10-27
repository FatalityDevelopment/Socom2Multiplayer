using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Tls;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>
/// Accepts TCP connections, negotiates TLS, reads exactly one HTTP/DNAS request,
/// and sends the protocol processor's response. No DNAS opcode or ticket policy
/// belongs in this class.
/// </summary>
public sealed class TcpServer
{
    private readonly IPAddress _bind;
    private readonly int _port;
    private readonly DnasServerProcessor _processor;
    private readonly X509Certificate2? _certificate;
    private readonly AsymmetricKeyParameter? _privateKey;
    private readonly X509Certificate2? _ca;
    private readonly PacketJournal _journal;
    private readonly SemaphoreSlim _slots = new(16);
    private long _connectionId;

    public TcpServer(IPAddress bind, int port, DnasServerProcessor processor, X509Certificate2 certificate, AsymmetricKeyParameter? privateKey, X509Certificate2? ca, string? capture)
    {
        _bind = bind;
        _port = port;
        _processor = processor ?? throw new ArgumentNullException(nameof(processor));
        _certificate = certificate;
        _privateKey = privateKey;
        _ca = ca;
        _journal = new PacketJournal(capture ?? "PacketLogs");
    }

    internal async Task RunAsync(CancellationToken cancellationToken)
    {
        TcpListener listener = new(_bind, _port);
        listener.Start(32);

        Console.WriteLine($"[LISTEN] PS2 TLS/HTTPS {_bind}:{_port}");
        Console.WriteLine("[INFO] One HTTP request per connection. DNAS sessions persist across connections. Ctrl+C to stop.");
        PacketJournal.Line(ConsoleColor.Cyan, $"[PACKET LOGS] {_journal.DirectoryPath}");

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                await _slots.WaitAsync(cancellationToken);

                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync(cancellationToken);
                }
                catch
                {
                    _slots.Release();
                    throw;
                }

                long connectionId = Interlocked.Increment(ref _connectionId);
                PacketJournal.Line(ConsoleColor.DarkCyan, $"[TCP ACCEPT #{connectionId}] {client.Client.RemoteEndPoint}");

                // The handler releases its own slot, including on failed TLS
                // handshakes; keep accepting unrelated clients independently.
                _ = HandleConnectionAsync(client, connectionId, cancellationToken);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        finally
        {
            listener.Stop();
        }
    }

    private async Task HandleConnectionAsync(TcpClient client, long connectionId, CancellationToken cancellationToken)
    {
        using (client)
        {
            PacketJournal.Transaction? transaction = null;

            try
            {
                client.ReceiveTimeout = 30000;
                client.SendTimeout = 30000;

                List<string> transcript = new();
                string connected = $"[#{connectionId}] Connected {client.Client.RemoteEndPoint}";
                transcript.Add(connected);
                PacketJournal.Line(ConsoleColor.DarkCyan, connected);
                _journal.ConnectionEvent($"[#{connectionId}] TCP accepted {client.Client.RemoteEndPoint}");

                Stream stream = await EstablishStreamAsync(client.GetStream(), connectionId, transcript, cancellationToken);

                if (stream == Stream.Null)
                    return; // The peer rejected the TLS handshake.

                _journal.ConnectionEvent($"[#{connectionId}] TLS ready, waiting for HTTP request");
                var request = await Http.ReadWireMessageAsync(stream, cancellationToken);

                string requestLine = $"[TCP #{connectionId}] {request.startLine} | HTTP body {request.body.Length} bytes";
                transcript.Add(requestLine);
                PacketJournal.Line(ConsoleColor.White, requestLine);

                transaction = _journal.BeginIncoming(request.body, connectionId, request.startLine, transcript);
                await ProcessRequestAsync(stream, request.body, transaction, cancellationToken);
            }
            catch (TlsFatalAlertReceived alert)
            {
                DescribeClientTlsAlert(connectionId, alert);
            }
            catch (Exception error) when (error is IOException or SocketException or OperationCanceledException or
                FormatException or InvalidDataException or TlsFatalAlert)
            {
                WriteError(connectionId, transaction, "TRANSPORT", error.Message);
            }
            catch (Exception error)
            {
                WriteError(connectionId, transaction, "ERROR", error.ToString());
            }
            finally
            {
                _slots.Release();
            }
        }
    }

    private async Task<Stream> EstablishStreamAsync(Stream tcp, long connectionId, List<string> transcript, CancellationToken cancellationToken)
    {
        _journal.ConnectionEvent($"[#{connectionId}] Waiting for TLS ClientHello");

        Stream? secured = await LegacyTls.TryAcceptAsync(
            tcp,
            _certificate!,
            _privateKey,
            _ca,
            details =>
            {
                string line = $"[#{connectionId}] [TLS] {details}";
                lock (transcript)
                    transcript.Add(line);

                PacketJournal.Line(ConsoleColor.DarkCyan, line);
            },
            cancellationToken);

        return secured ?? Stream.Null;
    }

    private async Task ProcessRequestAsync(Stream stream, byte[] requestBody, PacketJournal.Transaction transaction, CancellationToken cancellationToken)
    {
        try
        {
            // Protocol parsing and dispatch happen on a typed message.
            // This method does not inspect or branch on DNAS operation codes.
            DnasMessage incoming = DnasPackets.Parse(requestBody);
            DnasResponse result = _processor.Handle(incoming);

            _journal.Log(transaction, ConsoleColor.DarkCyan, $"[OPERATION] {new DnasOperation(incoming.Header.Operation)}");

            if (!string.IsNullOrEmpty(result.Note))
                _journal.Log(transaction, ConsoleColor.Yellow, result.Note);

            if (result.ClientProof != null)
                _journal.RecordDecodedC1(transaction, result.ClientProof);

            DnasMessage outgoing = result.Packet;

            byte[] response = outgoing.Serialize();
            _journal.RecordOutgoing(transaction, response, "DNAS HTTP 200");
            _journal.RegisterServerSession(transaction, response);
            _journal.Log(transaction, ConsoleColor.Green,
                $"[SESSION {transaction.SessionNumber} / #{transaction.Sequence}] " +
                $"Reply accepted, next phase={result.Phase}, id={result.SessionId}");

            await Http.WriteResponseAsync(stream, response, cancellationToken);
        }
        catch (Exception error) when (error is ArgumentException or FormatException or InvalidOperationException or
            CryptographicException or NotSupportedException or FileNotFoundException or System.Net.Http.HttpRequestException)
        {
            _journal.Log(transaction, ConsoleColor.Red,
                $"[SESSION {transaction.SessionNumber} / #{transaction.Sequence}] " +
                $"[REJECT] {error.GetType().Name}: {error.Message}");

            byte[] response = ErrorResponseBytes();
            _journal.RecordOutgoing(transaction, response, "HTTP 400 (not DNAS)", isDnas: false);
            await stream.WriteAsync(response, cancellationToken);
            await stream.FlushAsync(cancellationToken);
        }
    }

    private void DescribeClientTlsAlert(long connectionId, TlsFatalAlertReceived alert)
    {
        Console.WriteLine($"[#{connectionId}] [TLS CLIENT ALERT] {alert.Message}");

        if (!alert.Message.Contains("certificate_unknown", StringComparison.OrdinalIgnoreCase) &&
            !alert.Message.Contains("unknown_ca", StringComparison.OrdinalIgnoreCase))
            return;

        Console.WriteLine($"[#{connectionId}] [TLS CERTIFICATE REJECTED] Client rejected the certificate before DNAS C1.");
        Console.WriteLine($"[#{connectionId}] [TLS CERTIFICATE REJECTED] Subject={_certificate?.Subject}; Issuer={_certificate?.Issuer}");
        Console.WriteLine($"[#{connectionId}] [TLS CERTIFICATE REJECTED] Verify issuer, signature format, hostname and validity.");
        Console.WriteLine($"[#{connectionId}] [TLS CERTIFICATE REJECTED] RSA tickets are unrelated to the TLS certificate.");
    }

    private static void WriteError(long connectionId, PacketJournal.Transaction? transaction, string category, string detail)
    {
        string line = $"[#{connectionId}] [{category}] {detail}";
        if (transaction != null)
            PacketJournal.Line(ConsoleColor.Red, line, transaction);
        else
            PacketJournal.Line(ConsoleColor.Red, line);
    }

    private static byte[] ErrorResponseBytes()
    {
        return Encoding.ASCII.GetBytes(
            "HTTP/1.0 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    }
}
