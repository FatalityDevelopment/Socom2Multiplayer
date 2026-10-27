using DNAS;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TCP.Server;

/// <summary>HTTP framing over an already-established TLS stream. DNAS binary packets are HTTP bodies.</summary>
public static class Http
{
    private const int MaxHeaders = 32768;
    private const int MaxPayload = 1024 * 1024;

    /// <summary>
    /// Client HTTP headers have not been recovered byte-for-byte from the PS2 TLS stream.
    /// Supply the actual PS2-generated HTTP request header bytes instead of using an
    /// invented modern HTTP POST. The body is the validated PS2 DNAS packet.
    /// </summary>
    public static async Task WriteCapturedPs2RequestAsync(Stream tls, byte[] capturedPs2HttpHeaders, byte[] ps2Packet, CancellationToken ct = default)
    {
        _ = new Packet(ps2Packet);
        if (capturedPs2HttpHeaders == null || capturedPs2HttpHeaders.Length < 4 ||
            capturedPs2HttpHeaders[^4] != 13 || capturedPs2HttpHeaders[^3] != 10 ||
            capturedPs2HttpHeaders[^2] != 13 || capturedPs2HttpHeaders[^1] != 10)
            throw new ArgumentException("Supply the real PS2 HTTP headers ending in CRLFCRLF.", nameof(capturedPs2HttpHeaders));
        await tls.WriteAsync(capturedPs2HttpHeaders, ct);
        await tls.WriteAsync(ps2Packet, ct);
        await tls.FlushAsync(ct);
    }

    public static async Task WriteResponseAsync(Stream tls, byte[] packet, CancellationToken ct = default)
    {
        _ = new Packet(packet);
        byte[] header = Encoding.ASCII.GetBytes($"HTTP/1.0 200 OK\r\nContent-Type: image/gif\r\nContent-Length: {packet.Length}\r\nConnection: close\r\n\r\n");
        await tls.WriteAsync(header, ct);
        await tls.WriteAsync(packet, ct);
        await tls.FlushAsync(ct);
    }

    /// <summary>Reads bounded HTTP framing without discarding a malformed DNAS body.
    /// Useful for diagnostic captures. Call Packet(...) before any protocol handling.</summary>
    public static async Task<(string startLine, Dictionary<string, string> headers, byte[] body)> ReadWireMessageAsync(Stream tls, CancellationToken ct = default)
    {
        byte[] headerBytes = new byte[MaxHeaders];
        int length = 0, match = 0;
        byte[] end = { 13, 10, 13, 10 };
        byte[] one = new byte[1];
        while (length < MaxHeaders && match < 4)
        {
            int n = await tls.ReadAsync(one, ct);
            if (n != 1) throw new EndOfStreamException("EOF in HTTP headers.");
            byte value = one[0];
            headerBytes[length++] = value;
            match = value == end[match] ? match + 1 : (value == 13 ? 1 : 0);
        }
        if (match != 4) throw new FormatException("HTTP header too large or unterminated.");
        string[] lines = Encoding.ASCII.GetString(headerBytes, 0, length - 4).Split("\r\n");
        if (lines.Length == 0 || lines[0].Length == 0) throw new FormatException("Missing HTTP start line.");
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 1; i < lines.Length; i++)
        {
            int colon = lines[i].IndexOf(':');
            if (colon > 0) headers[lines[i][..colon].Trim()] = lines[i][(colon + 1)..].Trim();
        }
        if (!headers.TryGetValue("Content-Length", out string? sizeText) || !int.TryParse(sizeText, out int size) || size < 0 || size > MaxPayload)
            throw new FormatException("DNAS transport requires a valid Content-Length (max 1 MiB).");
        byte[] body = new byte[size];
        await tls.ReadExactlyAsync(body, ct);
        return (lines[0], headers, body);
    }

    /// <summary>Preserved original API: validates the DNAS binary packet after reading HTTP.</summary>
    public static async Task<(string startLine, Dictionary<string, string> headers, byte[] body)> ReadMessageAsync(Stream tls, CancellationToken ct = default)
    {
        var message = await ReadWireMessageAsync(tls, ct);
        _ = new Packet(message.body);
        return message;
    }
}
