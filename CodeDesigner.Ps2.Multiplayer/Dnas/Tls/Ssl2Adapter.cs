using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>
/// Converts an SSLv2-format ClientHello into a TLS 1.0 ClientHello so that
/// BouncyCastle 2.x can process it.
///
/// Background: The PS2 DNAS SSL library sends its TLS ClientHello wrapped in an
/// SSLv2 two-byte record header (first byte = 0x80) for backward compatibility
/// with old SSL 2.0 servers — this is the "SSLv23 client method" behaviour in
/// classic OpenSSL.  BouncyCastle 2.x expects strict TLS records (first byte
/// 0x16 = ContentType.handshake) and rejects the SSLv2 header with
/// unexpected_message(10) / UNKNOWN(128).
///
/// Conversion rules (matches what OpenSSL's s23_srvr.c does internally):
///   • SSLv2 record header: (0x80 | high7(len)), low8(len)
///   • SSLv2 ClientHello contains 3-byte cipher specs; those whose first byte
///     is 0x00 are TLS suites and are kept; SSLv2-only specs are dropped.
///   • The SSLv2 challenge (16–32 bytes) is right-aligned in the 32-byte TLS
///     client_random field.
///   • The negotiated version is normalised to at minimum TLS 1.0 (0x03,0x01).
/// </summary>

internal static class Ssl2Adapter
{
    /// <summary>
    /// Peeks at the first byte of <paramref name="inner"/>.
    /// <list type="bullet">
    ///   <item>If it is <c>0x80</c>, reads the full SSLv2 ClientHello, converts
    ///   it to a TLS 1.0 ClientHello, and returns a <see cref="PrefixedStream"/>
    ///   that replays the converted record followed by the rest of
    ///   <paramref name="inner"/>.</item>
    ///   <item>Otherwise, returns a <see cref="PrefixedStream"/> that replays
    ///   the peeked byte followed by the rest of <paramref name="inner"/>.</item>
    /// </list>
    /// </summary>
    // Returns (adaptedStream, wasSsl2, ssl2Payload).
    // ssl2Payload is the raw SSLv2 ClientHello body (from type-byte 0x01 onwards);
    // it must be fed into the Finished transcript hash instead of the converted
    // TLS ClientHello bytes so that BC's hash matches the PS2's.
    internal static async Task<(Stream stream, bool wasSsl2, byte[]? ssl2Payload)> WrapAsync(Stream inner, CancellationToken ct)
    {
        // ── peek first byte ─────────────────────────────────────
        var first = new byte[1];
        int n = await inner.ReadAsync(first, 0, 1, ct).ConfigureAwait(false);
        if (n == 0)
            return (new PrefixedStream(Array.Empty<byte>(), inner), false, null);

        if ((first[0] & 0x80) == 0)
            return (new PrefixedStream(first, inner), false, null);

        // ── SSLv2 two-byte record header ──────────────────────────────────
        // Format when high bit is set (no-padding): ((b0 & 0x7F) << 8) | b1
        // The upper seven bits of b0 contribute to the length. Do not assume b0 == 0x80.
        var second = new byte[1];
        await ReadExactAsync(inner, second, ct).ConfigureAwait(false);
        int payloadLen = ((first[0] & 0x7F) << 8) | second[0];

        if (payloadLen < 9 || payloadLen > 16384) throw new InvalidDataException($"Invalid SSLv2 ClientHello record length: {payloadLen}.");

        var payload = new byte[payloadLen];
        await ReadExactAsync(inner, payload, ct).ConfigureAwait(false);

        // ── SSLv2 ClientHello body ────────────────────────────────────────
        if (payload[0] != 0x01) throw new InvalidDataException($"SSLv2 message type 0x{payload[0]:X2}, expected 0x01 (CLIENT-HELLO)");

        int pos = 1;
        byte verMajor    = payload[pos++];
        byte verMinor    = payload[pos++];
        int cipherSpecLen = (payload[pos] << 8) | payload[pos + 1];
        pos += 2;
        int sessionIdLen  = (payload[pos] << 8) | payload[pos + 1];
        pos += 2;
        int challengeLen  = (payload[pos] << 8) | payload[pos + 1];
        pos += 2;

        if (cipherSpecLen % 3 != 0 || pos + cipherSpecLen + sessionIdLen + challengeLen != payloadLen) throw new InvalidDataException("Invalid SSLv2 ClientHello field lengths.");
        if (challengeLen < 16 || challengeLen > 32) throw new InvalidDataException("SSLv2 challenge must contain 16 to 32 bytes.");

        // Extract TLS cipher suites (3-byte SSLv2 specs with b0==0x00 are TLS suites)
        var tlsCiphers = new List<ushort>(cipherSpecLen / 3);
        for (int i = 0; i < cipherSpecLen; i += 3)
        {
            // The preceding length check guarantees this access is within the record.
            byte b0 = payload[pos + i];
            byte b1 = payload[pos + i + 1];
            byte b2 = payload[pos + i + 2];
            if (b0 == 0x00)
                tlsCiphers.Add((ushort)((b1 << 8) | b2));
        }
        pos += cipherSpecLen;
        pos += sessionIdLen; // skip session ID

        // Challenge → right-aligned in 32-byte client_random
        var clientRandom = new byte[32];
        int copyLen = Math.Min(challengeLen, 32);
        Buffer.BlockCopy(payload, pos, clientRandom, 32 - copyLen, copyLen);

        // Never invent cipher suites absent from the actual PS2 ClientHello.
        if (tlsCiphers.Count == 0)
            throw new InvalidDataException("The PS2 ClientHello did not advertise any TLS cipher suite.");

        // Do NOT inject TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00FF).
        //
        // If SCSV is present, BouncyCastle sets secureRenegotiation=true and then
        // appends a renegotiation_info extension to the ServerHello even when
        // LegacyTlsServer.GetServerExtensions() returns an empty map (BC adds it
        // post-call whenever secureRenegotiation=true).  The PS2 DNAS SSL library
        // is SSLv3-era and rejects the unknown extension with handshake_failure(40).
        //
        // Without SCSV, BC calls NotifySecureRenegotiation(false) on the server,
        // which LegacyTlsServer overrides to suppress the error.  BC then sends a
        // ServerHello with no extensions; the PS2 accepts it.

        byte[] tlsRecord = BuildTls10ClientHello(verMajor, verMinor, clientRandom, tlsCiphers);
        // Return the original SSLv2 payload so the caller can seed the Finished
        // transcript hash with the bytes the PS2 actually sent (see Ssl2HandshakeHash).
        return (new PrefixedStream(tlsRecord, inner), true, payload);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Private helpers
    // ─────────────────────────────────────────────────────────────────────

    private static byte[] BuildTls10ClientHello(byte verMajor, byte verMinor, byte[] clientRandom, List<ushort> ciphers)
    {
        // Normalise version to at least TLS 1.0
        if (verMajor < 3) { verMajor = 3; verMinor = 1; }
        else if (verMajor == 3 && verMinor < 1) verMinor = 1;

        int cipherBytes = ciphers.Count * 2;

        // ClientHello body:
        //   2 client_version
        //  32 random
        //   1 session_id_length (0)
        //   2 cipher_suites_length
        //   N cipher suites × 2 bytes
        //   1 compression_methods_length (1)
        //   1 compression_method (null = 0)
        int chelloBodyLen = 2 + 32 + 1 + 2 + cipherBytes + 1 + 1;

        // Handshake header: 1-byte type + 3-byte length
        int handshakeLen = 4 + chelloBodyLen;

        // TLS record: 1-byte content-type + 2-byte version + 2-byte length
        using var ms = new MemoryStream(5 + handshakeLen);

        // TLS record header
        ms.WriteByte(0x16);                       // ContentType.handshake
        ms.WriteByte(0x03); ms.WriteByte(0x01);   // TLS 1.0
        ms.WriteByte((byte)(handshakeLen >> 8));
        ms.WriteByte((byte)(handshakeLen & 0xFF));

        // Handshake header
        ms.WriteByte(0x01);                       // HandshakeType.client_hello
        ms.WriteByte((byte)(chelloBodyLen >> 16));
        ms.WriteByte((byte)(chelloBodyLen >> 8));
        ms.WriteByte((byte)(chelloBodyLen & 0xFF));

        // client_version
        ms.WriteByte(verMajor);
        ms.WriteByte(verMinor);

        // random (32 bytes)
        ms.Write(clientRandom, 0, 32);

        // session_id
        ms.WriteByte(0);

        // cipher_suites
        ms.WriteByte((byte)(cipherBytes >> 8));
        ms.WriteByte((byte)(cipherBytes & 0xFF));
        foreach (ushort cs in ciphers)
        {
            ms.WriteByte((byte)(cs >> 8));
            ms.WriteByte((byte)(cs & 0xFF));
        }

        // compression_methods
        ms.WriteByte(1);
        ms.WriteByte(0);

        return ms.ToArray();
    }

    private static async Task ReadExactAsync(Stream s, byte[] buf, CancellationToken ct)
    {
        int total = 0;
        while (total < buf.Length)
        {
            int n = await s.ReadAsync(buf, total, buf.Length - total, ct).ConfigureAwait(false);
            if (n == 0) throw new EndOfStreamException("Unexpected EOF while reading SSLv2 ClientHello");
            total += n;
        }
    }
}

/// <summary>
/// Reads from a fixed in-memory prefix, then continues from an inner stream.
/// Writes go directly to the inner stream.
/// Used to "put back" bytes already consumed from a network stream.
/// </summary>
