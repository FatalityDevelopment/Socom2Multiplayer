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

internal sealed class PrefixedStream : Stream
{
    private readonly byte[] _prefix;
    private int _prefixPos;
    private readonly Stream _inner;

    internal PrefixedStream(byte[] prefix, Stream inner)
    {
        _prefix   = prefix;
        _prefixPos = 0;
        _inner    = inner;
    }

    public override bool CanRead  => true;
    public override bool CanSeek  => false;
    public override bool CanWrite => _inner.CanWrite;
    public override long Length   => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush() => _inner.Flush();

    public override long Seek(long offset, SeekOrigin origin)
        => throw new NotSupportedException();

    public override void SetLength(long value)
        => throw new NotSupportedException();

    public override int Read(byte[] buffer, int offset, int count)
    {
        int remaining = _prefix.Length - _prefixPos;
        if (remaining > 0)
        {
            int take = Math.Min(count, remaining);
            Buffer.BlockCopy(_prefix, _prefixPos, buffer, offset, take);
            _prefixPos += take;
            return take;
        }
        return _inner.Read(buffer, offset, count);
    }

    public override void Write(byte[] buffer, int offset, int count)
        => _inner.Write(buffer, offset, count);

    protected override void Dispose(bool disposing)
    {
        if (disposing) _inner.Dispose();
        base.Dispose(disposing);
    }
}
