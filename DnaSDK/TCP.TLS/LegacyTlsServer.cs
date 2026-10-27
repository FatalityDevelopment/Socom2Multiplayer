using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;

namespace TLS;

/// <summary>
/// BouncyCastle-based TLS server for legacy HTTPS connections.
///
/// Windows Schannel on modern Windows (10 22H2+) hard-blocks RC4 and SSLv3 at
/// the kernel level regardless of registry settings. The original PS2 client only
/// offers TLS_RSA_WITH_RC4_128_SHA, TLS_RSA_WITH_RC4_128_MD5 and
/// TLS_RSA_WITH_3DES_EDE_CBC_SHA — none of which Schannel will negotiate.
///
/// BouncyCastle implements TLS entirely in userspace using its own crypto, so
/// it can negotiate any cipher suite we register here.
/// </summary>
internal sealed class LegacyTlsServer : DefaultTlsServer
{
    private readonly X509Certificate2 _cert;
    private readonly AsymmetricKeyParameter? _bcKey;
    private readonly X509Certificate2? _caCert;
    private readonly Action<string>? _log;

    // SSLv2 transcript-hash fix (see NotifyOfferedCipherSuites / FixSsl2TranscriptHash).
    private readonly byte[]? _ssl2Payload;
    private readonly TlsServerProtocol? _bcProtocol;

    internal LegacyTlsServer(BcTlsCrypto crypto, X509Certificate2 cert, AsymmetricKeyParameter? bcKey, X509Certificate2? caCert, Action<string>? log, byte[]? ssl2Payload = null, TlsServerProtocol? bcProtocol = null)
        : base(crypto)
    {
        _cert       = cert;
        _bcKey      = bcKey;
        _caCert     = caCert;
        _log        = log;
        _ssl2Payload = ssl2Payload;
        _bcProtocol  = bcProtocol;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Protocol version — force TLS 1.0 only.
    //
    // The original PS2 SSL library sends an SSLv2-format ClientHello but uses TLS 1.0
    // record-layer semantics (implicit CBC IV, TLS 1.0 PRF).  It may advertise
    // a high version (e.g. TLS 1.2 cipher suites like 0x0066) in the SSLv2
    // hello's version field.  If BC negotiates TLS 1.2, it expects an 8-byte
    // explicit IV in every CBC record — the PS2 sends none, so decryption of
    // the client Finished fails with decrypt_error(51).
    //
    // Locking to TLS 1.0 ensures both sides use implicit IV and TLS 1.0 PRF.
    // ─────────────────────────────────────────────────────────────────────────

    protected override ProtocolVersion[] GetSupportedVersions()
        => new[] { ProtocolVersion.TLSv10 };

    // ─────────────────────────────────────────────────────────────────────────
    // RFC 5746 (secure renegotiation) — the PS2 SSLv2-format ClientHello has
    // no concept of renegotiation_info; BC's default throws handshake_failure
    // when secureRenegotiation=false.  Accept legacy clients silently.
    // ─────────────────────────────────────────────────────────────────────────

    public override void NotifySecureRenegotiation(bool secureRenegotiation)
    {
        // The PS2 SSLv2 ClientHello has no renegotiation_info and we deliberately
        // do not inject TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00FF) — see Ssl2Adapter.
        // secureRenegotiation will therefore be false; suppress the default
        // handshake_failure that DefaultTlsServer would otherwise throw.
        // With secureRenegotiation=false, BC sends a ServerHello with no
        // renegotiation_info extension, which the PS2 SSL library accepts.
    }

    public override void NotifyOfferedCipherSuites(int[] offeredSuiteData)
    {
        // ── SSLv2 transcript-hash proxy ──────────────────────────────────────
        // BC calls NotifyOfferedCipherSuites *inside* GenerateServerHello(),
        // BEFORE it hashes the ClientHello.  The actual hashing happens right
        // after GenerateServerHello() returns via:
        //
        //   buf.UpdateHash(m_handshakeHash);        ← TLS ClientHello bytes
        //   SendServerHelloMessage(serverHello);    ← ServerHello bytes
        //
        // The PS2 (OpenSSL SSLv23 hybrid) hashes the original SSLv2 payload
        // instead of the converted TLS ClientHello.  We cannot suppress BC's
        // call, so we install a TlsHandshakeHash proxy that intercepts the
        // *first* Update() call and substitutes our SSLv2 payload.  All
        // subsequent calls (ServerHello, Certificate, …) pass through normally.
        if (_ssl2Payload != null && _bcProtocol != null)
            InstallTranscriptHashProxy();

        _log?.Invoke($"PS2 offered {offeredSuiteData.Length} cipher suites: {string.Join(", ", offeredSuiteData.Select(s => $"0x{s:X4}"))}");
        base.NotifyOfferedCipherSuites(offeredSuiteData);
    }

    private void InstallTranscriptHashProxy()
    {
        try
        {
            var field = typeof(TlsProtocol).GetField("m_handshakeHash", BindingFlags.NonPublic | BindingFlags.Instance);
            var raw = field?.GetValue(_bcProtocol);
            if (raw is TlsHandshakeHash innerHash)
            {
                field!.SetValue(_bcProtocol, new Ssl2TranscriptHashProxy(innerHash, _ssl2Payload!));
                _log?.Invoke($"SSLv2 transcript hash proxy installed ({_ssl2Payload!.Length} bytes)");
            }
            else
            {
                _log?.Invoke($"WARN: Could not install transcript proxy — m_handshakeHash type={raw?.GetType().FullName ?? "<null>"}");
            }
        }
        catch (Exception ex)
        {
            _log?.Invoke($"WARN: InstallTranscriptHashProxy: {ex.Message}");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TlsHandshakeHash proxy — substitutes SSLv2 payload for TLS ClientHello
    //
    // BC's DeferredHash accumulates the TLS ClientHello via its first Update().
    // We intercept that call and feed the original SSLv2 payload instead, so
    // both sides (PS2 and BC) compute the Finished hash over the same bytes.
    // All other method calls are forwarded to the wrapped DeferredHash.
    // ─────────────────────────────────────────────────────────────────────────
    private sealed class Ssl2TranscriptHashProxy : TlsHandshakeHash
    {
        private readonly TlsHandshakeHash _inner;
        private readonly byte[] _ssl2Payload;
        private bool _firstUpdateDone;

        internal Ssl2TranscriptHashProxy(TlsHandshakeHash inner, byte[] ssl2Payload)
        {
            _inner = inner;
            _ssl2Payload = ssl2Payload;
        }

        // Intercept the first Update() call — that is BC hashing the TLS ClientHello.
        // We emit the SSLv2 payload bytes instead; all later calls go straight through.
        public void Update(byte[] input, int inOff, int length)
        {
            if (!_firstUpdateDone)
            {
                _firstUpdateDone = true;
                _inner.Update(_ssl2Payload, 0, _ssl2Payload.Length);
            }
            else
            {
                _inner.Update(input, inOff, length);
            }
        }

        public void Update(ReadOnlySpan<byte> input)
        {
            if (!_firstUpdateDone)
            {
                _firstUpdateDone = true;
                _inner.Update(_ssl2Payload, 0, _ssl2Payload.Length);
            }
            else
            {
                _inner.Update(input);
            }
        }

        // Everything else delegates to the inner hash unchanged.
        public byte[] CalculateHash()                              => _inner.CalculateHash();
        public TlsHash CloneHash()                                 => _inner.CloneHash();
        public void Reset()                                        => _inner.Reset();
        public void CopyBufferTo(System.IO.Stream output)          => _inner.CopyBufferTo(output);
        public void ForceBuffering()                               => _inner.ForceBuffering();
        public void NotifyPrfDetermined()                          => _inner.NotifyPrfDetermined();
        public void TrackHashAlgorithm(int cryptoHashAlgorithm)    => _inner.TrackHashAlgorithm(cryptoHashAlgorithm);
        public void SealHashAlgorithms()                           => _inner.SealHashAlgorithms();
        public void StopTracking()                                 => _inner.StopTracking();
        public TlsHash ForkPrfHash()                               => _inner.ForkPrfHash();
        public byte[] GetFinalHash(int cryptoHashAlgorithm)        => _inner.GetFinalHash(cryptoHashAlgorithm);
    }

    public override int GetSelectedCipherSuite()
    {
        // Use SERVER preference order (iterate our list, pick first the client also offered).
        // Prefer the PS2-compatible ciphers our installed BouncyCastle release can handle.
        // This release supports RSA/3DES here; it cannot negotiate the older RC4 suites.
        foreach (int suite in GetSupportedCipherSuites())
        {
            if (m_offeredCipherSuites != null && Array.IndexOf(m_offeredCipherSuites, suite) >= 0)
            {
                _log?.Invoke($"Cipher suite selected (server pref): 0x{suite:X4}");
                return suite;
            }
        }
        // Fall back to BC default if none of ours are offered.
        var selected = base.GetSelectedCipherSuite();
        _log?.Invoke($"Cipher suite selected (client pref fallback): 0x{selected:X4}");
        return selected;
    }

    // Suppress all server-side TLS extensions — the PS2 DNAS SSL library is
    // SSLv3-era and may not handle unknown extensions gracefully.
    public override IDictionary<int, byte[]> GetServerExtensions()
        => new System.Collections.Generic.Dictionary<int, byte[]>();

    // ─────────────────────────────────────────────────────────────────────────
    // Cipher suite preference — offer what the PS2 DNAS client can accept
    // ─────────────────────────────────────────────────────────────────────────

    protected override int[] GetSupportedCipherSuites() => new[]
    {
        // RC4 (0x0005, 0x0004) was removed from BouncyCastle 2.x TLS engine —
        // selecting it causes internal_error(80) during session-key setup.
        // 3DES-EDE-CBC is the PS2's next choice and is fully supported by BC 2.x.
        CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,  // PS2 cipher suite 0x000A
    };

    // ─────────────────────────────────────────────────────────────────────────
    // RSA key-exchange credentials (non-ephemeral RSA — what the PS2 uses)
    // ─────────────────────────────────────────────────────────────────────────

    protected override TlsCredentialedDecryptor GetRsaEncryptionCredentials()
    {
        try
        {
            return GetRsaEncryptionCredentialsCore();
        }
        catch (Exception ex)
        {
            _log?.Invoke($"GetRsaEncryptionCredentials failed ({_bcKey?.GetType().Name ?? "<null>"}): {ex}");
            throw;
        }
    }

    private TlsCredentialedDecryptor GetRsaEncryptionCredentialsCore()
    {
        // Build the TLS Certificate chain: leaf cert + CA cert (if available).
        // The PS2 firmware does not cache intermediate CAs; the full chain must
        // be sent in the TLS Certificate message or the PS2 cannot verify the leaf.
        var tlsCerts = _caCert != null
            ? new TlsCertificate[]
              {
                  new BcTlsCertificate((BcTlsCrypto)m_context.Crypto, _cert.RawData),
                  new BcTlsCertificate((BcTlsCrypto)m_context.Crypto, _caCert.RawData),
              }
            : new TlsCertificate[]
              {
                  new BcTlsCertificate((BcTlsCrypto)m_context.Crypto, _cert.RawData),
              };
        var certChain = new Certificate(tlsCerts);

        AsymmetricKeyParameter bcPrivKey;
        if (_bcKey != null)
        {
            // Generated and PEM keys are supplied directly in BC form; no CNG export.
            bcPrivKey = _bcKey;
        }
        else
        {
            // Fallback: derive BC key from the .NET RSA object (requires Exportable flag).
            // Auto-generated and PEM private keys are passed directly to BC; only
            // externally supplied PFX certificates need this fallback.
            using var rsa = _cert.GetRSAPrivateKey() ?? throw new InvalidOperationException("TLS certificate has no RSA private key.");
            try { bcPrivKey = FromRsaParameters(rsa.ExportParameters(includePrivateParameters: true)); }
            catch (System.Security.Cryptography.CryptographicException ex)
            {
                throw new InvalidOperationException("PFX private key cannot be exported for BouncyCastle TLS. Supply an exportable PFX or an unencrypted --cert-pem/--key-pem pair.", ex);
            }
        }

        // BcDefaultTlsCredentialedDecryptor is the public BC class for RSA key-exchange
        return new BcDefaultTlsCredentialedDecryptor((BcTlsCrypto)m_context.Crypto, certChain, bcPrivKey);
    }

    // Export a newly generated .NET key before passing its certificate to Windows.
    // Prevents Windows X509/CNG key-provider restrictions during TLS handshakes.
    internal static AsymmetricKeyParameter FromRsaParameters(System.Security.Cryptography.RSAParameters key)
        => new RsaPrivateCrtKeyParameters(new BigInteger(1, key.Modulus!), new BigInteger(1, key.Exponent!), new BigInteger(1, key.D!), new BigInteger(1, key.P!), new BigInteger(1, key.Q!), new BigInteger(1, key.DP!), new BigInteger(1, key.DQ!), new BigInteger(1, key.InverseQ!));
}
