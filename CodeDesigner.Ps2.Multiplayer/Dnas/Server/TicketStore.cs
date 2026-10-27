using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CodeDesigner.Ps2.Multiplayer.Dnas;

/// <summary>
/// Stores original DNAS RSA signatures by serial. The signed 128-byte operand
/// is sufficient for the live server; a title-specific public modulus is only
/// needed to create the optional decoded RSA block and enrich the text report.
/// </summary>
public sealed class TicketStore
{
    private readonly string _root;
    private readonly DnasRepRepository _repository;
    private readonly ConcurrentDictionary<string, object> _gates = new(StringComparer.Ordinal);

    public TicketStore(string root = "RSA", string? repositoryBaseUrl = null, string? preferredRegion = null)
    {
        if (!Path.IsPathRooted(root) && !Directory.Exists(root) && Directory.Exists(Path.Combine(AppContext.BaseDirectory, root)))
            root = Path.Combine(AppContext.BaseDirectory, root);

        _root = Path.GetFullPath(root);
        RsaModulusAssets.CopyMissing(_root);
        _repository = new DnasRepRepository(repositoryBaseUrl, preferredRegion);
    }

    /// <summary>
    /// Reads RSA/Signatures/SERIAL.BIN. If absent, obtains the archived S1 by
    /// the validated C1 lookup ID, extracts its original 128-byte signature,
    /// and caches it. Missing modulus files never block this process.
    /// </summary>
    public byte[] GetOrFetch(string serial, C1Packet request)
    {
        ArgumentNullException.ThrowIfNull(request);
        string name = NormalizeSerial(serial);
        string signaturePath = Path.Combine(_root, "Signatures", name + ".BIN");

        lock (_gates.GetOrAdd(name, _ => new object()))
        {
            if (File.Exists(signaturePath))
            {
                byte[] local = File.ReadAllBytes(signaturePath);
                Guard.Size(local, 128, signaturePath);
                SaveDiagnosticFiles(name, request, local, null);
                return local;
            }

            byte[] template = FetchTemplate(request);
            byte[] signature = template.AsSpan(0x48, 128).ToArray();

            // The original 128-byte operand is extracted independently of the
            // optional modulus. The retail client verifies this operand.
            // A matching archival lookup is not proof of RSA validity.
            Directory.CreateDirectory(Path.GetDirectoryName(signaturePath)!);
            SaveDiagnosticFiles(name, request, signature, template);
            File.WriteAllBytes(signaturePath, signature);
            return signature;
        }
    }

    /// <summary>Returns the separately supplied modulus, or null if absent.</summary>
    public byte[]? TryGetPublicModulus(string serial)
    {
        string name = NormalizeSerial(serial);
        string path = Path.Combine(_root, "Moduli", name + ".BIN");
        if (!File.Exists(path)) return null;

        byte[] modulus = File.ReadAllBytes(path);
        if (modulus.Length != 128)
        {
            Console.Error.WriteLine($"[RSA] Ignoring invalid optional modulus file {path}: expected 128 bytes.");
            return null;
        }
        return modulus;
    }

    private static string NormalizeSerial(string serial)
    {
        return Identity.NormalizeGameSerial(serial).Replace("-", "", StringComparison.Ordinal);
    }

    private byte[] FetchTemplate(C1Packet request)
    {
        byte[] template = _repository.FetchS1Template(request);
        if (template.Length != 328)
            throw new FormatException("DNASRep S1 template must be exactly 328 bytes for this request family.");

        uint actual = BinaryPrimitives.ReadUInt32BigEndian(template.AsSpan(0, 4));
        uint expected = (request.Header.Operation & 0xFFFF0000u) | 5u;
        if (actual != expected)
            throw new CryptographicException($"Archived S1 operation mismatch: expected 0x{expected:X8}, received 0x{actual:X8}.");

        int bodyLength = BinaryPrimitives.ReadInt32BigEndian(template.AsSpan(36, 4));
        if (bodyLength != 288)
            throw new FormatException("Archived S1 header/body length mismatch.");

        return template;
    }

    /// <summary>
    /// Writes the public-RSA diagnostic when an optional modulus is available.
    /// A missing or mismatched modulus never prevents use of the signed ticket.
    /// Existing archived S1 metadata is retained when refreshing a report.
    /// </summary>
    private void SaveDiagnosticFiles(string name, C1Packet request, byte[] signature, byte[]? template)
    {
        string decodedPath = Path.Combine(_root, "Signatures", name + "_DC.BIN");
        string reportPath = Path.Combine(_root, "Decoded", name + ".TXT");
        byte[]? modulus = TryGetPublicModulus(name);
        byte[]? decodedBlock = null;
        byte[]? payload117 = null;
        string? decodeError = null;

        if (modulus != null)
        {
            try
            {
                byte[] candidate = RSA.PublicOperation(signature, modulus);
                payload117 = RSA.ExtractType1(candidate, 117);
                decodedBlock = candidate;
            }
            catch (Exception error) when (error is FormatException or ArgumentException or CryptographicException)
            {
                decodeError = error.Message;
                Console.Error.WriteLine($"[RSA] Optional public decode failed for {name}: {decodeError}");
            }
        }

        string? previous = File.Exists(reportPath) ? File.ReadAllText(reportPath) : null;
        string report = DnasTicketReport.Create(name, request, signature, template, previous, decodedBlock, payload117, decodeError, modulus != null);

        if (!string.Equals(previous, report, StringComparison.Ordinal))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(reportPath)!);
            File.WriteAllText(reportPath, report, new UTF8Encoding(false));
        }

        if (decodedBlock != null)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(decodedPath)!);
            if (!File.Exists(decodedPath) || !File.ReadAllBytes(decodedPath).AsSpan().SequenceEqual(decodedBlock))
                File.WriteAllBytes(decodedPath, decodedBlock);
        }
    }
}
