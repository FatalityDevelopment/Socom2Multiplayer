using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;

namespace DNAS;

/// <summary>
/// Fetches an archived original S1 template by the lookup ID and operation in
/// the authenticated client C1. This is an archival ticket source, never a
/// replay engine: the returned template is not transmitted to the client.
///
/// The archive root is either an HTTPS URL (DNASrep on GitHub by default) or a
/// local directory holding the same layout, e.g. Data/us-gw/packets/LOOKUP_OPERATION.
/// </summary>
public sealed class DnasRepRepository
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(10) };
    private static readonly string[] Regions = { "us-gw", "eu-gw", "gai-gw" };
    private static readonly string[] Layouts =
    {
        "{region}/packets",
        "data/{region}/packets",
        "packets/{region}"
    };

    private readonly string _baseUrl;
    private readonly string? _localRoot;
    private readonly string[] _regions;

    public DnasRepRepository(string? repositoryBaseUrl = null, string? preferredRegion = null)
    {
        _baseUrl = (repositoryBaseUrl ??
            "https://raw.githubusercontent.com/FogNo23/DNASrep/master/www/dnas").TrimEnd('/', '\\');

        // The preferred region is searched first; the others remain fallbacks.
        _regions = string.IsNullOrWhiteSpace(preferredRegion)
            ? Regions
            : Regions.OrderBy(region => !string.Equals(region, preferredRegion, StringComparison.OrdinalIgnoreCase)).ToArray();

        if (Uri.TryCreate(_baseUrl, UriKind.Absolute, out Uri? uri) && uri.Scheme == Uri.UriSchemeHttps)
            return;

        if (Uri.TryCreate(_baseUrl, UriKind.Absolute, out uri) && uri.Scheme != Uri.UriSchemeFile)
            throw new ArgumentException("DNASRep origin must be an absolute HTTPS URL or a local directory.", nameof(repositoryBaseUrl));

        // A relative directory resolves against the executable, then the working directory.
        string local = uri?.IsFile == true ? uri.LocalPath : _baseUrl;
        if (!Path.IsPathRooted(local) && Directory.Exists(Path.Combine(AppContext.BaseDirectory, local)))
            local = Path.Combine(AppContext.BaseDirectory, local);

        // A missing directory is reported per lookup, so tickets already cached keep working.
        _localRoot = Path.GetFullPath(local);
    }

    /// <summary>The archive root in use: a local directory or an HTTPS URL.</summary>
    public string Origin => _localRoot ?? _baseUrl;

    public byte[] FetchS1Template(C1Packet request)
    {
        ArgumentNullException.ThrowIfNull(request);

        string lookup = Convert.ToHexString(request.LookupId8).ToLowerInvariant();
        string operation = request.Header.Operation.ToString("x8");
        string fileName = $"{lookup}_{operation}";

        foreach (string region in _regions)
        {
            foreach (string layout in Layouts)
            {
                string directory = layout.Replace("{region}", region, StringComparison.Ordinal);
                byte[]? content = _localRoot != null
                    ? ReadLocal(Path.Combine(_localRoot, directory, fileName))
                    : ReadRemote($"{_baseUrl}/{directory}/{fileName}");

                // A missing archive object is not evidence of authentication
                // failure and must not authorize a fallback RSA ticket.
                if (content == null)
                    continue;

                if (content.Length > 4096)
                    throw new FormatException("DNASRep response unexpectedly large.");

                return content;
            }
        }

        throw new FileNotFoundException(
            $"No matching original S1 response found in {Origin} for lookup ID and operation: " + fileName);
    }

    private static byte[]? ReadLocal(string path)
    {
        return File.Exists(path) ? File.ReadAllBytes(path) : null;
    }

    private static byte[]? ReadRemote(string url)
    {
        using HttpResponseMessage response = Http.GetAsync(url).GetAwaiter().GetResult();
        if (response.StatusCode == HttpStatusCode.NotFound)
            return null;

        response.EnsureSuccessStatusCode();
        return response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
    }
}
