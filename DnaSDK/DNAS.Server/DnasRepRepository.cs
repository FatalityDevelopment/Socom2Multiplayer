using System;
using System.IO;
using System.Net;
using System.Net.Http;

namespace DNAS;

/// <summary>
/// Fetches an archived original S1 template by the lookup ID and operation in
/// the authenticated client C1. This is an archival ticket source, never a
/// replay engine: the returned template is not transmitted to the client.
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

    public DnasRepRepository(string? repositoryBaseUrl = null)
    {
        _baseUrl = (repositoryBaseUrl ??
            "https://raw.githubusercontent.com/FogNo23/DNASrep/master/www/dnas").TrimEnd('/');

        if (!Uri.TryCreate(_baseUrl, UriKind.Absolute, out Uri? uri) || uri.Scheme != Uri.UriSchemeHttps)
            throw new ArgumentException("DNASRep origin must be an absolute HTTPS URL.", nameof(repositoryBaseUrl));
    }

    public byte[] FetchS1Template(C1Packet request)
    {
        ArgumentNullException.ThrowIfNull(request);

        string lookup = Convert.ToHexString(request.LookupId8).ToLowerInvariant();
        string operation = request.Header.Operation.ToString("x8");
        string fileName = $"{lookup}_{operation}";

        foreach (string region in Regions)
        {
            foreach (string layout in Layouts)
            {
                string directory = layout.Replace("{region}", region, StringComparison.Ordinal);
                string url = $"{_baseUrl}/{directory}/{fileName}";

                // A missing archive object is not evidence of authentication
                // failure and must not authorize a fallback RSA ticket.
                using HttpResponseMessage response = Http.GetAsync(url).GetAwaiter().GetResult();
                if (response.StatusCode == HttpStatusCode.NotFound)
                    continue;

                response.EnsureSuccessStatusCode();
                byte[] content = response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
                if (content.Length > 4096)
                    throw new FormatException("DNASRep response unexpectedly large.");

                return content;
            }
        }

        throw new FileNotFoundException(
            "No matching original S1 response found for lookup ID and operation: " + fileName);
    }
}
