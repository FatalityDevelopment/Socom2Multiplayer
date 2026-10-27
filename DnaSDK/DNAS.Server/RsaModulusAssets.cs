using System;
using System.Collections.Generic;
using System.IO;

namespace DNAS;

/// <summary>
/// Installs optional RSA modulus assets without embedding game information
/// into the SDK. File names are discovered at runtime, never hard-coded.
/// Existing user-supplied modulus files are never overwritten.
/// </summary>
internal static class RsaModulusAssets
{
    public static void CopyMissing(string ticketRoot)
    {
        string? assets = FindModulusAssets();
        if (assets == null)
            return;

        // Store root may be relative to the working directory; the executable
        // output folder is a separate destination when launched by Visual Studio.
        CopyTo(assets, Path.Combine(ticketRoot, "Moduli"));
        CopyTo(assets, Path.Combine(AppContext.BaseDirectory, "RSA", "Moduli"));
    }

    private static string? FindModulusAssets()
    {
        HashSet<string> visited = new(StringComparer.OrdinalIgnoreCase);
        foreach (string start in new[] { Environment.CurrentDirectory, AppContext.BaseDirectory })
        {
            DirectoryInfo? directory = new(Path.GetFullPath(start));
            while (directory != null && visited.Add(directory.FullName))
            {
                string candidate = Path.Combine(directory.FullName, "Assets", "Moduli");
                if (Directory.Exists(candidate))
                    return candidate;
                directory = directory.Parent;
            }
        }
        return null;
    }

    private static void CopyTo(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (string file in Directory.EnumerateFiles(source, "*.BIN", SearchOption.TopDirectoryOnly))
        {
            if (new FileInfo(file).Length != 128)
            {
                Console.Error.WriteLine($"[RSA] Ignoring invalid modulus asset: {Path.GetFileName(file)}");
                continue;
            }

            string output = Path.Combine(destination, Path.GetFileName(file));
            if (File.Exists(output))
                continue;

            // Never overwrite a user-maintained modulus or an existing cache.
            try
            {
                File.Copy(file, output, overwrite: false);
                Console.WriteLine($"[RSA] Installed optional modulus: {output}");
            }
            catch (IOException) when (File.Exists(output))
            {
                // Concurrent instance won the non-overwriting copy.
            }
        }
    }
}
