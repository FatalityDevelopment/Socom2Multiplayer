using System.Text;

namespace CodeDesigner.Ps2.Multiplayer.Storage;

internal static class AtomicFile
{
    /// <summary>
    /// Replace <paramref name="path"/> with <paramref name="text"/> so a crash leaves either the old file or the new
    /// one, never a half-written mix: write a temp file, flush it to disk, then rename it over the target.
    /// </summary>
    public static void WriteAllText(string path, string text)
    {
        var tmp = path + ".tmp";
        using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            var bytes = Encoding.UTF8.GetBytes(text);
            fs.Write(bytes);
            fs.Flush(flushToDisk: true);
        }
        File.Move(tmp, path, overwrite: true);
    }
}
