using Microsoft.Extensions.Logging;
// ─────────────────────────────────────────────────────────────────────────────
// Simple append-to-file logger — no extra NuGet packages required.
// ─────────────────────────────────────────────────────────────────────────────

public sealed class FileLoggerProvider : ILoggerProvider
{
    private readonly StreamWriter _writer;
    private readonly object _lock = new();

    public FileLoggerProvider(string path)
    {
        _writer = new StreamWriter(path, append: false) { AutoFlush = true };
    }

    public ILogger CreateLogger(string categoryName) => new FileLogger(categoryName, _writer, _lock);

    public void Dispose() => _writer.Dispose();
}
