using System.Threading.Channels;
using Microsoft.Extensions.Logging;
// ─────────────────────────────────────────────────────────────────────────────
// Simple append-to-file logger — no extra NuGet packages required.
// Lines are queued and written by one background task, so logging never blocks a connection on disk I/O.
// The file rolls to <name>.1 … <name>.<KeepFiles> once it reaches MaxFileBytes.
// ─────────────────────────────────────────────────────────────────────────────

public sealed class FileLoggerProvider : ILoggerProvider
{
    public const long MaxFileBytes = 50L * 1024 * 1024;
    public const int  KeepFiles    = 3;

    /// <summary>Queued lines; when the writer falls this far behind, new lines are dropped rather than buffered.</summary>
    private const int QueueCapacity = 100_000;

    private readonly string _path;
    private readonly Channel<string> _queue = Channel.CreateBounded<string>(
        new BoundedChannelOptions(QueueCapacity) { SingleReader = true, FullMode = BoundedChannelFullMode.DropWrite });
    private readonly Task _writerTask;

    public FileLoggerProvider(string path)
    {
        _path = path;
        _writerTask = Task.Run(WriteLoopAsync);
    }

    public ILogger CreateLogger(string categoryName) => new FileLogger(categoryName, line => _queue.Writer.TryWrite(line));

    private async Task WriteLoopAsync()
    {
        StreamWriter? writer = null;
        try
        {
            writer = Open();
            await foreach (var line in _queue.Reader.ReadAllAsync())
            {
                writer.WriteLine(line);
                // Flush once the queue is drained: bursts cost one flush, and a quiet log is always on disk.
                if (_queue.Reader.Count == 0) writer.Flush();
                if (writer.BaseStream.Length >= MaxFileBytes)
                {
                    writer.Dispose();
                    Roll();
                    writer = Open();
                }
            }
        }
        catch (IOException)
        {
            // Disk trouble: stop file logging rather than take the server down (console logging continues).
        }
        finally
        {
            writer?.Dispose();
        }
    }

    private StreamWriter Open() => new(new FileStream(_path, FileMode.Append, FileAccess.Write, FileShare.Read));

    private void Roll()
    {
        for (int i = KeepFiles - 1; i >= 1; i--)
        {
            var from = $"{_path}.{i}";
            if (File.Exists(from)) File.Move(from, $"{_path}.{i + 1}", overwrite: true);
        }
        File.Move(_path, $"{_path}.1", overwrite: true);
    }

    public void Dispose()
    {
        _queue.Writer.TryComplete();
        _writerTask.Wait(TimeSpan.FromSeconds(5));
    }
}
