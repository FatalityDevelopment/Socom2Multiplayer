using Microsoft.Extensions.Logging;

public sealed class FileLogger : ILogger
{
    private readonly string _category;
    private readonly StreamWriter _writer;
    private readonly object _lock;

    public FileLogger(string category, StreamWriter writer, object @lock)
    {
        _category = category;
        _writer   = writer;
        _lock     = @lock;
    }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel level) => level >= LogLevel.Debug;

    public void Log<TState>(LogLevel level, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(level)) return;
        var line = $"{DateTime.Now:HH:mm:ss.fff} [{level.ToString()[..4]}] {_category.Split('.').Last()}: {formatter(state, exception)}";
        if (exception != null) line += Environment.NewLine + exception;
        lock (_lock) _writer.WriteLine(line);
    }
}
