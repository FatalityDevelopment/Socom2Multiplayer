using Microsoft.Extensions.Logging;

public sealed class FileLogger : ILogger
{
    private readonly string _category;
    private readonly Action<string> _write;

    public FileLogger(string category, Action<string> write)
    {
        _category = category.Split('.').Last();
        _write    = write;
    }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    // The host's filter rules (Logging:LogLevel) decide what reaches this provider.
    public bool IsEnabled(LogLevel level) => level != LogLevel.None;

    public void Log<TState>(LogLevel level, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(level)) return;
        var line = $"{DateTime.Now:HH:mm:ss.fff} [{level.ToString()[..4]}] {_category}: {formatter(state, exception)}";
        if (exception != null) line += Environment.NewLine + exception;
        _write(line);
    }
}
