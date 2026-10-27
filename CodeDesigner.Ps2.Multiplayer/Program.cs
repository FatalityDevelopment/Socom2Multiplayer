using CodeDesigner.Ps2.Multiplayer.Config;
using CodeDesigner.Ps2.Multiplayer.Servers;
using CodeDesigner.Ps2.Multiplayer.Storage;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

// ─────────────────────────────────────────────────────────────────────────────
// CodeDesigner.Ps2.Multiplayer
// PS2 online server emulator: Medius (MUIS + MAS + MLS) + DNAS
// Compatible with SOCOM II and other SCE Medius-based PS2 games.
// ─────────────────────────────────────────────────────────────────────────────

var builder = Host.CreateApplicationBuilder(args);

// Config: config.json next to the binary, then an optional extra file (MULTIPLAYER_CONFIG, e.g. a mounted
// volume), then environment variables LAST so they override both — containers set e.g. Online__ServerIp.
builder.Configuration
    .SetBasePath(AppContext.BaseDirectory)
    .AddJsonFile("config.json", optional: true, reloadOnChange: false);
if (Environment.GetEnvironmentVariable("MULTIPLAYER_CONFIG") is { Length: > 0 } extraConfig)
    builder.Configuration.AddJsonFile(extraConfig, optional: false, reloadOnChange: false);
builder.Configuration.AddEnvironmentVariables();

// Console logging + file logging. MULTIPLAYER_LOG_FILE overrides the file path; "none" disables it
// (containers log to stdout — an unbounded file would just fill the container disk).
var logFile = Environment.GetEnvironmentVariable("MULTIPLAYER_LOG_FILE") is { Length: > 0 } logEnv
    ? logEnv
    : Path.Combine(AppContext.BaseDirectory, "multiplayer.log");
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
if (!logFile.Equals("none", StringComparison.OrdinalIgnoreCase))
    builder.Logging.AddProvider(new FileLoggerProvider(logFile));
builder.Logging.SetMinimumLevel(LogLevel.Debug);

// Load server config
var serverConfig = new MultiplayerConfig();
builder.Configuration.GetSection("Online").Bind(serverConfig);
// Also accept the legacy "Medius" section so old config.json files still work
if (serverConfig.ServerIp == "127.0.0.1" && builder.Configuration.GetSection("Medius").Exists())
    builder.Configuration.GetSection("Medius").Bind(serverConfig);

builder.Services.AddSingleton(serverConfig);

// Shared in-memory storage
builder.Services.AddSingleton<InMemoryStorage>();
builder.Services.AddSingleton<PresenceRegistry>();
builder.Services.AddSingleton<AdminSettings>();

// Servers
builder.Services.AddSingleton<MuisServer>();
builder.Services.AddSingleton<MasServer>();
builder.Services.AddSingleton<MlsServer>();
builder.Services.AddSingleton<DnasServer>();
builder.Services.AddSingleton<DnsServer>();
builder.Services.AddSingleton<DmeServer>();
builder.Services.AddSingleton<NatServer>();
builder.Services.AddSingleton<PatchHttpServer>();
builder.Services.AddSingleton<DebugApiServer>();

// Hosted service that starts everything
builder.Services.AddHostedService<MultiplayerHostedService>();

var host = builder.Build();

// ServerIp "auto" (container deployments): resolve the public IP before any server announces it.
await ServerIpResolver.ResolveAsync(serverConfig,
    host.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Config"), CancellationToken.None);

await host.RunAsync();
