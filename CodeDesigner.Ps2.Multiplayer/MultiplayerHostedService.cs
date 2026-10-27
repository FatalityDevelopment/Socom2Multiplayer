using CodeDesigner.Ps2.Multiplayer.Config;
using CodeDesigner.Ps2.Multiplayer.Servers;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
// ─────────────────────────────────────────────────────────────────────────────

public class MultiplayerHostedService : IHostedService
{
    private readonly MuisServer          _muis;
    private readonly MasServer           _mas;
    private readonly MlsServer           _mls;
    private readonly DnasServer          _dnas;
    private readonly DnsServer           _dns;
    private readonly DmeServer           _dme;
    private readonly NatServer           _nat;
    private readonly PatchHttpServer     _patch;
    private readonly DebugApiServer      _debug;
    private readonly MultiplayerConfig   _config;
    private readonly ILogger<MultiplayerHostedService> _log;
    private CancellationTokenSource _cts = new();

    public MultiplayerHostedService(
        MuisServer muis, MasServer mas, MlsServer mls, DnasServer dnas,
        DnsServer dns, DmeServer dme, NatServer nat, PatchHttpServer patch, DebugApiServer debug,
        MultiplayerConfig config, ILogger<MultiplayerHostedService> log)
    {
        _muis   = muis;
        _mas    = mas;
        _mls    = mls;
        _dnas   = dnas;
        _dns    = dns;
        _dme    = dme;
        _nat    = nat;
        _patch  = patch;
        _debug  = debug;
        _config = config;
        _log    = log;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var ct = _cts.Token;

        _log.LogInformation("═══════════════════════════════════════════════════");
        _log.LogInformation("  SOCOM II Multiplayer Server");
        _log.LogInformation("  Server IP   : {Ip}",   _config.ServerIp);
        _log.LogInformation("  MUIS Port   : {Port}", _config.MuisPort);
        _log.LogInformation("  MAS Port    : {Port}", _config.MasPort);
        _log.LogInformation("  MLS Port    : {Port}", _config.MlsPort);
        _log.LogInformation("  DME Port    : {Port}", _config.DmePort);
        _log.LogInformation("  NAT Port    : {Port} (UDP)", _config.NatPort);
        _log.LogInformation("  DNAS HTTPS  : {Port} (DnaSDK)", _config.DnasHttpsPort);
        _log.LogInformation("  DNS Port    : {Port} (UDP, intercepts *.dnas.playstation.org)", _config.DnsDnasPort);
        _log.LogInformation("  Patch HTTP  : {Port} ({Ver})", _config.PatchHttpPort, _config.UniversePatchVersion);
        _log.LogInformation("  AppIds      : {Ids}",  string.Join(", ", _config.AllowedAppIds));
        _log.LogInformation("═══════════════════════════════════════════════════");

        await _muis.StartAsync(ct);
        await _mas.StartAsync(ct);
        await _mls.StartAsync(ct);
        await _dns.StartAsync(ct);
        await _dnas.StartAsync(ct);
        await _dme.StartAsync(ct);
        await _nat.StartAsync(ct);
        await _patch.StartAsync(ct);
        await _debug.StartAsync(ct);
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _log.LogInformation("Shutting down multiplayer servers...");
        _cts.Cancel();
        _muis.Stop();
        _mas.Stop();
        _mls.Stop();
        _dns.Stop();
        _dnas.Stop();
        _dme.Stop();
        _nat.Stop();
        _patch.Stop();
        _debug.Stop();
        return Task.CompletedTask;
    }
}
