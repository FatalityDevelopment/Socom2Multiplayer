using System.Net;
using System.Net.Sockets;
using CodeDesigner.Ps2.Multiplayer.Config;
using Microsoft.Extensions.Logging;

namespace CodeDesigner.Ps2.Multiplayer.Servers;

/// <summary>
/// UDP NAT punchthrough helper server.
///
/// PS2 games use this to discover their external IP address and port before
/// establishing peer-to-peer connections.  The client sends a short UDP
/// datagram; the server echoes back the client's source IP and port so the
/// client can advertise them to other players.
///
/// Protocol (ported from horizon-server Server.NAT/NAT.cs):
///   Client  →  Server : 4-byte datagram (last byte ≠ 0xD4 → request echo)
///   Server  →  Client : 6-byte reply [IP:4 LE][port:2 BE]
///
/// If the last byte of the incoming datagram IS 0xD4, the server silently
/// discards it (keepalive / ignore sentinel).
/// </summary>
public class NatServer
{
    private readonly MultiplayerConfig _config;
    private readonly ILogger<NatServer> _log;

    private UdpClient?         _udp;
    private CancellationToken  _ct;

    public NatServer(MultiplayerConfig config, ILogger<NatServer> log)
    {
        _config = config;
        _log    = log;
    }

    public Task StartAsync(CancellationToken ct)
    {
        _ct  = ct;
        if (_config.NatPort == 0)
        {
            _log.LogInformation("[NAT] Port = 0 — disabled, not listening");
            return Task.CompletedTask;
        }
        try
        {
            _udp = new UdpClient(new IPEndPoint(IPAddress.Parse(_config.BindAddress), _config.NatPort));
        }
        catch (SocketException ex)
        {
            // The NAT helper is optional; the rest of the server can run without it.
            _log.LogError("[NAT] Cannot bind {Addr}:{Port} (UDP): {Msg} — NAT helper disabled",
                _config.BindAddress, _config.NatPort, ex.Message);
            return Task.CompletedTask;
        }
        UdpSockets.IgnoreConnectionResets(_udp);
        _log.LogInformation("[NAT] Listening on {Addr}:{Port} (UDP)", _config.BindAddress, _config.NatPort);
        _ = ReceiveLoopAsync(ct);
        return Task.CompletedTask;
    }

    public void Stop()
    {
        try { _udp?.Close(); } catch { /* ignore */ }
    }

    // ── Receive loop ──────────────────────────────────────────────────────────

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var result = await _udp!.ReceiveAsync(ct);
                _ = HandleDatagramAsync(result);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                _log.LogWarning("[NAT] Receive error: {Msg}", ex.Message);
                await Task.Delay(100, ct);
            }
        }
    }

    private async Task HandleDatagramAsync(UdpReceiveResult result)
    {
        var data     = result.Buffer;
        var endpoint = result.RemoteEndPoint;

        // 4-byte minimum; last byte == 0xD4 → silent discard.
        // 0xD4 is the Medius keepalive sentinel used to hold the NAT binding open
        // without triggering an echo reply — the client expects no response to it.
        if (data.Length < 4 || data[^1] == 0xD4)
            return;

        _log.LogDebug("[NAT] Echo request from {Ep}", endpoint);

        // Build 6-byte response: [clientIP:4 LE][clientPort:2 BE]
        var reply     = new byte[6];
        var ipBytes   = endpoint.Address.MapToIPv4().GetAddressBytes();
        Buffer.BlockCopy(ipBytes, 0, reply, 0, 4);
        reply[4] = (byte)((endpoint.Port >> 8) & 0xFF);
        reply[5] = (byte)(endpoint.Port & 0xFF);

        try
        {
            await _udp!.SendAsync(reply, reply.Length, endpoint);
            _log.LogDebug("[NAT] Sent echo {IP}:{Port} → {Ep}", endpoint.Address, endpoint.Port, endpoint);
        }
        catch (Exception ex)
        {
            _log.LogWarning("[NAT] Send error to {Ep}: {Msg}", endpoint, ex.Message);
        }
    }
}
