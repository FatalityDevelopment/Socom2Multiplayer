using System.Net.Sockets;
using System.Text;
using CodeDesigner.Ps2.Multiplayer.Config;
using CodeDesigner.Ps2.Multiplayer.Models;
using CodeDesigner.Ps2.Multiplayer.Protocol;
using CodeDesigner.Ps2.Multiplayer.Storage;
using Microsoft.Extensions.Logging;

namespace CodeDesigner.Ps2.Multiplayer.Servers;

/// <summary>
/// DME (game world) TCP server.
///
/// SOCOM II (v108) flow, from the retail Join_Medley capture:
///   1. MLS JoinGame reserves a slot in a <see cref="DmeWorld"/> and returns NetConnectionInfo
///      (this server's address, the DME world id, and the slot's access token).
///   2. The client connects here with the normal SCERT handshake. Its encrypted CLIENT_CONNECT_TCP carries
///      the DME world id (one byte, v108 packing) and the access token.
///   3. Server replies CRYPTKEY_GAME, CRYPTKEY_PEER, CONNECT_ACCEPT_TCP (PlayerId = DME slot,
///      PlayerCount), CONNECT_COMPLETE, then SERVER_APP DMEServerVersion "1.22.0140".
///   4. RT_MSG_CLIENT_APP_* frames are relayed to the other players in the world.
/// </summary>
public class DmeServer : BaseMediusTcpServer
{
    /// <summary>
    /// Retail DME server version — hash-verified: the 18-byte SERVER_APP after CONNECT_COMPLETE in
    /// Join_Medley (hash 6f795527) is exactly [00 00]["1.22.0140" zero-padded to 16].
    /// </summary>
    private const string RetailDmeServerVersion = "1.22.0140";
    private const int DmeVersionLength = 16;

    private readonly MultiplayerConfig _config;
    private readonly PresenceRegistry _presence;
    private readonly ILogger<DmeServer> _log;

    public DmeServer(MultiplayerConfig config, PresenceRegistry presence, InMemoryStorage store, AdminSettings admin,
        ILogger<DmeServer> log)
        : base(log, config)
    {
        _config    = config;
        _presence  = presence;
        _log       = log;
        ServerName = "DME";
        DmeClientState.PlayerNotificationsEnabled = config.DmePlayerNotifications;
        admin.BansChanged += bans => KickBanned(bans, store);
    }

    protected override int? AccountIdOf(MediusClientState state) =>
        FindSlot(state)?.AccountId is int id && id != 0 ? id : null;

    public Task StartAsync(CancellationToken ct) =>
        StartAsync(_config.BindAddress, _config.DmePort, ct);

    /// <summary>Create a DME world for the Medius game <paramref name="mediusWorldId"/>.</summary>
    public static DmeWorld CreateWorld(int mediusWorldId, int appId, int maxPlayers)
        => new(mediusWorldId, appId, maxPlayers);

    // ── Connect (v108 hooks) ──────────────────────────────────────────────────

    protected override bool SendCryptKeyPeerAfterGame => true;
    protected override bool RejectUnboundOldProtoConnect => true;

    protected override Task<(ushort PlayerId, ushort PlayerCount)?> OnOldProtoConnectAsync(
        MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var world = state.WorldId is int id ? DmeWorld.GetById(id) : null;
        var slot  = world?.FindByAccessKey(state.AccessKey);
        if (world == null || slot == null)
        {
            _log.LogWarning("[DME] Connect for world {World} with unknown access key '{Key}' ({Worlds})",
                state.WorldId, state.AccessKey.Length > 4 ? state.AccessKey[..4] + "…" : state.AccessKey, string.Join(", ", DmeWorld.All));
            return Task.FromResult<(ushort, ushort)?>(null);
        }

        slot.IsConnected   = true;
        slot.MediusVersion = state.MediusVersion;
        slot.ScertId       = state.ScertId;
        if (state.ClientCryptKey.Length > 0) slot.PublicKey = state.ClientCryptKey;
        if (tcp.Client.RemoteEndPoint is System.Net.IPEndPoint ep) slot.IpAddress = ep.Address.MapToIPv4().ToString();
        slot.Bind(
            (type, payload) => SendPacketAsync(tcp, new ScertPacket { MessageType = type, Payload = payload }, state, ct),
            () =>
            {
                _log.LogWarning("[DME] Player {Id} in {World} fell {N} frames behind — disconnecting",
                    slot.DmeId, world, DmeClientState.OutboxCapacity);
                try { tcp.Close(); } catch { /* already gone */ }
            });

        state.DmeWorldId         = world.WorldId;
        state.DmeClientIndex     = slot.DmeId;
        state.IsDmeAuthenticated = true;

        _log.LogInformation("[DME] Account {Acct} bound to {World} as player {Id}",
            slot.AccountId, world, slot.DmeId);
        return Task.FromResult<(ushort, ushort)?>(((ushort)slot.DmeId, (ushort)world.ConnectedCount));
    }

    protected override async Task OnOldProtoConnectCompleteAsync(MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var slot = FindSlot(state);
        if (slot == null) return;

        // DMEServerVersion: [MessageClassDME=0][ServerVersion=0][Version:16]
        var msg = new byte[2 + DmeVersionLength];
        Encoding.ASCII.GetBytes(RetailDmeServerVersion).CopyTo(msg, 2);
        await SendPacketAsync(tcp, ScertPacket.CreateServerApp(msg), state, ct);

        slot.HasJoined = true;
        slot.World.NotifyPlayerJoined(slot);
    }

    // ── Disconnect cleanup ────────────────────────────────────────────────────

    protected override Task OnClientDisconnectedAsync(MediusClientState state)
    {
        var slot = FindSlot(state);
        if (slot != null)
        {
            var world = slot.World;
            world.NotifyPlayerLeft(slot);
            world.RemoveClient(slot);
            if (slot.AccountId != 0) _presence.LeftGame(slot.AccountId);
            _log.LogInformation("[DME] Player {Id} left {World}", slot.DmeId, world);

            if (world.Clients.IsEmpty && world.SelfDestructFlag)
            {
                world.Destroy();
                _log.LogInformation("[DME] {World} destroyed (empty + self-destruct)", world);
            }
        }
        return Task.CompletedTask;
    }

    // ── Message dispatch ──────────────────────────────────────────────────────

    private const byte DmeMessageClass = (byte)NetMessageClass.MessageClassDME;
    private const byte DmePing         = (byte)DmeAppMessageId.Ping;

    protected override async Task HandleMediusMessageAsync(
        MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        // DME Ping (class 0, id 1) sent to the server: TimeOfSend:u32 | PingInstance:u8 | RequestEcho:u8 | pad2.
        // SOCOM sends one about once a minute with RequestEcho=1 (on hardware: 00 00 00 00 01 01 00 00).
        // Echo it back unchanged except RequestEcho=0, the standard DME ping reply — horizon doesn't handle it.
        if ((byte)packet.MessageClass == DmeMessageClass && packet.MessageType == DmePing && packet.Payload.Length >= 6)
        {
            if (packet.Payload[5] != 0)
            {
                var reply = new byte[2 + packet.Payload.Length];
                reply[0] = DmeMessageClass;
                reply[1] = DmePing;
                packet.Payload.CopyTo(reply, 2);
                reply[2 + 5] = 0;                                  // RequestEcho = 0
                await SendPacketAsync(tcp, ScertPacket.CreateServerApp(reply), state, ct);
                _log.LogDebug("[DME] -> Ping echo (instance {Inst})", packet.Payload[4]);
            }
            return;
        }

        _log.LogInformation("[DME] Medius msg class=0x{C:X2} type=0x{T:X2} ({Len} bytes)",
            (byte)packet.MessageClass, packet.MessageType, packet.Payload.Length);
    }

    protected override Task HandleRtMessageAsync(
        RT_MSG_TYPE msgType, byte[] payload, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var slot = FindSlot(state);
        if (slot == null)
        {
            _log.LogDebug("[DME] {Type} from unbound connection ignored", msgType);
            return Task.CompletedTask;
        }
        slot.LastMessageAt = DateTime.UtcNow;
        var world = slot.World;

        switch (msgType)
        {
            case RT_MSG_TYPE.RT_MSG_CLIENT_APP_BROADCAST:
                world.BroadcastApp(slot, payload);
                break;

            case RT_MSG_TYPE.RT_MSG_CLIENT_APP_SINGLE when payload.Length >= 2:
                world.SendAppSingle(slot, payload[0] | (payload[1] << 8), payload[2..]);
                break;

            case RT_MSG_TYPE.RT_MSG_CLIENT_APP_LIST when payload.Length >= 1:
            {
                // [count:1][targetId:2 LE] * count + [data]
                int count = payload[0];
                int dataOffset = 1 + count * 2;
                if (payload.Length < dataOffset) break;
                // Each target gets one copy: repeated ids (or the sender itself) would multiply the relay.
                var targets = new HashSet<int>(count);
                for (int i = 0; i < count; i++)
                {
                    int target = payload[1 + i * 2] | (payload[2 + i * 2] << 8);
                    if (target != slot.DmeId) targets.Add(target);
                }
                world.SendAppList(slot, targets, payload[dataOffset..]);
                break;
            }

            case RT_MSG_TYPE.RT_MSG_CLIENT_SET_RECV_FLAG when payload.Length >= 1:
                slot.RecvFlag = (RT_RECV_FLAG)payload[0];
                break;

            case RT_MSG_TYPE.RT_MSG_CLIENT_FLUSH_ALL:
            case RT_MSG_TYPE.RT_MSG_CLIENT_FLUSH_SINGLE:
            case RT_MSG_TYPE.RT_MSG_CLIENT_SET_AGG_TIME:
                break;

            default:
                _log.LogInformation("[DME] Unhandled RT {Type} ({Len} bytes)", msgType, payload.Length);
                break;
        }
        return Task.CompletedTask;
    }

    private static DmeClientState? FindSlot(MediusClientState state)
    {
        if (state.DmeWorldId is not int worldId || state.DmeClientIndex is not int index) return null;
        var world = DmeWorld.GetById(worldId);
        return world != null && world.Clients.TryGetValue(index, out var slot) ? slot : null;
    }
}
