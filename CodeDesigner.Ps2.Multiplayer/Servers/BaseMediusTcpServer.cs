using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using CodeDesigner.Ps2.Multiplayer.Config;
using CodeDesigner.Ps2.Multiplayer.Crypto;
using CodeDesigner.Ps2.Multiplayer.Models;
using CodeDesigner.Ps2.Multiplayer.Protocol;
using CodeDesigner.Ps2.Multiplayer.Storage;
using Microsoft.Extensions.Logging;

namespace CodeDesigner.Ps2.Multiplayer.Servers;

/// <summary>
/// Abstract TCP server that accepts SCERT connections, manages the per-client
/// receive buffer, and dispatches decoded packets to subclasses.
///
/// SCERT Handshake (SOCOM II / old Medius v &lt;= 108, 2002-2004 PS2 games):
///   CLIENT_HELLO               → SERVER_HELLO (128-byte RSA N or zeros)
///   CLIENT_CRYPTKEY_PUBLIC     → SERVER_CRYPTKEY_PEER  (PS2 auto-sends CLIENT_CONNECT_TCP next — no server trigger needed)
///   CLIENT_CONNECT_TCP         → [CRYPTKEY_GAME (MAS/MLS only)] + SERVER_CONNECT_ACCEPT_TCP + SERVER_CONNECT_COMPLETE
///   CLIENT_CONNECT_READY_TCP   → SERVER_CONNECT_COMPLETE
///   &lt;Medius app messages follow&gt;
///
/// SCERT Handshake (New Medius v &gt; 108, PS3 era):
///   ... same key exchange ...
///   CLIENT_CONNECT_TCP         → SERVER_CONNECT_REQUIRE
///   CLIENT_CONNECT_READY_REQUIRE → SERVER_CRYPTKEY_GAME + SERVER_CONNECT_ACCEPT_TCP
///   CLIENT_CONNECT_READY_TCP   → SERVER_CONNECT_COMPLETE
/// </summary>
public abstract class BaseMediusTcpServer
{
    private readonly ILogger      _log;
    private readonly MultiplayerConfig _config;
    private TcpListener?         _listener;

    private uint _scertIdCounter = 0;

    protected readonly ConcurrentDictionary<string, (MediusClientState State, TcpClient Client)> Clients = new();

    /// <summary>
    /// Per-connection write gate. The main receive loop and the background keepalive loop both write to
    /// the same socket; without serialization their byte streams interleave (a keepalive/cheat write
    /// landing mid-way through a community-batch write) and the client receives a corrupted packet and
    /// instantly disconnects — intermittently, depending on timing. Every send acquires this gate so only
    /// one write is ever in flight per connection. (RC4 is stateless per packet — see the decrypt path —
    /// so only the raw write needs serializing.)
    /// </summary>
    private readonly ConcurrentDictionary<TcpClient, SemaphoreSlim> _sendGates = new();

    protected BaseMediusTcpServer(ILogger log, MultiplayerConfig config)
    {
        _log    = log;
        _config = config;
    }

    public string ServerName { get; protected set; } = "SCERT";
    public int    Port       { get; protected set; }

    /// <summary>
    /// Whether to send SERVER_CRYPTKEY_GAME during the old-protocol CLIENT_CONNECT_TCP handshake.
    /// MUIS does NOT send it (matches Horizon); MAS and MLS do.
    /// </summary>
    protected virtual bool SendCryptKeyGameOnConnect => true;

    /// <summary>
    /// Old-proto (v108) connect: send a second SERVER_CRYPTKEY_PEER right after CRYPTKEY_GAME. The retail DME
    /// did (Join_Medley capture: GAME, PEER, ACCEPT_TCP, COMPLETE); the retail MAS/MLS did not.
    /// </summary>
    protected virtual bool SendCryptKeyPeerAfterGame => false;

    /// <summary>
    /// Old-proto (v108) connect hook, called after the encrypted CLIENT_CONNECT_TCP is parsed (WorldId, AppId,
    /// SessionKey, AccessKey set) and before CONNECT_ACCEPT. Return the (PlayerId, PlayerCount) to put in
    /// CONNECT_ACCEPT_TCP, or null for the defaults.
    /// </summary>
    protected virtual Task<(ushort PlayerId, ushort PlayerCount)?> OnOldProtoConnectAsync(
        MediusClientState state, TcpClient tcp, CancellationToken ct)
        => Task.FromResult<(ushort, ushort)?>(null);

    /// <summary>When true, a null result from <see cref="OnOldProtoConnectAsync"/> force-disconnects the client.</summary>
    protected virtual bool RejectUnboundOldProtoConnect => false;

    /// <summary>Old-proto (v108) hook, called right after SERVER_CONNECT_COMPLETE is sent.</summary>
    protected virtual Task OnOldProtoConnectCompleteAsync(MediusClientState state, TcpClient tcp, CancellationToken ct)
        => Task.CompletedTask;

    /// <summary>
    /// If true, OnSessionEstablishedAsync is called immediately after sending SERVER_CONNECT_COMPLETE
    /// in the old-protocol path, without waiting for CLIENT_CONNECT_READY_TCP.
    /// MUIS requires this: the PS2 disconnects from MUIS right after receiving CONNECT_COMPLETE
    /// and never sends CLIENT_CONNECT_READY_TCP.
    /// </summary>
    protected virtual bool PushDataAfterConnectComplete => false;

    /// <summary>
    /// When true, after the client self-heartbeats (lobby), the keepalive loop streams a periodic
    /// RT_MSG_SERVER_CHEAT_QUERY (anti-cheat heartbeat) instead of going silent. The official 2012
    /// server streams these continuously in the lobby; without them the community screen soft-disconnects
    /// (_1068_MEDIUS_DISCONNECTED_NETWORK) after ~90-120s. MLS only.
    /// </summary>
    protected virtual bool LobbyCheatHeartbeat => false;

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    public Task StartAsync(string bindAddress, int port, CancellationToken ct)
    {
        if (port == 0)
        {
            _log.LogInformation("[{Name}] Port = 0 — disabled, not listening", ServerName);
            return Task.CompletedTask;
        }
        Port      = port;
        _listener = new TcpListener(IPAddress.Parse(bindAddress), port);
        _listener.Start();
        _log.LogInformation("[{Name}] Listening on {Addr}:{Port}", ServerName, bindAddress, port);
        _ = AcceptLoopAsync(ct);
        return Task.CompletedTask;
    }

    public void Stop()
    {
        _listener?.Stop();
        foreach (var (_, (_, client)) in Clients)
            client.Close();
        Clients.Clear();
    }

    // -------------------------------------------------------------------------
    // Accept loop
    // -------------------------------------------------------------------------

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var tcp = await _listener!.AcceptTcpClientAsync(ct);
                _ = HandleClientAsync(tcp, ct);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _log.LogError(ex, "[{Name}] Accept error", ServerName);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Bans
    // -------------------------------------------------------------------------

    /// <summary>The account a connection belongs to (DME overrides — its connections are tied via the DME slot).</summary>
    protected virtual int? AccountIdOf(MediusClientState state) => state.AccountId;

    /// <summary>Close every connection whose account or IP is banned. Wired to <see cref="AdminSettings.BansChanged"/>.</summary>
    protected void KickBanned(BanList bans, InMemoryStorage store)
    {
        foreach (var (_, (state, tcp)) in Clients)
        {
            var name = AccountIdOf(state) is int id ? store.GetAccountById(id)?.AccountName : null;
            var ip = IPEndPoint.TryParse(state.RemoteEndpoint, out var ep) ? ep.Address : null;
            var ban = (name != null ? bans.FindAccount(name) : null) ?? bans.FindIp(ip);
            if (ban == null) continue;

            _log.LogWarning("[{Name}] Kicking {Who} ({Ep}) — banned: {Reason}", ServerName, name ?? "?", state.RemoteEndpoint, ban.Reason);
            try { tcp.Close(); } catch { /* already gone */ }
        }
    }

    // -------------------------------------------------------------------------
    // Per-client read loop
    // -------------------------------------------------------------------------

    private async Task HandleClientAsync(TcpClient tcp, CancellationToken ct)
    {
        tcp.NoDelay = true;

        var state = new MediusClientState
        {
            RemoteEndpoint = tcp.Client.RemoteEndPoint?.ToString() ?? "?",
            Timeout        = TimeSpan.FromSeconds(60),
        };

        Clients[state.ConnectionId] = (state, tcp);
        _log.LogInformation("[{Name}] Client connected: {Ep} ({Id})", ServerName, state.RemoteEndpoint, state.ConnectionId);

        await OnClientConnectedAsync(state, tcp);

        // Server-initiated keepalive. SOCOM II's idle timer fires after a stretch
        // of server silence and pops "Disconnected from Network" on the persona
        // screen mid-typing. RunKeepAliveLoopAsync pings the client with the exact
        // CLIENT_ECHO (0x05, payload 0xA5, RcClientSession) heartbeat the 2012 retail
        // MAS server used — see ScertPacket.CreateClientEcho. The earlier empty
        // SERVER_ECHO (0x1F) keepalive was the wrong message type and itself caused
        // the disconnect the moment it fired. The cancellation token kills the loop
        // the moment HandleClientAsync exits.
        using var keepAliveCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _ = RunKeepAliveLoopAsync(state, tcp, keepAliveCts.Token);

        var stream = tcp.GetStream();
        var buffer = new byte[8192];
        var pending = new List<byte>(8192);

        try
        {
            while (!ct.IsCancellationRequested && tcp.Connected)
            {
                int read = await stream.ReadAsync(buffer, ct);
                if (read == 0) break;

                state.Touch();
                _log.LogDebug("[{Name}] RAW recv {Len} bytes: {Hex}", ServerName, read,
                    BitConverter.ToString(buffer, 0, read).Replace("-", " "));
                pending.AddRange(buffer[..read]);

                // Parse as many complete packets as possible
                while (true)
                {
                    var pendingArray = pending.ToArray();
                    var packet = ScertPacket.TryRead(pendingArray, 0, pendingArray.Length, out int consumed);
                    if (packet == null || consumed == 0) break;

                    pending.RemoveRange(0, consumed);

                    // Decrypt payload in-place using per-packet stateless PS2 RC4.
                    // Only applies AFTER the key exchange completes (CLIENT_CRYPTKEY_PUBLIC
                    // itself is RSA-encrypted, not RC4 — don't decrypt it).
                    if (packet.IsEncrypted && packet.Hash != null && state.CryptKeyReceived)
                    {
                        int clear = ClearPrefixLength(packet.MessageType, packet.Payload.Length);
                        PS2_RC4.Decrypt(state.SessionRc4Key, packet.Hash, packet.Payload.AsSpan(clear));
                    }

                    // Isolate handler faults: a single malformed message must not tear down
                    // the connection (and drop every message queued behind it). Log and move on.
                    try
                    {
                        await DispatchPacketAsync(packet, state, tcp, ct);
                    }
                    catch (Exception ex) when (!ct.IsCancellationRequested)
                    {
                        _log.LogWarning("[{Name}] Handler error for {Type} from {Id}: {Msg}",
                            ServerName, packet.MessageType, state.ConnectionId, ex.Message);
                    }
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            _log.LogWarning("[{Name}] Client {Id} read error: {Msg}", ServerName, state.ConnectionId, ex.Message);
        }
        finally
        {
            if (pending.Count > 0)
                _log.LogWarning("[{Name}] Client {Id} disconnected with {N} unparsed bytes: {Hex}",
                    ServerName, state.ConnectionId, pending.Count,
                    BitConverter.ToString(pending.ToArray()).Replace("-", " "));
            Clients.TryRemove(state.ConnectionId, out _);
            if (_sendGates.TryRemove(tcp, out var sendGate)) sendGate.Dispose();
            await OnClientDisconnectedAsync(state);
            tcp.Close();
            _log.LogInformation("[{Name}] Client disconnected: {Id}", ServerName, state.ConnectionId);
        }
    }

    // -------------------------------------------------------------------------
    // Packet dispatch
    // -------------------------------------------------------------------------

    private async Task DispatchPacketAsync(ScertPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        _log.LogDebug("[{Name}] <- {Id} {Type} ({Len} bytes) {Hex}",
            ServerName, state.ConnectionId, packet.MessageType, packet.Payload.Length,
            BitConverter.ToString(packet.Payload).Replace("-", " "));

        switch (packet.MessageType)
        {
            case RT_MSG_TYPE.RT_MSG_CLIENT_HELLO:
                await HandleHelloAsync(packet, state, tcp, ct);
                break;

            case RT_MSG_TYPE.RT_MSG_CLIENT_CRYPTKEY_PUBLIC:
                await HandleCryptKeyPublicAsync(packet, state, tcp, ct);
                break;

            case RT_MSG_TYPE.RT_MSG_CLIENT_CONNECT_TCP:
                await HandleConnectTcpAsync(packet, state, tcp, ct);
                break;

            case RT_MSG_TYPE.RT_MSG_CLIENT_CRYPTKEY_PEER:
                // PS2 sends its own session key encrypted with the server's RSA public key
                // as mutual authentication. No server response is required; PS2 proceeds to
                // CLIENT_CONNECT_TCP immediately after this.
                _log.LogInformation("[{Name}] <- CLIENT_CRYPTKEY_PEER (mutual auth, {Len} bytes)", ServerName, packet.Payload.Length);
                break;

            case RT_MSG_TYPE.RT_MSG_CLIENT_CONNECT_READY_REQUIRE:
                await HandleConnectReadyRequireAsync(packet, state, tcp, ct);
                break;

            case RT_MSG_TYPE.RT_MSG_CLIENT_CONNECT_READY_TCP:
                await HandleConnectReadyTcpAsync(packet, state, tcp, ct);
                break;

            case RT_MSG_TYPE.RT_MSG_CLIENT_ECHO:
                // Mirror the client's heartbeat back as CLIENT_ECHO under RcClientSession,
                // exactly as the 2012 retail MAS server does (same type + hash 4F B8 CF 6A).
                // The client now heartbeats on its own — stop the proactive keepalive so we
                // don't out-ping it and trip the game's echo watchdog (see RunKeepAliveLoopAsync).
                state.ClientEchoSeen = true;
                await SendPacketAsync(tcp, ScertPacket.CreateEchoResponse(packet.Payload), state, CipherContext.RcClientSession, ct);
                break;

            case RT_MSG_TYPE.RT_MSG_CLIENT_APP_TOSERVER:
                _log.LogInformation("[{Name}] CLIENT_APP_TOSERVER ({Len} bytes): {Hex}",
                    ServerName, packet.Payload.Length,
                    BitConverter.ToString(packet.Payload).Replace("-", " "));
                var mp = MediusPacket.Parse(packet.Payload);
                if (mp != null)
                    await HandleMediusMessageAsync(mp, state, tcp, ct);
                else
                    await HandleRtMessageAsync(RT_MSG_TYPE.RT_MSG_CLIENT_APP_TOSERVER, packet.Payload, state, tcp, ct);
                break;

            case RT_MSG_TYPE.RT_MSG_SERVER_CHEAT_QUERY:
                // PS2 sends its anti-cheat response using the same 0x1D type byte.
                _log.LogInformation("[{Name}] <- CHEAT_QUERY response ({Len} bytes): {Hex}",
                    ServerName, packet.Payload.Length,
                    BitConverter.ToString(packet.Payload).Replace("-", " "));
                await HandleCheatQueryResponseAsync(packet, state, tcp, ct);
                break;

            case RT_MSG_TYPE.RT_MSG_CLIENT_APP_BROADCAST:
            case RT_MSG_TYPE.RT_MSG_CLIENT_APP_SINGLE:
            case RT_MSG_TYPE.RT_MSG_CLIENT_APP_LIST:
            case RT_MSG_TYPE.RT_MSG_CLIENT_SET_RECV_FLAG:
            case RT_MSG_TYPE.RT_MSG_CLIENT_SET_AGG_TIME:
            case RT_MSG_TYPE.RT_MSG_CLIENT_FLUSH_ALL:
            case RT_MSG_TYPE.RT_MSG_CLIENT_FLUSH_SINGLE:
                await HandleRtMessageAsync(packet.MessageType, packet.Payload, state, tcp, ct);
                break;

            case RT_MSG_TYPE.RT_MSG_CLIENT_DISCONNECT:
            case RT_MSG_TYPE.RT_MSG_CLIENT_DISCONNECT_WITH_REASON:
                tcp.Close();
                break;

            default:
                _log.LogInformation("[{Name}] Unhandled SCERT type {Type} payload={Hex}",
                    ServerName, packet.MessageType,
                    BitConverter.ToString(packet.Payload).Replace("-", " "));
                break;
        }
    }

    // -------------------------------------------------------------------------
    // SCERT handshake — common to all servers
    // -------------------------------------------------------------------------

    private async Task HandleHelloAsync(ScertPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        // CLIENT_HELLO payload: array of ushorts.
        // Parameters[0] = unknown/flags, Parameters[1] = MediusVersion
        if (packet.Payload.Length >= 4)
            state.MediusVersion = BitConverter.ToUInt16(packet.Payload, 2);  // Parameters[1]
        else if (packet.Payload.Length >= 2)
            state.MediusVersion = BitConverter.ToUInt16(packet.Payload, 0);  // fallback

        state.HelloReceived = true;
        _log.LogInformation("[{Name}] CLIENT_HELLO ver={Ver} from {Ep}", ServerName, state.MediusVersion, state.RemoteEndpoint);

        // Respond with SERVER_HELLO.  Some games (e.g. Ratchet) send CLIENT_HELLO
        // and expect a reply.  SOCOM II never sends CLIENT_HELLO (it expects the
        // proactive one from OnClientConnectedAsync), but responding here is harmless.
        await SendPacketAsync(tcp, ScertPacket.CreateHello(), ct);
    }

    private async Task HandleCryptKeyPublicAsync(ScertPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        state.CryptKeyReceived = true;

        // CLIENT_CRYPTKEY_PUBLIC payload is the raw RSA ciphertext — NOT outer-RC4-encrypted.
        // The PS2 sets 0x80 flag + hash for authentication but does not apply RC4 to this
        // packet (it has no session key yet).  Treat payload as RSA ciphertext directly.

        _log.LogDebug("[{Name}] CLIENT_CRYPTKEY_PUBLIC ({Len} bytes) hash={HashHex} payload={Hex}",
            ServerName, packet.Payload.Length,
            packet.Hash != null ? BitConverter.ToString(packet.Hash).Replace("-", " ") : "null",
            BitConverter.ToString(packet.Payload).Replace("-", " "));

        // The 64-byte payload is N_ps2 RSA-encrypted with Horizon's server public key
        // (N_server hardcoded in the PS2 game binary — independent of SERVER_HELLO content).
        // RSA-decrypt with D_server to recover N_ps2 in little-endian.
        // Some clients may omit the encrypted-header hash; treat that as all-zero hash.
        var hashForDecrypt = packet.Hash ?? new byte[4];

        if (!Ps2Rsa.ServerKey.Decrypt(packet.Payload, hashForDecrypt, out var ps2NBytes))
        {
            // Hash mismatch — log full diagnostic and continue without closing.
            // This can happen if the deployed binary didn't parse Hash correctly (stale build).
            // In that case treat the payload as plaintext N_ps2 as a fallback.
            var rawDecrypted = Ps2Rsa.ServerKey.DecryptRaw(packet.Payload);
            _log.LogWarning("[{Name}] CLIENT_CRYPTKEY_PUBLIC: hash mismatch. hash={H} rawDecrypt={D}",
                ServerName,
                BitConverter.ToString(hashForDecrypt).Replace("-", " "),
                BitConverter.ToString(rawDecrypted).Replace("-", " "));
            // Use the RSA-decrypted bytes even without hash verification.
            ps2NBytes = rawDecrypted;
        }

        _log.LogDebug("[{Name}] N_ps2 (LE)={Hex}", ServerName,
            BitConverter.ToString(ps2NBytes).Replace("-", " "));

        state.ClientCryptKey = ps2NBytes;
        state.ClientRsa      = Ps2Rsa.FromClientPublicKey(ps2NBytes);

        // Generate a random 64-byte RC4 session key, ensuring its value < N_ps2
        // so RSA encryption m^E mod N_ps2 is a bijection the PS2 can invert with D_ps2.
        state.SessionRc4Key = Ps2Rsa.GenerateMessageLessThan(state.ClientRsa.N);

        _log.LogDebug("[{Name}] SessionRc4Key={Hex}", ServerName,
            BitConverter.ToString(state.SessionRc4Key).Replace("-", " "));

        // Send CRYPTKEY_PEER with the raw session key (no RSA encryption, no 0x80 flag).
        // The PS2 SCERT overlay (old proto, type 0x13 without 0x80) uses the payload bytes
        // directly as its RC4 working key — it does NOT apply RSA decryption for this path.
        _log.LogDebug("[{Name}] CRYPTKEY_PEER payload={Hex}", ServerName,
            BitConverter.ToString(state.SessionRc4Key).Replace("-", " "));

        await SendPacketAsync(tcp, ScertPacket.CreateCryptKeyPeer(state.SessionRc4Key), ct);
        // CRYPTKEY_GAME is sent later, after the PS2 responds with its encrypted CLIENT_CONNECT_TCP.
    }

    private async Task HandleConnectTcpAsync(ScertPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        // The PS2 sends CLIENT_CONNECT_TCP twice:
        //   1st: plain, empty payload — the initial connect announcement (before key exchange).
        //   2nd: encrypted, payload contains [TargetWorldId:4][UNK0:1][AppId:4][RSA_KEY:...]
        //        This arrives after the PS2 has received CRYPTKEY_PEER.
        // We distinguish them by whether the key exchange has completed yet.
        if (!state.CryptKeyReceived)
        {
            // First CLIENT_CONNECT_TCP — plain, empty. Just acknowledge it internally.
            _log.LogDebug("[{Name}] <- CLIENT_CONNECT_TCP (initial, plain) — no response yet", ServerName);
            state.ConnectReceived = true;
            return;
        }

        // Second CLIENT_CONNECT_TCP — encrypted, carries AppId.
        state.ConnectReceived = true;

        // Payload layout (with RC4 NOP active on PS2, received as plaintext):
        //   Old Medius (version < 109):  [TargetWorldId: 4][UNK0: 1][AppId: 4][RSA_KEY: ...]
        //   New Medius (version >= 109): [TargetWorldId: 4][AppId: 4][RSA_KEY: ...]
        if (packet.Payload.Length >= 4)
        {
            // TargetWorldId: the world this connection is for — e.g. a briefing room's MediusWorldID
            // when the client reconnects after a successful JoinChannel. SOCOM II (v108) packs the world
            // into the HIGH byte of this u32; the low 3 bytes are constant (01 08 D2). On hardware:
            // login batch = 0x01D20801 (world 1, MAS default), US EAST room = 0x44D20801 (world 0x44).
            uint targetWorld = BitConverter.ToUInt32(packet.Payload, 0);
            state.WorldId = state.MediusVersion < 109 ? (int)(targetWorld >> 24) : (int)targetWorld;
            int pos = 4;
            if (state.MediusVersion < 109)
                pos += 1; // skip UNK0 (old protocol only)
            if (packet.Payload.Length >= pos + 4)
                state.AppId = BitConverter.ToInt32(packet.Payload, pos);

            // v108 tail (107 bytes total): ... [RSA_KEY:64 @9][SessionKey:17 @73][AccessKey:17 @90]
            const int keysAt = 4 + 1 + 4 + 64;
            if (state.MediusVersion < 109 && packet.Payload.Length >= keysAt + 2 * MediusConstants.SESSIONKEY_MAXLEN)
            {
                var r = new MediusReader(packet.Payload[(keysAt + MediusConstants.SESSIONKEY_MAXLEN)..]);
                state.AccessKey = r.ReadString(MediusConstants.SESSIONKEY_MAXLEN);
            }
        }

        _log.LogInformation("[{Name}] CLIENT_CONNECT_TCP (encrypted) AppId={AppId} ver={Ver} world=0x{World:X}",
            ServerName, state.AppId, state.MediusVersion, state.WorldId ?? 0);

        state.ScertId = Interlocked.Increment(ref _scertIdCounter);
        var clientIp = (tcp.Client.RemoteEndPoint as IPEndPoint)?.Address;

        if (state.MediusVersion > 108)
        {
            // New protocol: send SERVER_CONNECT_REQUIRE, client responds with CLIENT_CONNECT_READY_REQUIRE
            await SendPacketAsync(tcp, ScertPacket.CreateConnectRequire(), ct);
        }
        else
        {
            // Old protocol (SOCOM II era): send CRYPTKEY_GAME + CONNECT_ACCEPT + CONNECT_COMPLETE.
            // 2012 capture confirms ctx=3 (RcClientSession) for CRYPTKEY_GAME; however
            // CONNECT_ACCEPT and CONNECT_COMPLETE use ctx=1 (RcServerSession) in our implementation
            // because that is what the PS2 accepts in practice (allows proceeding to GetUniverse).
            // Session is established immediately — PS2 does NOT send CLIENT_CONNECT_READY_TCP on MUIS.
            var ids = await OnOldProtoConnectAsync(state, tcp, ct);
            if (ids == null && RejectUnboundOldProtoConnect)
            {
                _log.LogWarning("[{Name}] CLIENT_CONNECT_TCP rejected (world=0x{World:X})", ServerName, state.WorldId ?? 0);
                await SendPacketAsync(tcp, ScertPacket.CreateForcedDisconnect(1), state, ct);
                return;
            }
            var (playerId, playerCount) = ids ?? ((ushort)state.ScertId, (ushort)1);

            if (SendCryptKeyGameOnConnect)
            {
                _log.LogDebug("[{Name}] -> RT_MSG_SERVER_CRYPTKEY_GAME", ServerName);
                await SendPacketAsync(tcp, ScertPacket.CreateCryptKeyGame(state.SessionRc4Key), state, CipherContext.RcClientSession, ct);
            }
            if (SendCryptKeyPeerAfterGame)
                await SendPacketAsync(tcp, ScertPacket.CreateCryptKeyPeer(state.SessionRc4Key), ct);
            await SendPacketAsync(tcp, ScertPacket.CreateConnectAcceptTcp(state.ScertId, playerId, playerCount, clientIp, state.MediusVersion), state, ct);
            await SendPacketAsync(tcp, ScertPacket.CreateConnectComplete(), state, ct);
            state.IsSessionEstablished = true;
            _log.LogInformation("[{Name}] Old-proto handshake complete for {Ep}", ServerName, state.RemoteEndpoint);
            await OnOldProtoConnectCompleteAsync(state, tcp, ct);
            if (PushDataAfterConnectComplete)
                await OnSessionEstablishedAsync(state, tcp, ct);
        }
    }

    private async Task HandleConnectReadyRequireAsync(ScertPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        // PS2 replied to SERVER_CONNECT_REQUIRE — allocate ScertId and complete the handshake.
        state.ScertId = Interlocked.Increment(ref _scertIdCounter);
        var clientIp = (tcp.Client.RemoteEndPoint as IPEndPoint)?.Address;
        if (SendCryptKeyGameOnConnect)
        {
            await SendPacketAsync(tcp, ScertPacket.CreateCryptKeyGame(state.SessionRc4Key), state, ct);
        }
        await SendPacketAsync(tcp, ScertPacket.CreateConnectAcceptTcp(state.ScertId, (ushort)state.ScertId, 1, clientIp, state.MediusVersion), state, ct);
        await SendPacketAsync(tcp, ScertPacket.CreateConnectComplete(), state, ct);
        state.IsSessionEstablished = true;
        _log.LogInformation("[{Name}] SCERT session established (CONNECT_READY_REQUIRE path) for {Ep}", ServerName, state.RemoteEndpoint);
        await OnSessionEstablishedAsync(state, tcp, ct);
    }

    private async Task HandleConnectReadyTcpAsync(ScertPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        state.ConnectReadyReceived = true;
        // Reply with plain SERVER_CONNECT_COMPLETE — same reasoning as the first one:
        // the PS2 state machine checks for type byte 0x1A (plain), not 0x9A (encrypted).
        await SendPacketAsync(tcp, ScertPacket.CreateConnectComplete(), ct);
        if (state.MediusVersion > 108)
            await SendPacketAsync(tcp, ScertPacket.CreateServerEcho(), state, ct);
        if (!state.IsSessionEstablished)
        {
            state.IsSessionEstablished = true;
            _log.LogInformation("[{Name}] SCERT session established for {Ep}", ServerName, state.RemoteEndpoint);
            await OnSessionEstablishedAsync(state, tcp, ct);
        }
        else
        {
            _log.LogDebug("[{Name}] CLIENT_CONNECT_READY_TCP from already-established session {Id}", ServerName, state.ConnectionId);
        }
    }

    /// <summary>
    /// Background loop that sends a SERVER_ECHO every <see cref="KeepAliveInterval"/>
    /// once the SCERT session is established. Prevents PS2 clients from dropping
    /// the connection while the user is idle (e.g. typing a username at the
    /// login screen).
    /// </summary>
    /// <remarks>
    /// The 2012 retail captures (Masquarr_logoff_SII.pcap row [0001]) show the MAS server
    /// pinging idle clients with a CLIENT_ECHO (0x05) carrying a single 0xA5 byte under
    /// CipherContext.RcClientSession — hash 4F B8 CF 6A. SOCOM II resets its idle timer on
    /// receipt and stays on the persona screen. The previous empty SERVER_ECHO (0x1F)
    /// keepalive used the wrong message type/context and was itself the trigger for the
    /// "Disconnected from Network" drop. Use <see cref="ScertPacket.CreateClientEcho"/>.
    /// </remarks>
    private async Task RunKeepAliveLoopAsync(MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested && tcp.Connected)
            {
                await Task.Delay(KeepAliveInterval, ct);
                if (!tcp.Connected) return;
                if (!state.IsSessionEstablished) continue;

                // Once the client heartbeats on its own (post-login lobby), STOP pinging — the
                // client maintains the connection and extra server pings trip its echo watchdog,
                // dropping the lobby after a few minutes. Before that (persona screen) the client
                // is silent, so the proactive ping is what keeps the connection alive.
                // The ~90-120s community-screen drop is _1068_MEDIUS_DISCONNECTED_NETWORK (status 0x0B
                // @0x00452790) and is NOT a generic traffic-gap timeout (traffic flows both ways the whole
                // time yet it still fires). The leading lead is the missing anti-cheat CHEAT_QUERY stream
                // (official 2012 server sends it continuously in the lobby). On MLS we stream it here.
                if (state.ClientEchoSeen)
                {
                    if (LobbyCheatHeartbeat)
                    {
                        // Fallback/kickoff only — the brisk cheat-query ping-pong is driven reactively in
                        // HandleCheatQueryResponseAsync (retail runs it at ~50-180ms gaps). This slow timer
                        // (re)starts the exchange if the client's responses ever stall for CheatHeartbeatInterval.
                        if (DateTime.UtcNow - state.LastProactiveEchoAt < CheatHeartbeatInterval) continue;
                        try
                        {
                            await SendSaltedCheatQueryAsync(state, tcp, ct);
                        }
                        catch (Exception ex) when (!ct.IsCancellationRequested)
                        {
                            _log.LogDebug("[{Name}] Lobby cheat heartbeat send failed for {Id}: {Msg}", ServerName, state.ConnectionId, ex.Message);
                            return;
                        }
                    }
                    continue;
                }

                // Skip if the client sent us anything recently — only ping
                // when traffic has truly gone quiet, to avoid stepping on
                // legitimate exchanges.
                if (DateTime.UtcNow - state.LastMessageAt < KeepAliveInterval) continue;

                try
                {
                    await SendPacketAsync(tcp, ScertPacket.CreateClientEcho(), state, CipherContext.RcClientSession, ct);
                    _log.LogDebug("[{Name}] -> CLIENT_ECHO (keepalive) to {Id}", ServerName, state.ConnectionId);
                }
                catch (Exception ex) when (!ct.IsCancellationRequested)
                {
                    _log.LogDebug("[{Name}] Keepalive ECHO send failed for {Id}: {Msg}", ServerName, state.ConnectionId, ex.Message);
                    return;
                }
            }
        }
        catch (OperationCanceledException) { /* shutdown */ }
    }

    /// <summary>
    /// How often the server pings idle clients with SERVER_ECHO. PS2 idle
    /// timers fire around ~15-30s of total silence depending on the title;
    /// a 5s cadence leaves margin for a dropped packet on noisy networks.
    /// </summary>
    protected virtual TimeSpan KeepAliveInterval => TimeSpan.FromSeconds(5);

    /// <summary>Cadence of the lobby anti-cheat CHEAT_QUERY heartbeat (when <see cref="LobbyCheatHeartbeat"/>).
    /// 15s holds the community screen ~60-90s; faster cadences didn't extend it, so keep it calm (no spam).</summary>
    protected virtual TimeSpan CheatHeartbeatInterval => TimeSpan.FromSeconds(15);

    /// <summary>EE region the lobby CHEAT_QUERY asks the client to hash. Must be readable/resident — the
    /// SCUS-97275 main ELF loads at 0x00100000, so 0x00100000+0x1000 is always-present game code.</summary>
    protected virtual uint CheatQueryAddress => 0x00100000;
    protected virtual int  CheatQueryLength  => 0x1000;

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// <summary>Send a raw (unencrypted) SCERT packet — used only for pre-handshake messages.</summary>
    protected async Task SendPacketAsync(TcpClient tcp, ScertPacket packet, CancellationToken ct)
    {
        if (!tcp.Connected) return;

        // Serialize all writes on this connection so the keepalive loop and the main loop can't
        // interleave bytes on the wire (= corrupted packet → instant client disconnect).
        var gate = _sendGates.GetOrAdd(tcp, static _ => new SemaphoreSlim(1, 1));
        try { await gate.WaitAsync(ct); }
        catch (OperationCanceledException) { return; }

        try
        {
            var data = packet.Serialize();
            var stream = tcp.GetStream();
            await stream.WriteAsync(data, ct);
            _log.LogDebug("[{Name}] -> {Type} ({Len} bytes)", ServerName, packet.MessageType, packet.Payload.Length);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            _log.LogWarning("[{Name}] Send error: {Msg}", ServerName, ex.Message);
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>
    /// Send a SCERT packet, RC4-encrypting the payload with <paramref name="context"/>.
    /// Packets whose <see cref="ScertPacket.Hash"/> is already set are sent as-is.
    /// </summary>
    protected Task SendPacketAsync(TcpClient tcp, ScertPacket packet, MediusClientState state, CipherContext context, CancellationToken ct)
    {
        if (state.SessionRc4Key != null && packet.Hash == null)
        {
            int clear = ClearPrefixLength(packet.MessageType, packet.Payload.Length);
            PS2_RC4.Encrypt(state.SessionRc4Key, context,
                packet.Payload[clear..], out var cipher, out var hash);
            packet.Hash    = hash;
            packet.Payload = [.. packet.Payload.AsSpan(0, clear), .. cipher];
        }
        return SendPacketAsync(tcp, packet, ct);
    }

    /// <summary>
    /// Bytes at the start of an encrypted RT payload that travel in the clear. CLIENT_APP_SINGLE carries its
    /// [target/source DME index:2] unencrypted and the hash + RC4 cover only the data after it — seen on PCSX2:
    /// the host's identical handshake to fake peers 1, 2 and 3 had the same hash and ciphertext, only the
    /// leading index differed.
    /// </summary>
    private static int ClearPrefixLength(RT_MSG_TYPE type, int payloadLength)
        => type == RT_MSG_TYPE.RT_MSG_CLIENT_APP_SINGLE && payloadLength >= 2 ? 2 : 0;

    /// <summary>
    /// Send a SCERT packet encrypted with <see cref="CipherContext.RcServerSession"/>.
    /// Used for all post-handshake SERVER_APP traffic.
    /// </summary>
    protected Task SendPacketAsync(TcpClient tcp, ScertPacket packet, MediusClientState state, CancellationToken ct)
        => SendPacketAsync(tcp, packet, state, CipherContext.RcServerSession, ct);

    protected Task SendMediusAsync(TcpClient tcp, MediusPacket msg, MediusClientState state, CancellationToken ct)
    {
        var payload = msg.Serialize();
        return SendPacketAsync(tcp, ScertPacket.CreateServerApp(payload), state, ct);
    }

    /// <summary>
    /// Legacy overload used by derived-class handlers that have not yet been updated to pass state.
    /// Sends the SERVER_APP packet unencrypted; works because the PS2 SCERT overlay accepts
    /// both encrypted and plaintext packets based on the 0x80 type-byte flag.
    /// </summary>
    protected Task SendMediusAsync(TcpClient tcp, MediusPacket msg, CancellationToken ct)
    {
        var payload = msg.Serialize();
        return SendPacketAsync(tcp, ScertPacket.CreateServerApp(payload), ct);
    }

    // -------------------------------------------------------------------------
    // Binary injection (RT_MSG_SERVER_MEMORY_POKE)
    // -------------------------------------------------------------------------

    /// <summary>
    /// Build a SERVER_MEMORY_POKE payload: [destAddr:4 LE][size:4 LE][data:size].
    /// (Matches the retail SOCOM II code-download wire format.)
    /// </summary>
    private static byte[] BuildPokePayload(uint addr, ReadOnlySpan<byte> data)
    {
        var buf = new byte[8 + data.Length];
        BitConverter.GetBytes(addr).CopyTo(buf, 0);
        BitConverter.GetBytes((uint)data.Length).CopyTo(buf, 4);
        data.CopyTo(buf.AsSpan(8));
        return buf;
    }

    /// <summary>
    /// Stream <paramref name="blob"/> into EE memory at <paramref name="loadAddr"/> as a sequence of
    /// SERVER_MEMORY_POKE writes (<paramref name="chunkSize"/> bytes each, default 512 like retail),
    /// then — if <paramref name="hookAddr"/> is set — write a MIPS <c>J entry</c> there so the
    /// injected code runs (<paramref name="entryAddr"/> defaults to <paramref name="loadAddr"/>).
    /// Pokes are sent plaintext, matching the captured working-server stream.
    /// </summary>
    public async Task InjectBinaryAsync(TcpClient tcp, uint loadAddr, byte[] blob,
        uint? hookAddr, uint? entryAddr, int chunkSize, CancellationToken ct)
    {
        if (blob.Length == 0) return;
        chunkSize = Math.Clamp(chunkSize, 1, 1024);

        for (int off = 0; off < blob.Length; off += chunkSize)
        {
            int len = Math.Min(chunkSize, blob.Length - off);
            var poke = BuildPokePayload(loadAddr + (uint)off, blob.AsSpan(off, len));
            await SendPacketAsync(tcp, ScertPacket.CreateMemoryPoke(poke), ct);
        }

        if (hookAddr is uint hook)
        {
            uint target = entryAddr ?? loadAddr;
            uint jInstr = 0x08000000u | ((target >> 2) & 0x03FFFFFFu);          // MIPS: J target
            var hookPoke = BuildPokePayload(hook, BitConverter.GetBytes(jInstr));
            await SendPacketAsync(tcp, ScertPacket.CreateMemoryPoke(hookPoke), ct);
            _log.LogInformation("[{Name}] Injected hook J 0x{Tgt:X8} @ 0x{Hook:X8}", ServerName, target, hook);
        }

        _log.LogInformation("[{Name}] Injected {Len} bytes @ 0x{Addr:X8} ({N} pokes)",
            ServerName, blob.Length, loadAddr, (blob.Length + chunkSize - 1) / chunkSize);
    }

    /// <summary>On-demand: inject into a single tracked client by connection id. Returns false if not found.</summary>
    public async Task<bool> InjectIntoClientAsync(string connectionId, uint loadAddr, byte[] blob,
        uint? hookAddr, uint? entryAddr, int chunkSize, CancellationToken ct)
    {
        if (!Clients.TryGetValue(connectionId, out var c)) return false;
        await InjectBinaryAsync(c.Client, loadAddr, blob, hookAddr, entryAddr, chunkSize, ct);
        return true;
    }

    /// <summary>On-demand: inject into every currently-connected client. Returns how many received it.</summary>
    public async Task<int> InjectIntoAllAsync(uint loadAddr, byte[] blob,
        uint? hookAddr, uint? entryAddr, int chunkSize, CancellationToken ct)
    {
        int n = 0;
        foreach (var (_, (_, client)) in Clients)
        {
            if (!client.Connected) continue;
            try { await InjectBinaryAsync(client, loadAddr, blob, hookAddr, entryAddr, chunkSize, ct); n++; }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                _log.LogWarning("[{Name}] Inject to a client failed: {Msg}", ServerName, ex.Message);
            }
        }
        return n;
    }

    /// <summary>
    /// Resolve and send every enabled <see cref="MultiplayerConfig.Injections"/> entry to one client.
    /// Called when a player reaches the lobby. Missing files are logged and skipped, not fatal.
    /// </summary>
    protected async Task SendConfiguredInjectionsAsync(TcpClient tcp, CancellationToken ct)
    {
        foreach (var inj in _config.Injections)
        {
            if (!inj.Enabled) continue;
            if (!TryParseAddr(inj.LoadAddress, out uint loadAddr))
            {
                _log.LogWarning("[{Name}] Injection '{N}': bad LoadAddress '{A}'", ServerName, inj.Name, inj.LoadAddress);
                continue;
            }
            var path = ResolveInjectPath(inj.File);
            if (path == null) { _log.LogWarning("[{Name}] Injection '{N}': file not found '{F}'", ServerName, inj.Name, inj.File); continue; }

            uint? hookAddr  = TryParseAddr(inj.HookAddress, out uint h) ? h : null;
            uint? entryAddr = TryParseAddr(inj.EntryPoint, out uint e) ? e : null;
            var blob = await File.ReadAllBytesAsync(path, ct);

            _log.LogInformation("[{Name}] Injecting '{N}' ({Len} bytes) -> 0x{Addr:X8}", ServerName,
                string.IsNullOrEmpty(inj.Name) ? Path.GetFileName(path) : inj.Name, blob.Length, loadAddr);
            await InjectBinaryAsync(tcp, loadAddr, blob, hookAddr, entryAddr, inj.ChunkSize, ct);
        }
    }

    /// <summary>
    /// Replay a captured SERVER_MEMORY_POKE stream verbatim — SOCOM II's online-code download.
    /// File format (from dump_pokes.py): repeated [len:4 LE][pokePayload] where each pokePayload is
    /// already a complete [destAddr:4][size:4][data] poke block. The retail client ships WITHOUT
    /// online code; without this stream it finishes the lobby handshake then times out.
    /// </summary>
    protected async Task ReplayPokeStreamAsync(TcpClient tcp, string? binPath, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(binPath)) return;
        if (!File.Exists(binPath))
        {
            _log.LogWarning("[{Name}] LobbyPokeStreamFile not found: {Path}", ServerName, binPath);
            return;
        }

        var data = await File.ReadAllBytesAsync(binPath, ct);
        int off = 0, count = 0; long bytes = 0;
        while (off + 4 <= data.Length)
        {
            int len = BitConverter.ToInt32(data, off); off += 4;
            if (len <= 0 || off + len > data.Length) break;
            await SendPacketAsync(tcp, ScertPacket.CreateMemoryPoke(data[off..(off + len)]), ct);
            off += len; count++; bytes += len;
        }
        _log.LogInformation("[{Name}] Replayed {N} SERVER_MEMORY_POKE records ({Bytes} bytes) from {File}",
            ServerName, count, bytes, Path.GetFileName(binPath));
    }

    /// <summary>Parse a hex/decimal EE address string ("0x000A0000" or "655360"). False on null/blank/invalid.</summary>
    protected static bool TryParseAddr(string? s, out uint addr)
    {
        addr = 0;
        if (string.IsNullOrWhiteSpace(s)) return false;
        s = s.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return uint.TryParse(s.AsSpan(2), System.Globalization.NumberStyles.HexNumber, null, out addr);
        return uint.TryParse(s, out addr);
    }

    /// <summary>Resolve an injection .bin path (absolute, or relative to the app base dir / Data/). Null if missing.</summary>
    private static string? ResolveInjectPath(string file)
    {
        if (string.IsNullOrWhiteSpace(file)) return null;
        if (File.Exists(file)) return file;
        var baseRel = Path.Combine(AppContext.BaseDirectory, file);
        if (File.Exists(baseRel)) return baseRel;
        var dataRel = Path.Combine(AppContext.BaseDirectory, "Data", file);
        if (File.Exists(dataRel)) return dataRel;
        return null;
    }

    // -------------------------------------------------------------------------
    // Abstract / virtual
    // -------------------------------------------------------------------------

    protected virtual Task OnClientConnectedAsync(MediusClientState state, TcpClient tcp)
    {
        // Wait for the PS2 to initiate — it sends CLIENT_CONNECT_TCP (plain, empty) first,
        // then CLIENT_CRYPTKEY_PUBLIC. Do NOT send SERVER_HELLO proactively.
        return Task.CompletedTask;
    }

    /// <summary>
    /// Called immediately after the SCERT handshake completes and the session is established.
    /// Override in server subclasses to push initial data to the client (e.g. MUIS universe info).
    /// </summary>
    protected virtual Task OnSessionEstablishedAsync(MediusClientState state, TcpClient tcp, CancellationToken ct)
        => Task.CompletedTask;

    protected virtual Task OnClientDisconnectedAsync(MediusClientState state)
        => Task.CompletedTask;

    /// <summary>
    /// Called for raw RT transport-layer messages that are NOT decoded as Medius
    /// application-layer packets (e.g. DME game relay messages).
    /// </summary>
    protected virtual Task HandleRtMessageAsync(
        RT_MSG_TYPE msgType, byte[] payload, MediusClientState state, TcpClient tcp, CancellationToken ct)
        => Task.CompletedTask;

    /// <summary>
    /// Called when the PS2 sends an anti-cheat response (RT_MSG_SERVER_CHEAT_QUERY 0x1D).
    /// MUIS overrides this to drive the 3-round login cheat exchange. For the in-lobby anti-cheat
    /// (<see cref="LobbyCheatHeartbeat"/> servers, i.e. MLS) the client's salted-hash response is simply
    /// acknowledged here; the next challenge is issued on the steady <see cref="CheatHeartbeatInterval"/>
    /// timer in <see cref="RunKeepAliveLoopAsync"/>. (A faster reactive ping-pong was tried and did NOT
    /// extend the ~60-90s community-screen hold beyond the 15s-timer version — the remaining drop is a
    /// separate IOP-side watchdog — so we keep the calm cadence and don't spam.)
    /// </summary>
    protected virtual Task HandleCheatQueryResponseAsync(ScertPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
        => Task.CompletedTask;

    /// <summary>
    /// Sends one 29-byte salted RT_MSG_SERVER_CHEAT_QUERY (lobby anti-cheat challenge) and stamps the time.
    /// Driven by the keepalive loop on the <see cref="CheatHeartbeatInterval"/> cadence.
    /// </summary>
    protected async Task SendSaltedCheatQueryAsync(MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        state.LastProactiveEchoAt = DateTime.UtcNow;
        var salt = new byte[16];
        Random.Shared.NextBytes(salt);
        var seq = state.CheatSeq++;
        await SendPacketAsync(tcp, ScertPacket.CreateSaltedCheatQuery(seq, CheatQueryAddress, CheatQueryLength, salt), state, ct);
        _log.LogDebug("[{Name}] -> SERVER_CHEAT_QUERY salted seq={Seq} (lobby anti-cheat) to {Id}", ServerName, seq, state.ConnectionId);
    }

    protected abstract Task HandleMediusMessageAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct);
}
