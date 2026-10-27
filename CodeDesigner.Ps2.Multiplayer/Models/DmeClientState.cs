using CodeDesigner.Ps2.Multiplayer.Protocol;

namespace CodeDesigner.Ps2.Multiplayer.Models;

/// <summary>
/// One player slot in a <see cref="DmeWorld"/>.
///
/// The slot is reserved by MLS JoinGame (keyed by an access token returned in the JoinGameResponse's
/// NetConnectionInfo), then bound to a TCP connection when the client's CLIENT_CONNECT_TCP to the DME
/// presents that token — the same reserve-then-connect model as horizon-server's DME.
/// </summary>
public class DmeClientState
{
    // ── Identity ──────────────────────────────────────────────────────────────

    /// <summary>MLS session key of the player that reserved this slot.</summary>
    public string SessionKey { get; }

    /// <summary>Access token handed out in JoinGameResponse; the DME connect presents it back.</summary>
    public string AccessKey { get; }

    /// <summary>Account that reserved the slot (for logging / game player counts).</summary>
    public int AccountId { get; }

    /// <summary>Slot index within the <see cref="DmeWorld"/> (0 … MaxClients-1).</summary>
    public int DmeId { get; }

    /// <summary>
    /// Reserved through JoinGame with JoinType spectator / mass spectator. SOCOM II's CreateGame MaxPlayers already
    /// counts the spectator seats (players + spectators, GameStats[4] = max spectators), so spectators share the
    /// world's slots; the flag only drives the server's own counts and logs.
    /// </summary>
    public bool IsSpectator { get; set; }

    /// <summary>SCERT client ID assigned during the SCERT handshake.</summary>
    public uint ScertId { get; set; }

    /// <summary>Medius protocol version (108 = old PS2, >108 = PS3).</summary>
    public int MediusVersion { get; set; } = 108;

    /// <summary>The world this client belongs to.</summary>
    public DmeWorld World { get; }

    // ── Transport ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Sends one RT frame (type + plaintext payload) to this client over its encrypted DME connection.
    /// Null until the client's TCP connection is bound to the slot.
    /// </summary>
    public Func<RT_MSG_TYPE, byte[], Task>? Sender { get; set; }

    // ── State flags ───────────────────────────────────────────────────────────

    /// <summary>Whether a TCP connection is bound to this slot.</summary>
    public bool IsConnected { get; set; }

    /// <summary>True once the DME connect handshake completed and the client takes part in relaying.</summary>
    public bool HasJoined { get; set; }

    /// <summary>Whether the client has been disconnected.</summary>
    public bool Disconnected { get; private set; }

    /// <summary>Receive-filter flags controlling which packet types are forwarded.</summary>
    public RT_RECV_FLAG RecvFlag { get; set; } =
        RT_RECV_FLAG.RECV_SINGLE | RT_RECV_FLAG.RECV_LIST;

    // ── Timing ────────────────────────────────────────────────────────────────

    public DateTime ReservedAt     { get; } = DateTime.UtcNow;
    public DateTime LastMessageAt  { get; set; } = DateTime.UtcNow;

    // ── Construction ──────────────────────────────────────────────────────────

    public DmeClientState(string sessionKey, string accessKey, int accountId, DmeWorld world, int dmeId)
    {
        SessionKey = sessionKey;
        AccessKey  = accessKey;
        AccountId  = accountId;
        World      = world;
        DmeId      = dmeId;
    }

    // ── Receive-flag helper ───────────────────────────────────────────────────

    /// <summary>
    /// Returns true if the client should receive packets matching
    /// <paramref name="flag"/>.  For old Medius (v ≤ 108) all flags are implicitly set.
    /// </summary>
    public bool HasRecvFlag(RT_RECV_FLAG flag)
        => MediusVersion <= 108 || RecvFlag.HasFlag(flag);

    // ── Outbound helpers ──────────────────────────────────────────────────────

    /// <summary>Send one RT frame to this client (fire-and-forget; send errors surface in the server log).</summary>
    public void Send(RT_MSG_TYPE type, byte[] payload)
    {
        if (Disconnected || Sender == null) return;
        _ = Sender(type, payload);
    }

    /// <summary>The client's 64-byte RSA public modulus (N_ps2, LE) from CLIENT_CRYPTKEY_PUBLIC; peers need it.</summary>
    public byte[] PublicKey { get; set; } = new byte[64];

    /// <summary>The client's IP address as peers should see it.</summary>
    public string IpAddress { get; set; } = "0.0.0.0";

    /// <summary>
    /// SERVER_CONNECT_NOTIFY (player joined), v108 layout from the SOCOM II DME client (handler 0x0063E848,
    /// which requires exactly 82 bytes): [playerIndex:2 LE][IP address: 16-byte NUL-padded string][public key:64].
    /// Any other length is a protocol error and the receiving console drops out of the game.
    /// </summary>
    public void SendConnectNotify(DmeClientState joined)
        => SendNotify(RT_MSG_TYPE.RT_MSG_SERVER_CONNECT_NOTIFY,
                BuildConnectNotify(joined.DmeId, joined.IpAddress, joined.PublicKey));

    /// <summary>SERVER_DISCONNECT_NOTIFY (player left), v108: [playerIndex:2 LE][IP address:16] — exactly 18 bytes.</summary>
    public void SendDisconnectNotify(DmeClientState left)
        => SendNotify(RT_MSG_TYPE.RT_MSG_SERVER_DISCONNECT_NOTIFY,
                BuildDisconnectNotify(left.DmeId, left.IpAddress));

    public static byte[] BuildConnectNotify(int playerIndex, string ip, byte[] publicKey)
    {
        var payload = new byte[2 + 16 + 64];
        WriteIndexAndIp(payload, playerIndex, ip);
        Buffer.BlockCopy(publicKey, 0, payload, 18, Math.Min(64, publicKey.Length));
        return payload;
    }

    public static byte[] BuildDisconnectNotify(int playerIndex, string ip)
    {
        var payload = new byte[2 + 16];
        WriteIndexAndIp(payload, playerIndex, ip);
        return payload;
    }

    private static void WriteIndexAndIp(byte[] payload, int playerIndex, string ip)
    {
        payload[0] = (byte)playerIndex;
        payload[1] = (byte)(playerIndex >> 8);
        var ipBytes = System.Text.Encoding.ASCII.GetBytes(ip);
        Buffer.BlockCopy(ipBytes, 0, payload, 2, Math.Min(15, ipBytes.Length));
    }

    /// <summary>Set from <c>MultiplayerConfig.DmePlayerNotifications</c> when the DME server starts.</summary>
    public static bool PlayerNotificationsEnabled { get; set; }

    private void SendNotify(RT_MSG_TYPE type, byte[] payload)
    {
        if (PlayerNotificationsEnabled) Send(type, payload);
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    public void MarkDisconnected()
    {
        Disconnected = true;
        Sender = null;
    }

    public override string ToString()
        => $"DmeClient(world={World.WorldId}, dmeId={DmeId}, acct={AccountId})";
}
