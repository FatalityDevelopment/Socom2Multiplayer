using CodeDesigner.Ps2.Multiplayer.Crypto;

namespace CodeDesigner.Ps2.Multiplayer.Models;

public enum PlayerStatus
{
    Disconnected     = 0,
    InAuthWorld      = 1,
    InChatWorld      = 2,
    InGameWorld      = 3,
    InOtherUniverse  = 4,
}

/// <summary>
/// Tracks a single connected client's session state across the SCERT handshake
/// and into the Medius Lobby or Game layer.
/// </summary>
public class MediusClientState
{
    // -------------------------------------------------------------------------
    // Connection identity
    // -------------------------------------------------------------------------

    /// <summary>Unique connection ID assigned when the TCP socket is accepted.</summary>
    public string ConnectionId   { get; set; } = Guid.NewGuid().ToString("N")[..16];

    /// <summary>Remote endpoint string for logging.</summary>
    public string RemoteEndpoint { get; set; } = string.Empty;

    // -------------------------------------------------------------------------
    // SCERT handshake state
    // -------------------------------------------------------------------------
    public bool HelloReceived        { get; set; }
    public bool CryptKeyReceived     { get; set; }
    public bool ConnectReceived      { get; set; }
    public bool ConnectReadyReceived { get; set; }
    public bool IsSessionEstablished { get; set; }

    /// <summary>Medius protocol version sent by the client in CLIENT_HELLO.</summary>
    public ushort MediusVersion { get; set; } = 108;

    /// <summary>AppId the client declared during CONNECT_TCP.</summary>
    public int AppId { get; set; }

    /// <summary>
    /// RC4 session key generated during handshake.
    /// 64 bytes. All-zero when encryption is disabled.
    /// </summary>
    public byte[] SessionRc4Key { get; set; } = new byte[64];

    /// <summary>Raw bytes the client sent in CLIENT_CRYPTKEY_PUBLIC.</summary>
    public byte[] ClientCryptKey { get; set; } = Array.Empty<byte>();

    /// <summary>RSA cipher constructed from the client's public key (for hash verification).</summary>
    public Ps2Rsa? ClientRsa { get; set; }

    /// <summary>SCERT client counter used in SERVER_CONNECT_ACCEPT_TCP.</summary>
    public uint ScertId { get; set; }

    // -------------------------------------------------------------------------
    // Medius session
    // -------------------------------------------------------------------------
    public string SessionKey   { get; set; } = string.Empty;
    /// <summary>Access key the client presented in its v108 CLIENT_CONNECT_TCP (DME: the slot token from JoinGame).</summary>
    public string AccessKey    { get; set; } = string.Empty;
    public int?   AccountId    { get; set; }
    public string AccountName  { get; set; } = string.Empty;
    public PlayerStatus Status { get; set; } = PlayerStatus.Disconnected;

    /// <summary>Set once the MLS lobby online-code SERVER_MEMORY_POKE stream has been replayed to this client.</summary>
    public bool LobbyPokesSent { get; set; }

    /// <summary>
    /// Set once the client has sent its own CLIENT_ECHO heartbeat. After this the server stops its
    /// proactive keepalive ping (the client now maintains the connection itself) and only mirrors the
    /// client's echoes — sending extra unsolicited pings appears to trip the game's echo watchdog and
    /// drop the lobby after a few minutes. The proactive ping is still needed BEFORE this (persona
    /// screen, where the client is silent while the user types).
    /// </summary>
    public bool ClientEchoSeen { get; set; }

    /// <summary>Last time the server sent a proactive CLIENT_ECHO ping (throttles the post-login gap-filler).</summary>
    public DateTime LastProactiveEchoAt { get; set; } = DateTime.MinValue;

    /// <summary>Incrementing SequenceId for the lobby anti-cheat SERVER_CHEAT_QUERY heartbeat.</summary>
    public int CheatSeq => Volatile.Read(ref _cheatSeq);
    private int _cheatSeq;

    /// <summary>Take the next CHEAT_QUERY sequence id. Atomic: the scanner, heartbeat and debug peeks share it.</summary>
    public int NextCheatSeq() => Interlocked.Increment(ref _cheatSeq) - 1;

    // Lobby memory scanner (cheat-scan.json) — where this client's scan is up to.
    public int  ScanVersion    { get; set; } = -1;
    public int  ScanRangeIndex { get; set; }
    public uint ScanCursor     { get; set; }

    /// <summary>
    /// True once this connection has received a community-screen init message (ChannelList). The game
    /// uses a SEPARATE MLS connection for the post-login community screen vs. the initial login batch;
    /// PlayerInfo (0x31) arrives on BOTH, but answering the LOGIN-batch one stops the game from advancing
    /// to the community reconnect (confirmed on hardware). The ~2-min watchdog (cbIsGameAlive) only rides
    /// on the community-connection PlayerInfo poll, so we answer PlayerInfo only after this flag is set.
    /// </summary>
    public bool CommunityReached { get; set; }

    // -------------------------------------------------------------------------
    // World placement
    // -------------------------------------------------------------------------
    public int? CurrentChannelId { get; set; }
    public int? CurrentGameId    { get; set; }
    public int? WorldId          { get; set; }

    // -------------------------------------------------------------------------
    // MUIS anti-cheat exchange state
    // -------------------------------------------------------------------------

    /// <summary>Round counter for the MUIS CHEAT_QUERY/MEMORY_POKE exchange (0=not started, 1-3=rounds, 4=done).</summary>
    public int    MuisCheatRound  { get; set; } = 0;
    /// <summary>MessageID from the PS2's GetUniverseInfo request; echoed back in the universe response.</summary>
    public byte[] MuisMsgId       { get; set; } = new byte[21];
    public uint   MuisInfoType    { get; set; } = 0xFFFFFFFF;
    public bool   MuisUseLobbyExt { get; set; } = true;

    // -------------------------------------------------------------------------
    // DME game server state
    // -------------------------------------------------------------------------

    /// <summary>ID of the DME world this client is participating in (set after DME auth).</summary>
    public int? DmeWorldId { get; set; }

    /// <summary>DME slot index within the world (set after DME auth).</summary>
    public int? DmeClientIndex { get; set; }

    /// <summary>True once the client has completed the DME authentication exchange.</summary>
    public bool IsDmeAuthenticated { get; set; }

    // -------------------------------------------------------------------------
    // Timing
    // -------------------------------------------------------------------------
    public DateTime ConnectedAt    { get; set; } = DateTime.UtcNow;
    public DateTime LastMessageAt  { get; set; } = DateTime.UtcNow;
    public TimeSpan Timeout        { get; set; } = TimeSpan.FromSeconds(60);

    public bool IsTimedOut => DateTime.UtcNow - LastMessageAt > Timeout;
    public bool IsLoggedIn => AccountId.HasValue;

    public void Touch() => LastMessageAt = DateTime.UtcNow;
}
