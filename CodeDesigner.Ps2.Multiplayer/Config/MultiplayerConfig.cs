using Microsoft.Extensions.Configuration;

namespace CodeDesigner.Ps2.Multiplayer.Config;

public class MultiplayerConfig
{
    /// <summary>
    /// Read the "Online" section (or the legacy "Medius" section when "Online" doesn't exist).
    /// The configuration binder appends to a list that already has items, so a configured AllowedAppIds of [10472]
    /// used to become [10683, 10684, 10472], and a configured BriefingRooms list was added after the retail rooms.
    /// Lists named in the configuration replace their defaults instead.
    /// </summary>
    public static MultiplayerConfig Load(IConfiguration configuration)
    {
        var section = configuration.GetSection("Online");
        if (!section.Exists() && configuration.GetSection("Medius").Exists())
            section = configuration.GetSection("Medius");

        var config = new MultiplayerConfig();
        section.Bind(config);
        config.AllowedAppIds = ListOr(section, nameof(AllowedAppIds), new MultiplayerConfig().AllowedAppIds);
        config.BriefingRooms = ListOr(section, nameof(BriefingRooms), BriefingRoomConfig.RetailDefaults());
        config.DefaultGames  = ListOr(section, nameof(DefaultGames),  DefaultGameConfig.RetailDefaults());
        config.Announcements = ListOr(section, nameof(Announcements), new List<string>());
        return config;
    }

    /// <summary>The configured list (empty when the key is set to "" or []), or the default when the key is absent.</summary>
    private static List<T> ListOr<T>(IConfigurationSection section, string key, List<T> defaults)
    {
        var child = section.GetSection(key);
        if (!child.Exists()) return defaults;
        return child.Get<List<T>>() ?? new List<T>();
    }

    // ── Network ──────────────────────────────────────────────────────────────

    /// <summary>IP address to bind to. 0.0.0.0 = all interfaces.</summary>
    public string BindAddress { get; set; } = "0.0.0.0";

    /// <summary>
    /// Announced server IP returned to clients (your LAN/WAN IP). "auto" resolves it at startup: from
    /// <see cref="PublicHostname"/> when set (e.g. an Azure Container Instances FQDN), otherwise by asking a
    /// public what's-my-IP service.
    /// </summary>
    public string ServerIp { get; set; } = "127.0.0.1";

    /// <summary>
    /// Public DNS name that resolves to this server's inbound IP. Used when <see cref="ServerIp"/> is "auto" —
    /// on Azure Container Instances the outbound IP can differ from the inbound one, so the IP handed to
    /// consoles must come from the group's own FQDN (e.g. "mylabel.eastus.azurecontainer.io").
    /// </summary>
    public string PublicHostname { get; set; } = "";

    // ── Medius ports ─────────────────────────────────────────────────────────

    /// <summary>MUIS (Universe Information) server TCP port. PS2 games connect here first.</summary>
    public int MuisPort { get; set; } = 10071;

    /// <summary>MAS (Authentication) server TCP port.</summary>
    public int MasPort { get; set; } = 10077;

    /// <summary>MLS (Lobby) server TCP port.</summary>
    public int MlsPort { get; set; } = 10075;

    /// <summary>DME (Demonware Multiplayer Engine) in-game relay TCP port.</summary>
    public int DmePort { get; set; } = 10070;

    /// <summary>
    /// Send SERVER_CONNECT_NOTIFY / SERVER_DISCONNECT_NOTIFY to the other players in a DME world. Off by default.
    /// The old 4-byte layout made the player already in the room quit (the DME client requires exactly 82 / 18
    /// bytes, handler 0x0063E848). The layout is now the v108 one ([index][ip:16][key:64]); proven on PCSX2 via the
    /// debug API, still to be confirmed on hardware before turning this on.
    /// </summary>
    public bool DmePlayerNotifications { get; set; }

    /// <summary>
    /// Localhost-only debug API (fake DME clients, raw RT frames) for testing lobby/player-count mods.
    /// 0 = disabled. Always binds 127.0.0.1, never <see cref="BindAddress"/>.
    /// </summary>
    public int DebugApiPort { get; set; }

    /// <summary>
    /// Shared secret every debug API request must send as its X-Debug-Token header. Empty = the header is still
    /// required (it blocks cross-site requests from a browser) but any value is accepted.
    /// </summary>
    public string DebugApiToken { get; set; } = "";

    // ── DNAS ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// DNAS HTTPS server port. PS2 contacts gate1.*.dnas.playstation.org:443.
    /// Requires elevated privileges on Linux (run as root or use iptables redirect).
    /// Set to 0 to disable the HTTPS listener.
    /// </summary>
    public int DnasHttpsPort { get; set; } = 443;

    /// <summary>
    /// Use someone else's DNAS server instead of the built-in one: an IP address or hostname. When set, the built-in
    /// DnaSDK gateway does not start and the DNS responder answers *.dnas.playstation.org with this server's address
    /// (a hostname is re-resolved every minute), while Medius names (*.pdonline.scea.com) still point at ServerIp.
    /// Empty = run DNAS here (default).
    /// </summary>
    public string ExternalDnasServer { get; set; } = "";

    /// <summary>True when DNAS is handled by <see cref="ExternalDnasServer"/> rather than this process.</summary>
    public bool UsesExternalDnas => !string.IsNullOrWhiteSpace(ExternalDnasServer);

    /// <summary>
    /// DNAS DNS responder port (normally 53). The DNS server intercepts
    /// *.dnas.playstation.org queries and returns ServerIp.
    /// Requires elevated privileges on Linux (run as root or redirect port 53).
    /// Set to 0 to disable the built-in DNS responder.
    /// </summary>
    public int DnsDnasPort { get; set; } = 53;

    /// <summary>
    /// Forward DNS queries this server doesn't answer itself (anything but the DNAS/Medius intercepts and
    /// <see cref="DnsMappings"/>) to a public resolver. Fine on a LAN; on a public IP it makes the server an
    /// open resolver that gets abused for DNS amplification, so internet deployments set this false and
    /// unknown names are REFUSED.
    /// </summary>
    public bool DnsForwardUnknown { get; set; } = false;

    /// <summary>
    /// DNAS region: picks the community TLS certificate (us-gw → cert-us, eu-gw → cert-eu, gai-gw → cert-jp) and is
    /// the packet region searched first for a title's ticket. Valid values: us-gw, eu-gw, gai-gw.
    /// </summary>
    public string DnasRegion { get; set; } = "us-gw";

    /// <summary>
    /// TLS certificate (PEM) for the DNAS HTTPS gateway. If empty, Certificates/dnas.crt is used when present,
    /// otherwise the region certificate Certificates/cert-us|cert-eu|cert-jp.pem (see <see cref="DnasRegion"/>).
    /// </summary>
    public string DnasCertPath { get; set; } = "";

    /// <summary>RSA private key (PEM) matching the certificate. If empty, Certificates/dnas.key or the region's -key.pem.</summary>
    public string DnasKeyPath { get; set; } = "";

    /// <summary>Issuer certificate (PEM) sent with the gateway certificate. Empty = Certificates/ca-cert.pem.</summary>
    public string DnasCaPath { get; set; } = "";

    /// <summary>
    /// DnaSDK ticket cache (Signatures/, Moduli/, Decoded/). Must be writable: each title's ticket is taken from its
    /// captured S1 packet once and cached here. Empty = &lt;DataDirectory&gt;/dnas/RSA.
    /// </summary>
    public string DnasRsaDirectory { get; set; } = "";

    /// <summary>
    /// Where DnaSDK writes its per-session DNAS packet captures and logs. Empty = &lt;DataDirectory&gt;/dnas/PacketLogs.
    /// </summary>
    public string DnasCaptureDirectory { get; set; } = "";

    /// <summary>
    /// Captured DNAS packets DnaSDK takes each title's original RSA ticket from: a local directory laid out as
    /// &lt;region&gt;/packets/&lt;lookup&gt;_&lt;operation&gt; (relative paths resolve next to the binary), or an HTTPS DNASrep
    /// mirror. Empty = Data (the packet files shipped with this server).
    /// </summary>
    public string DnasRepositoryUrl { get; set; } = "";

    // ── NAT ───────────────────────────────────────────────────────────────────

    /// <summary>NAT punchthrough helper UDP port.</summary>
    public int NatPort { get; set; } = 10069;

    // ── Game ─────────────────────────────────────────────────────────────────

    /// <summary>Maximum simultaneous connections per Medius/DME listener; further connections are closed on accept. 0 = no limit.</summary>
    public int MaxClients { get; set; } = 1000;

    /// <summary>
    /// AppIds allowed to connect (checked at CLIENT_CONNECT_TCP on every Medius/DME listener). SOCOM II NTSC-U
    /// reports 10472. Empty list (the default) = accept any AppId. A refused console is logged with its AppId.
    /// </summary>
    public List<int> AllowedAppIds { get; set; } = new();

    // ── Custom DNS mappings ───────────────────────────────────────────────────

    /// <summary>
    /// Custom hostname → IP overrides served by the built-in DNS server.
    /// The DNS server answers A-record queries for any hostname in this map
    /// with the mapped IP, in addition to the built-in DNAS intercept rules.
    /// Example:
    ///   "muis.example.com": "192.168.2.89"
    /// </summary>
    public Dictionary<string, string> DnsMappings { get; set; } = new();

    /// <summary>
    /// Folder for persistent server data (accounts, stats, friends/ignore lists, clans) — a JSON snapshot.
    /// Empty = "data" next to the server binary. Containers mount a volume here (e.g. /data).
    /// </summary>
    public string DataDirectory { get; set; } = "";

    /// <summary>When true, accounts are auto-created on first login (no separate registration).</summary>
    public bool AutoCreateAccounts { get; set; } = true;

    /// <summary>
    /// Seconds a new connection has to finish the SCERT handshake before it is closed. Stops idle sockets that
    /// never speak from holding a slot. 0 = no limit.
    /// </summary>
    public int ClientTimeoutSeconds { get; set; } = 60;

    /// <summary>
    /// Seconds an established connection may go without sending anything before it is closed. In-lobby and
    /// in-game clients heartbeat on their own, so this only reaps dead or abandoned sessions. 0 = no limit.
    /// </summary>
    public int IdleTimeoutSeconds { get; set; } = 900;

    /// <summary>
    /// Most simultaneous TCP connections one IP address may hold on each Medius/DME listener (a console uses up to
    /// two per listener). Consoles behind one NAT share an address, so keep headroom. 0 = no limit.
    /// </summary>
    public int MaxConnectionsPerIp { get; set; } = 32;

    // ── On-screen text / messages ────────────────────────────────────────────
    // Each of these maps to a DIFFERENT screen in the game's online flow. They are
    // independent so you can word them for their context. Max length is the game's
    // field size (~256 chars each); longer text is truncated. "\r\n" inserts a line
    // break. The MLS texts (EULA, ServerNews) support multi-line / scrolling panels.

    /// <summary>
    /// MUIS universe-selection screen: the universe NAME shown in the server list
    /// the player picks from before logging in. Keep it short (≤32 chars look best).
    /// </summary>
    public string UniverseName { get; set; } = "My PS2 Multiplayer Server";

    /// <summary>
    /// MUIS universe-selection screen: the short DESCRIPTION shown beside the
    /// universe name when the player highlights it in the server list.
    /// </summary>
    public string UniverseDescription { get; set; } = "A private PS2 online server. Pick this universe to play.";

    /// <summary>
    /// MUIS universe news (Lobby::UniverseNewsResponse, shown at universe select,
    /// BEFORE login). This is the pre-login news tied to the universe itself — NOT
    /// the in-lobby "SERVER NEWS" panel (that is <see cref="ServerNews"/>).
    /// </summary>
    public string UniverseNews { get; set; } = "Welcome! Select this universe and sign in to play online.";

    /// <summary>
    /// In-lobby usage policy / EULA text (MAS+MLS Policy → PolicyResponse). Shown as
    /// the agreement prompt as the player enters the community screen. Use it for
    /// house rules / terms players are accepting by playing here.
    /// </summary>
    public string EulaText { get; set; } =
        "Welcome to the server!\r\n\r\n" +
        "By playing here you agree to be respectful to other players, " +
        "avoid cheating or exploits, and have fun. " +
        "This is a community-run private server and is not affiliated with the original publisher.";

    /// <summary>
    /// In-lobby "SERVER NEWS" panel (MLS GetAnnouncements → GetAnnouncementsResponse),
    /// shown on the community/main online screen AFTER login. Use it for current
    /// announcements: events, maintenance windows, rule updates, Discord link, etc.
    /// Supports multiple lines (the panel scrolls).
    /// </summary>
    public string ServerNews { get; set; } =
        "Welcome to the server!\r\n\r\n" +
        "- Servers are up and running.\r\n" +
        "- Be respectful and have fun.\r\n" +
        "- Check back here for the latest news and events.";

    /// <summary>
    /// Extra in-lobby announcements, shown after <see cref="ServerNews"/> (each one is its own entry in the
    /// GetAnnouncements list, up to 1000 characters). Empty = ServerNews only.
    /// </summary>
    public List<string> Announcements { get; set; } = new();

    /// <summary>Application name returned in FindPlayer / FindWorldByName results.</summary>
    public string ApplicationName { get; set; } = "SOCOM II";

    /// <summary>
    /// Patch level announced in the universe entry (field 0x2B5 = "&lt;version&gt; &lt;url&gt;", split by the client
    /// with strtok(" \t")). A client whose built-in level differs (the r0001 disc) downloads
    /// <c>&lt;url&gt;APACHE00.ZDB</c> over HTTP and saves it to the memory card; a matching client logs straight in.
    /// </summary>
    public string UniversePatchVersion { get; set; } = "r0004";

    /// <summary>
    /// Folder URL the client appends "APACHE00.ZDB" to (must end in '/'; plain http — the client uses sceHTTP).
    /// Empty = this server's own patch HTTP server: http://&lt;ServerIp&gt;:&lt;PatchHttpPort&gt;/_socom2-prod/currentpatch/
    /// (retail was http://updates.pdonline.scea.com:80/_socom2-prod/currentpatch/).
    /// </summary>
    public string UniversePatchUrl { get; set; } = "";

    /// <summary>TCP port of the built-in patch HTTP server. 0 = disabled.</summary>
    public int PatchHttpPort { get; set; } = 80;

    /// <summary>
    /// The APACHE00.ZDB served to clients that need the update. Empty = &lt;DataDirectory&gt;/patch/APACHE00.ZDB.
    /// </summary>
    public string PatchFile { get; set; } = "";

    /// <summary>The URL actually announced to clients (see <see cref="UniversePatchUrl"/>).</summary>
    public string EffectivePatchUrl
    {
        get
        {
            // Only an http:// URL is usable by the client; anything else (e.g. a file path meant for PatchFile)
            // falls back to this server's own patch URL.
            var url = UniversePatchUrl.Trim().StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                ? UniversePatchUrl.Trim()
                : $"http://{ServerIp}:{PatchHttpPort}/_socom2-prod/currentpatch/";
            return url.EndsWith('/') ? url : url + "/";
        }
    }

    // ── Briefing rooms (online BRIEFING screen) ───────────────────────────────

    /// <summary>
    /// Online BRIEFING-screen rooms — the rooms a player must enter before they can create or join a
    /// game. Each is sent as one ChannelList_ExtraInfoResponse (0xED) entry in reply to the client's
    /// ChannelList_ExtraInfo0 (0xEC). Defaults are the retail rooms extracted from the servers-online
    /// memory dump (see <see cref="BriefingRoomConfig.RetailDefaults"/>).
    /// </summary>
    public List<BriefingRoomConfig> BriefingRooms { get; set; } = BriefingRoomConfig.RetailDefaults();

    /// <summary>
    /// Display order for <see cref="BriefingRooms"/>: "Manual" keeps the array order as written;
    /// "Alphabetical" sorts the room names A→Z before sending them.
    /// </summary>
    public string BriefingRoomSortOrder { get; set; } = "Manual";

    /// <summary>
    /// Wire layout of each 0xED entry. "Retail" = the 0x70-byte struct SOCOM II's RoomList callback
    /// (EE 0x003009B0) parses; "Legacy" = the 3b4ee8f 105-byte layout (connection-stable but renders no
    /// rooms — its EndOfList never lands on 0x6C). Keep "Legacy" as the one-line rollback.
    /// </summary>
    public string BriefingRoomListFormat { get; set; } = "Retail";

    /// <summary>
    /// Default rooms (permanent server-hosted games) listed inside every briefing room, as retail did.
    /// Defaults are the 27 extracted from the retail dump (see <see cref="DefaultGameConfig.RetailDefaults"/>).
    /// Empty list = briefing rooms show no games until a player creates one.
    /// </summary>
    public List<DefaultGameConfig> DefaultGames { get; set; } = DefaultGameConfig.RetailDefaults();

    /// <summary>
    /// Answer the community (login) connection's batch like retail did: VersionServer (79 B), SetGameListFilter0
    /// (30 B) and PlayerInfo (330-byte retail layout) — all hash/size-verified against create_Masquarr, where
    /// the retail server answered them on the community connection too. Off = the older hardware-stable
    /// behaviour (those three stay silent there). Targets the intermittent news-screen disconnect; flip back
    /// to false if login regresses.
    /// </summary>
    public bool CommunityRetailReplies { get; set; } = false;

    /// <summary>
    /// Apply the filters a console sets with SetGameListFilter0 when building its game list. Off by default: the
    /// filters are recorded and logged, but every game in the room is listed (the long-standing behaviour). Turn it
    /// on once the logged filters look right for your game — a wrong match would hide games.
    /// </summary>
    public bool ApplyGameListFilters { get; set; } = false;

    // ── Binary injection ──────────────────────────────────────────────────────

    /// <summary>
    /// Custom binaries to push into the console over RT_MSG_SERVER_MEMORY_POKE once a
    /// player reaches the lobby (MLS). Each entry loads a .bin at its LoadAddress and,
    /// if HookAddress is set, writes a MIPS jump there so the injected code runs.
    /// Empty = nothing is injected (stock behaviour). This is the same channel SOCOM II
    /// servers use to push their online code module; here it carries YOUR binaries.
    /// </summary>
    public List<BinaryInjection> Injections { get; set; } = new();

    /// <summary>
    /// Folder watched for on-demand injection manifests (*.json with the same shape as
    /// a <see cref="BinaryInjection"/> entry). Drop a manifest here and it is sent to the
    /// connected console(s) immediately, then the manifest is consumed. Empty = disabled.
    /// </summary>
    public string InjectDropFolder { get; set; } = "";

    /// <summary>
    /// Path to a captured SERVER_MEMORY_POKE stream to replay verbatim once a player completes the
    /// MLS lobby exchange — i.e. SOCOM II's online-code download. Format: a sequence of
    /// [len:4 LE][pokePayload] records where each pokePayload is a complete [destAddr:4][size:4][data]
    /// block (as produced by dump_pokes.py from the retail universe-community-screen capture).
    /// The retail game ships WITHOUT online code; without this stream the client finishes the lobby
    /// handshake then times out ("Disconnected from Network"). Empty = disabled.
    /// </summary>
    public string LobbyPokeStreamFile { get; set; } = "";

    // ── Early (MUIS) peek/poke experiment ─────────────────────────────────────

    /// <summary>
    /// Send the configured <see cref="Injections"/> on the MUIS connection — the first SCERT server the PS2
    /// talks to — instead of waiting for the MLS lobby. They go out inside the MUIS anti-cheat exchange
    /// (after the round-1 CHEAT_QUERY reply, before the retail round-2 MEMORY_POKE), the earliest point
    /// hardware is known to accept 0x1D/0x1E traffic. Poked bytes stay in EE RAM across the MAS/MLS
    /// reconnects. Experimental: false = stock (lobby-only) behaviour.
    /// </summary>
    public bool MuisEarlyInject { get; set; } = false;

    /// <summary>
    /// Optional test peek on MUIS: EE address (hex, e.g. "0x00100000") to read with a RAW_MEMORY
    /// CHEAT_QUERY at the same early point. The reply is logged as hex. Empty = no peek.
    /// </summary>
    public string MuisEarlyPeekAddress { get; set; } = "";

    /// <summary>Bytes to read for <see cref="MuisEarlyPeekAddress"/> (clamped 4..1024).</summary>
    public int MuisEarlyPeekLength { get; set; } = 64;
}

/// <summary>
/// One binary to inject into the PS2 over SERVER_MEMORY_POKE. Addresses are EE virtual
/// addresses written as hex strings (e.g. "0x000A0000").
/// </summary>
public class BinaryInjection
{
    /// <summary>Disable without deleting the entry.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Optional label for logs.</summary>
    public string Name { get; set; } = "";

    /// <summary>Path to the .bin (absolute, or relative to the app base dir / Data/).</summary>
    public string File { get; set; } = "";

    /// <summary>EE address the blob is written to, hex (e.g. "0x000A0000").</summary>
    public string LoadAddress { get; set; } = "";

    /// <summary>Optional EE address to write a "J entry" hook at, hex. Null/empty = load only.</summary>
    public string? HookAddress { get; set; }

    /// <summary>Entry point the hook jumps to, hex. Null/empty = LoadAddress.</summary>
    public string? EntryPoint { get; set; }

    /// <summary>Bytes per SERVER_MEMORY_POKE write (retail SOCOM II uses 512).</summary>
    public int ChunkSize { get; set; } = 512;
}
