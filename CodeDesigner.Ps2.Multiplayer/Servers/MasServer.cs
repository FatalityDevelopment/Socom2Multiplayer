using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using CodeDesigner.Ps2.Multiplayer.Config;
using CodeDesigner.Ps2.Multiplayer.Crypto;
using CodeDesigner.Ps2.Multiplayer.Models;
using CodeDesigner.Ps2.Multiplayer.Protocol;
using CodeDesigner.Ps2.Multiplayer.Storage;
using Microsoft.Extensions.Logging;

namespace CodeDesigner.Ps2.Multiplayer.Servers;

/// <summary>
/// MAS — Medius Authentication Server.
/// Clients connect here first to obtain a session key and authenticate or
/// register an account.  After a successful login the server returns an MLS
/// IP/port for the client to connect to next.
///
/// Default port: 10071 (TCP)
/// </summary>
public class MasServer : BaseMediusTcpServer
{
    private readonly MultiplayerConfig  _config;
    private readonly InMemoryStorage _store;
    private readonly AdminSettings _admin;
    private readonly ILogger<MasServer> _log;

    public MasServer(MultiplayerConfig config, InMemoryStorage store, AdminSettings admin, ILogger<MasServer> log)
        : base(log, config)
    {
        _admin     = admin;
        _config    = config;
        _store     = store;
        _log       = log;
        ServerName = "MAS";
        admin.BansChanged += bans => KickBanned(bans, _store);
    }

    public Task StartAsync(CancellationToken ct) =>
        StartAsync(_config.BindAddress, _config.MasPort, ct);

    // -------------------------------------------------------------------------
    // Medius message dispatch
    // -------------------------------------------------------------------------

    protected override async Task HandleMediusMessageAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        if (packet.MessageClass == NetMessageClass.MessageClassLobby)
        {
            var typeId = (MediusLobbyMessageId)packet.MessageType;
            _log.LogDebug("[MAS] Lobby msg: {Type}", typeId);

            switch (typeId)
            {
                case MediusLobbyMessageId.SessionBegin:
                    await HandleSessionBeginAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.AccountLogin:
                    await HandleAccountLoginAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.AnonymousLogin:
                    await HandleAnonymousLoginAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.AccountRegistration:
                    await HandleAccountRegistrationAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.AccountLogout:
                    await HandleAccountLogoutAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.TicketLogin:
                    await HandleTicketLoginAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.GetMyIP:
                    await HandleGetMyIpAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.Policy:
                    await HandlePolicyAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.VersionServer:
                    await HandleVersionServerAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.GetWorldSecurityLevel:
                    await HandleGetWorldSecurityLevelAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyMessageId.SetLocalizationParams:
                    await HandleSetLocalizationParamsAsync(packet, state, tcp, ct);
                    break;

                default:
                    _log.LogInformation("[MAS] Unhandled lobby msg 0x{Type:X2} ({Len} bytes)",
                        packet.MessageType, packet.Payload.Length);
                    break;
            }
        }
        else if (packet.MessageClass == NetMessageClass.MessageClassLobbyExt)
        {
            var typeId = (MediusLobbyExtMessageId)packet.MessageType;
            _log.LogDebug("[MAS] LobbyExt msg: {Type}", typeId);

            switch (typeId)
            {
                case MediusLobbyExtMessageId.ExtendedSessionBeginRequest:
                    await HandleExtendedSessionBeginAsync(packet, state, tcp, ct);
                    break;

                case MediusLobbyExtMessageId.DnasSignaturePost:
                    // DNAS ticket accepted unconditionally — no real DNAS validation
                    _log.LogInformation("[MAS] DnasSignaturePost received — accepted");
                    break;

                default:
                    _log.LogInformation("[MAS] Unhandled lobbyExt msg 0x{Type:X2} ({Len} bytes)",
                        packet.MessageType, packet.Payload.Length);
                    break;
            }
        }
        else
        {
            _log.LogInformation("[MAS] Unknown msg class=0x{Class:X2} type=0x{Type:X2} ({Len} bytes)",
                (byte)packet.MessageClass, packet.MessageType, packet.Payload.Length);
        }
    }

    // =========================================================================
    // Session
    // =========================================================================

    private async Task HandleSessionBeginAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        // Old Medius payload: [messageId: 21][sessionType: 4][sessionFlags: 4][appId: 4][...]
        // Echo messageId back in response (required by old Medius protocol).
        byte[] msgId = packet.Payload.Length >= MediusConstants.MESSAGEID_MAXLEN
            ? packet.Payload[..MediusConstants.MESSAGEID_MAXLEN]
            : new byte[MediusConstants.MESSAGEID_MAXLEN];

        state.SessionKey = GenerateSessionKey();
        state.Status     = PlayerStatus.InAuthWorld;

        _log.LogInformation("[MAS] SessionBegin msgId={MsgId}", Convert.ToHexString(msgId));

        // SessionBeginResponse — wire format ported from horizon-server-public-extended
        // MediusSessionBeginResponse.Serialize():
        //   [messageId : 21 bytes]
        //   [padding   : 3 bytes]   ← was missing
        //   [status    : 4 bytes int]
        //   [sessionKey: 17 bytes]
        //   [padding   : 1 byte for AppId∈{10694,21064}, else 3 bytes]
        //   = 48 bytes for SOCOM II (AppId 10472 — uses the 3-byte trailing pad)
        //
        // The leading 3-byte pad was missing in the previous implementation;
        // its absence shifted every later field by 3 bytes which means the
        // client read its session key from the wrong position and may have
        // parsed status as garbage. Hard to say which mattered most to the
        // client, but the wire size now matches horizon (107 bytes vs the
        // old 101 the user captured).
        bool isShortPaddingApp = state.AppId == 10694 || state.AppId == 21064;
        var w = new MediusWriter();
        w.Write(msgId);                                                       // 21
        w.WritePadding(3);                                                    // 3
        w.Write((int)MediusCallbackStatus.MediusSuccess);                     // 4
        w.WriteString(state.SessionKey, MediusConstants.SESSIONKEY_MAXLEN);   // 17
        w.WritePadding(isShortPaddingApp ? 1 : 3);                            // 1 or 3

        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.SessionBeginResponse, w.ToArray()), ct);
    }

    private async Task HandleExtendedSessionBeginAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        byte[] msgId = packet.Payload.Length >= MediusConstants.MESSAGEID_MAXLEN
            ? packet.Payload[..MediusConstants.MESSAGEID_MAXLEN]
            : new byte[MediusConstants.MESSAGEID_MAXLEN];

        state.SessionKey = GenerateSessionKey();
        state.Status     = PlayerStatus.InAuthWorld;

        _log.LogInformation("[MAS] ExtendedSessionBegin");

        var w = new MediusWriter();
        w.Write(msgId);                                                       // messageId echo (21 bytes)
        w.Write((int)MediusCallbackStatus.MediusSuccess);
        w.WriteString(state.SessionKey, MediusConstants.SESSIONKEY_MAXLEN);  // SessionKey (17 bytes)

        // ExtendedSessionBeginResponse reuses SessionBeginResponse message ID
        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.SessionBeginResponse, w.ToArray()), ct);
    }

    // =========================================================================
    // Authentication
    // =========================================================================

    private async Task HandleAccountLoginAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var r = new MediusReader(packet.Payload);
        // Old Medius layout: [messageId: 21][sessionKey: 17][username: 32][password: 32]
        byte[] msgId      = r.ReadBytes(MediusConstants.MESSAGEID_MAXLEN);
        string sessionKey = r.ReadString(MediusConstants.SESSIONKEY_MAXLEN);
        string username   = r.ReadString(MediusConstants.ACCOUNTNAME_MAXLEN);
        string password   = r.ReadString(MediusConstants.PASSWORD_MAXLEN);

        _log.LogInformation("[MAS] AccountLogin: user={User}", username);

        MediusCallbackStatus status;
        if (!IsValidAccountName(username))
        {
            await SendLoginFailure(tcp, MediusCallbackStatus.MediusAccountNotFound, msgId, ct);
            return;
        }
        if (BanFor(username, tcp) is string banReason)
        {
            _log.LogWarning("[MAS] Login refused — '{User}' is banned ({Reason})", username, banReason);
            await SendLoginFailure(tcp, MediusCallbackStatus.MediusAccountBanned, msgId, ct);
            return;
        }

        MediusAccount? account = _store.GetAccountByName(username);
        bool created = false;
        if (account == null)
        {
            if (!_config.AutoCreateAccounts)
            {
                status = MediusCallbackStatus.MediusAccountNotFound;
                await SendLoginFailure(tcp, status, msgId, ct);
                return;
            }
            account = _store.GetOrCreateAccount(username, PasswordHasher.Hash(password), out created);
            if (created)
                _log.LogInformation("[MAS] Auto-created account '{User}' id={Id}", username, account.AccountId);
        }

        if (!created)
        {
            if (!PasswordHasher.Verify(password, account.PasswordHash, out bool upgrade))
            {
                _log.LogInformation("[MAS] AccountLogin: wrong password for '{User}'", username);
                await SendLoginFailure(tcp, MediusCallbackStatus.MediusLoginFailed, msgId, ct);
                return;
            }
            if (upgrade) account.PasswordHash = PasswordHasher.Hash(password);
        }

        if (account.IsBanned)
        {
            _log.LogWarning("[MAS] Login refused — '{User}' is banned (account flag)", username);
            await SendLoginFailure(tcp, MediusCallbackStatus.MediusAccountBanned, msgId, ct);
            return;
        }

        state.AccountId   = account.AccountId;
        state.AccountName = account.AccountName;
        state.Status      = PlayerStatus.InAuthWorld;
        status            = MediusCallbackStatus.MediusSuccess;

        // The lobby (MLS) connections present this session key back — map it to the account there.
        _store.RegisterSession(state.SessionKey, account.AccountId, replaceOthers: true);
        account.LastLoginAt = DateTime.UtcNow;
        _store.MarkDirty();

        // AccountLoginResponse — wire format ported from horizon-server
        // RT.Models.Lobby.MediusAccountLoginResponse + RT.Models.Misc.NetConnectionInfo:
        //
        //   [messageId:21][padding:3][status:4][accountId:4][accountType:4][worldId:4]
        //   [ConnInfo.Type:4]
        //   [ConnInfo.MLS NetAddress: type(4)+ip(16)+port(uint:4)=24]
        //   [ConnInfo.NAT NetAddress: type(4)+ip(16)+port(uint:4)=24]
        //   [ConnInfo.WorldID:4]
        //   [ConnInfo.ServerKey:64]
        //   [ConnInfo.SessionKey:17]
        //   [ConnInfo.AccessKey:17]
        //   = 21+3+4+4+4+4+154 = 194 bytes total (v ≤ 108)
        //
        // Crucially the **port is uint (4 bytes)**, not ushort — the old
        // 20-byte MlsAddr block we wrote here was misaligned and the client
        // ended up reading random bytes as the MLS port (e.g. 10077 vs 10075),
        // which is why SOCOM II connected to a phantom port and disconnected.
        //
        // ServerKey MUST be the real server RSA public modulus (matches horizon's
        // Login(): ConnectInfo.ServerKey = Program.GlobalAuthPublic for account
        // login). After auth, SOCOM II uses this key to RSA-encrypt CRYPTKEY_PUBLIC
        // for the follow-on lobby connection — a zero key leaves it unable to bring
        // up that connection and it drops with "Disconnected from Network" right
        // after AccountLoginResponse. All our servers share Ps2Rsa.ServerKey, and
        // the MAS handshake already proved the client expects this modulus.
        const int defaultWorldId = 1;
        var w = new MediusWriter();
        w.Write(msgId);                                                                    // 21
        w.WritePadding(3);                                                                  // 3
        w.Write((int)status);                                                               // 4
        w.Write(account.AccountId);                                                         // 4
        w.Write((int)MediusAccountType.MediusMasterAccount);                                // 4
        w.Write(defaultWorldId);                                                            // 4
        // Lobby address points back at the MAS port, NOT a separate MlsPort.
        // 2012 retail captures (create_Masquarr.pcap) show SOCOM II doing auth AND
        // lobby on a single connection — it never opens a second port. Handing it a
        // different lobby endpoint (10075) made it tear down the MAS connection to
        // chase that port and then give up ("Disconnected from Network"). Pointing
        // lobby at the current endpoint keeps the client on the MAS connection, where
        // it proceeds to send ChannelList/GetAnnouncements etc.
        w.WriteNetConnectionInfo(                                                           // 154
            NetConnectionType.ClientServerTCP,
            mls: (NetAddressType.External,   _config.ServerIp, _config.MlsPort),
            nat: (NetAddressType.NATService, _config.ServerIp, _config.NatPort),
            worldId: defaultWorldId,
            serverKey: Ps2Rsa.ServerKey.GetPublicKey(),
            sessionKey: state.SessionKey,
            accessKey: state.SessionKey);

        // Encrypt the login response (RcServerSession). Horizon serializes Medius messages
        // with SkipEncryption=false by default and every retail SERVER_APP in the 2012
        // captures is [ENC]. SOCOM II tolerates plaintext for the early handshake responses
        // (SessionBegin/Version), but its login-completion path appears to require the
        // AccountLoginResponse encrypted — a plaintext one is parsed but then rejected,
        // and the client drops without transitioning to the lobby.
        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.AccountLoginResponse, w.ToArray()), state, ct);
    }

    private async Task HandleAnonymousLoginAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var r = new MediusReader(packet.Payload);
        // Old Medius layout: [messageId: 21][sessionKey: 17]
        byte[] msgId = r.ReadBytes(MediusConstants.MESSAGEID_MAXLEN);

        _log.LogInformation("[MAS] AnonymousLogin");

        if (BanFor(null, tcp) is string banReason)
        {
            _log.LogWarning("[MAS] AnonymousLogin refused — address is banned ({Reason})", banReason);
            await SendLoginFailure(tcp, MediusCallbackStatus.MediusAccountBanned, msgId, ct, MediusLobbyMessageId.AnonymousLoginResponse);
            return;
        }

        // No account: leave AccountId unset so nothing treats this connection as a real player.
        state.AccountId   = null;
        state.AccountName = "Anonymous";
        state.Status      = PlayerStatus.InAuthWorld;

        // AnonymousLoginResponse — same layout as AccountLoginResponse
        // (see comment in HandleAccountLoginAsync for the full wire-format
        // breakdown). AccountId = -1 matches horizon's anonymous convention.
        const int defaultWorldId = 1;
        var w = new MediusWriter();
        w.Write(msgId);                                                                    // 21
        w.WritePadding(3);                                                                  // 3
        w.Write((int)MediusCallbackStatus.MediusSuccess);                                   // 4
        w.Write(-1);                                                                        // 4  AccountId
        w.Write((int)MediusAccountType.MediusMasterAccount);                                // 4
        w.Write(defaultWorldId);                                                            // 4
        w.WriteNetConnectionInfo(                                                           // 154
            NetConnectionType.ClientServerTCP,
            mls: (NetAddressType.External,   _config.ServerIp, _config.MlsPort),  // separate MLS endpoint
            nat: (NetAddressType.NATService, _config.ServerIp, _config.NatPort),
            worldId: defaultWorldId,
            serverKey: Ps2Rsa.ServerKey.GetPublicKey(),  // real RSA modulus — see HandleAccountLoginAsync
            sessionKey: state.SessionKey,
            accessKey: state.SessionKey);

        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.AnonymousLoginResponse, w.ToArray()), state, ct);  // encrypted — see HandleAccountLoginAsync
    }

    private async Task HandleAccountRegistrationAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var r = new MediusReader(packet.Payload);
        // Old Medius layout: [messageId: 21][sessionKey: 17][username: 32][password: 32]
        byte[] msgId      = r.ReadBytes(MediusConstants.MESSAGEID_MAXLEN);
        string sessionKey = r.ReadString(MediusConstants.SESSIONKEY_MAXLEN);
        string username   = r.ReadString(MediusConstants.ACCOUNTNAME_MAXLEN);
        string password   = r.ReadString(MediusConstants.PASSWORD_MAXLEN);

        _log.LogInformation("[MAS] AccountRegistration: user={User}", username);

        // AccountRegistrationResponse — wire layout ported from horizon-server
        // RT.Models.Lobby.MediusAccountRegistrationResponse.Serialize():
        //   [messageId:21][padding:3][status:4][accountId:4] = 32 bytes total
        //
        // The 3-byte padding after msgId is critical — same shift bug we
        // fixed in SessionBeginResponse and the login responses. Without it
        // the client reads StatusCode from where we wrote padding (= 0 = a
        // success-like value), then AccountID from where StatusCode would
        // be, then garbage, and bounces back to login mid-handshake.

        var regStatus = !IsValidAccountName(username) ? MediusCallbackStatus.MediusRegistrationFailed
                      : string.IsNullOrEmpty(password)  ? MediusCallbackStatus.MediusInvalidPassword
                      : BanFor(username, tcp) != null   ? MediusCallbackStatus.MediusAccountBanned
                      : MediusCallbackStatus.MediusSuccess;
        var account = regStatus == MediusCallbackStatus.MediusSuccess
            ? _store.TryCreateAccount(username, PasswordHasher.Hash(password))
            : null;
        if (account == null && regStatus == MediusCallbackStatus.MediusSuccess)
            regStatus = MediusCallbackStatus.MediusAccountAlreadyExists;

        if (account == null)
        {
            // Use MediusAccountAlreadyExists (-999), not MediusAccountLoggedIn (-997).
            // The latter means "the account is currently in a session" — which is
            // misleading when the real reason is "the name is already taken".
            var wFail = new MediusWriter();
            wFail.Write(msgId);                                                  // 21
            wFail.WritePadding(3);                                                // 3
            wFail.Write((int)regStatus);                                          // 4
            wFail.Write(0);                                                       // 4 — AccountID placeholder
            await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.AccountRegistrationResponse, wFail.ToArray()), ct);
            return;
        }

        _log.LogInformation("[MAS] Registered account '{User}' id={Id}", username, account.AccountId);

        var w = new MediusWriter();
        w.Write(msgId);                                                          // 21
        w.WritePadding(3);                                                       // 3
        w.Write((int)MediusCallbackStatus.MediusSuccess);                        // 4
        w.Write(account.AccountId);                                              // 4

        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.AccountRegistrationResponse, w.ToArray()), ct);
    }

    private async Task HandleAccountLogoutAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        byte[] msgId = packet.Payload.Length >= MediusConstants.MESSAGEID_MAXLEN
            ? packet.Payload[..MediusConstants.MESSAGEID_MAXLEN]
            : new byte[MediusConstants.MESSAGEID_MAXLEN];

        _log.LogInformation("[MAS] AccountLogout: {User}", state.AccountName);
        _store.RevokeSession(state.SessionKey);
        state.AccountId   = null;
        state.AccountName = string.Empty;
        state.Status      = PlayerStatus.Disconnected;

        // AccountLogoutResponse — horizon layout: [msgId:21][pad:3][status:4] = 28 bytes
        var w = new MediusWriter();
        w.Write(msgId);                                     // 21
        w.WritePadding(3);                                  // 3
        w.Write((int)MediusCallbackStatus.MediusSuccess);   // 4

        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.AccountLogoutResponse, w.ToArray()), ct);
    }

    private async Task HandleTicketLoginAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        // Old Medius TicketLogin payload: [messageId:21][sessionKey:17][username:32][ticketBlob:rest]
        // We accept any ticket — no real DNAS/ticket validation.
        var r = new MediusReader(packet.Payload);
        byte[] msgId      = r.ReadBytes(MediusConstants.MESSAGEID_MAXLEN);
        string sessionKey = r.Remaining >= MediusConstants.SESSIONKEY_MAXLEN  ? r.ReadString(MediusConstants.SESSIONKEY_MAXLEN)  : string.Empty;
        string username   = r.Remaining >= MediusConstants.ACCOUNTNAME_MAXLEN ? r.ReadString(MediusConstants.ACCOUNTNAME_MAXLEN) : "Player";
        // remaining bytes = ticket blob (ignored)

        _log.LogInformation("[MAS] TicketLogin: user={User}", username);

        if (!IsValidAccountName(username))
        {
            await SendLoginFailure(tcp, MediusCallbackStatus.MediusAccountNotFound, msgId, ct, MediusLobbyMessageId.TicketLoginResponse);
            return;
        }
        if (BanFor(username, tcp) is string banReason)
        {
            _log.LogWarning("[MAS] TicketLogin refused — '{User}' is banned ({Reason})", username, banReason);
            await SendLoginFailure(tcp, MediusCallbackStatus.MediusAccountBanned, msgId, ct, MediusLobbyMessageId.TicketLoginResponse);
            return;
        }

        // The ticket itself isn't validated, so it can't prove who the player is. It may claim a new name (the
        // account is created without a password) or a password-less account, but an account protected by a
        // password only accepts a session that already logged in to it with that password.
        var account = _store.GetOrCreateAccount(username, string.Empty, out bool created);
        if (created)
            _log.LogInformation("[MAS] Auto-created account for ticket login: '{User}' id={Id}", username, account.AccountId);
        else if (!string.IsNullOrEmpty(account.PasswordHash) && !_store.IsSessionOf(sessionKey, account.AccountId))
        {
            _log.LogWarning("[MAS] TicketLogin refused — '{User}' has a password; use AccountLogin", username);
            await SendLoginFailure(tcp, MediusCallbackStatus.MediusInvalidPassword, msgId, ct, MediusLobbyMessageId.TicketLoginResponse);
            return;
        }
        if (account.IsBanned)
        {
            await SendLoginFailure(tcp, MediusCallbackStatus.MediusAccountBanned, msgId, ct, MediusLobbyMessageId.TicketLoginResponse);
            return;
        }

        state.AccountId   = account.AccountId;
        state.AccountName = account.AccountName;
        state.Status      = PlayerStatus.InAuthWorld;
        _store.RegisterSession(state.SessionKey, account.AccountId, replaceOthers: true);

        // TicketLoginResponse — wire format ported from horizon-server
        // RT.Models.Lobby.MediusTicketLoginResponse. Same NetConnectionInfo
        // shape as AccountLogin/AnonymousLogin (see HandleAccountLoginAsync
        // for the full byte-by-byte breakdown). The ticket flavour populates
        // ConnInfo.AccessKey with the token, not the session key, so the
        // client can present it to MLS.
        const int defaultWorldId = 1;
        var w = new MediusWriter();
        w.Write(msgId);                                                                    // 21
        w.WritePadding(3);                                                                  // 3
        w.Write((int)MediusCallbackStatus.MediusSuccess);                                   // 4
        w.Write(account.AccountId);                                                         // 4
        w.Write((int)MediusAccountType.MediusMasterAccount);                                // 4
        w.Write(defaultWorldId);                                                            // 4
        w.WriteNetConnectionInfo(                                                           // 154
            NetConnectionType.ClientServerTCP,
            mls: (NetAddressType.External,   _config.ServerIp, _config.MlsPort),
            nat: (NetAddressType.NATService, _config.ServerIp, _config.NatPort),
            worldId: defaultWorldId,
            serverKey: null,
            sessionKey: state.SessionKey,
            accessKey: state.SessionKey);   // reuse session key as token placeholder

        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.TicketLoginResponse, w.ToArray()), ct);
    }

    private async Task HandleGetMyIpAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        byte[] msgId = packet.Payload.Length >= MediusConstants.MESSAGEID_MAXLEN
            ? packet.Payload[..MediusConstants.MESSAGEID_MAXLEN]
            : new byte[MediusConstants.MESSAGEID_MAXLEN];

        var endpoint = state.RemoteEndpoint;
        // Strip port if present
        var ip = endpoint.Contains(':') ? endpoint[..endpoint.LastIndexOf(':')] : endpoint;

        // GetMyIPResponse — horizon layout: [msgId:21][pad:3][status:4][ip:20]
        // IP field is 20 bytes (IP_MAXLEN) — matches MediusConstants.IP_MAXLEN.
        var w = new MediusWriter();
        w.Write(msgId);                                     // 21
        w.WritePadding(3);                                  // 3
        w.Write((int)MediusCallbackStatus.MediusSuccess);   // 4
        w.WriteString(ip, MediusConstants.IP_MAXLEN);       // 20

        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.GetMyIPResponse, w.ToArray()), ct);
    }

    private async Task HandleVersionServerAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        // Old-Medius request payload: [messageId:21][sessionKey:17]. Echo the
        // messageId back in the response — the client correlates request →
        // response by it and disconnects if it doesn't see its own bytes.
        byte[] msgId = packet.Payload.Length >= MediusConstants.MESSAGEID_MAXLEN
            ? packet.Payload[..MediusConstants.MESSAGEID_MAXLEN]
            : new byte[MediusConstants.MESSAGEID_MAXLEN];

        // VersionServer (0x86) is the client asking what version we are; the
        // expected response is VersionServerResponse (0x87). Wire format
        // ported from horizon-server-public-extended's
        // MediusVersionServerResponse.Serialize:
        //
        //   [messageId : 21 bytes (MESSAGEID_MAXLEN)]
        //   [version   : 56 bytes (VERSIONSERVER_MAXLEN), NUL-padded ASCII]
        //   = 77 bytes total
        //
        // CRITICAL: no padding, no status code on the wire — the StatusCode
        // field exists on the class but is not serialized. An earlier
        // attempt added 3 padding bytes + a 4-byte status field, which made
        // SOCOM II read garbage where it expected the version string and
        // drop the connection right after.
        _log.LogInformation("[MAS] VersionServer -> VersionServerResponse");

        const int VERSIONSERVER_MAXLEN = 56;
        var w = new MediusWriter();
        w.Write(msgId);                                       // 21 bytes
        w.WriteString("CodeDesigner Medius 1.0.0", VERSIONSERVER_MAXLEN); // 56 bytes

        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.VersionServerResponse, w.ToArray()), ct);

        // DELIBERATELY NOT pushing PolicyResponse here.
        //
        // History: an earlier version pushed an UNSOLICITED PolicyResponse
        // right after VersionServerResponse. With both the malformed (77-byte)
        // AND the horizon-correct (288-byte) layouts the client always sent
        // RT_MSG_CLIENT_DISCONNECT seconds later — empirically SOCOM II
        // expects to *request* Policy explicitly (case MediusLobbyMessageId.Policy
        // in the dispatcher above), not have it pushed. Pushing it leaves the
        // login UI in a stuck state where pressing Connect just replays the
        // same broken Session+Version sequence instead of submitting auth.
        //
        // If the client wants Policy, HandlePolicyAsync handles the request.
        // Keep MAS quiet here and let the periodic SERVER_ECHO keepalive
        // (see BaseMediusTcpServer.RunKeepAliveLoopAsync) hold the session
        // open while the user types credentials.
    }

    private async Task HandleSetLocalizationParamsAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        // Request layout (SOCOM II, 48-byte payload): [messageId:21][sessionKey:17][params:10]
        // where params = language/encoding/timezone ints. We don't persist them — the client
        // only needs the ack to advance its login state machine.
        byte[] msgId = packet.Payload.Length >= MediusConstants.MESSAGEID_MAXLEN
            ? packet.Payload[..MediusConstants.MESSAGEID_MAXLEN]
            : new byte[MediusConstants.MESSAGEID_MAXLEN];

        _log.LogInformation("[MAS] SetLocalizationParams -> SetLocalizationParamsResponse");

        // The 2012 create_Masquarr capture shows the retail MAS server answering
        // SetLocalizationParams with a 30-byte SERVER_APP (= 2-byte header + 28-byte body):
        //   [messageId:21][padding:3][status:4]
        // SOCOM II sends SetLocalizationParams bundled with DnasSignaturePost + AccountLogin
        // at "Connect", and will not complete login until it sees this ack — leaving it
        // unhandled produced an immediate disconnect right after AccountLoginResponse.
        var w = new MediusWriter();
        w.Write(msgId);                                     // 21
        w.WritePadding(3);                                  // 3
        w.Write((int)MediusCallbackStatus.MediusSuccess);   // 4

        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.SetLocalizationParamsResponse, w.ToArray()), ct);
    }

    private async Task HandleGetWorldSecurityLevelAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        byte[] msgId = packet.Payload.Length >= MediusConstants.MESSAGEID_MAXLEN
            ? packet.Payload[..MediusConstants.MESSAGEID_MAXLEN]
            : new byte[MediusConstants.MESSAGEID_MAXLEN];

        _log.LogInformation("[MAS] GetWorldSecurityLevel -> GetWorldSecurityLevelResponse");

        // GetWorldSecurityLevelResponse — horizon layout:
        //   [msgId:21][pad:3][status:4][securityLevel:4] = 32 bytes
        var w = new MediusWriter();
        w.Write(msgId);                                     // 21
        w.WritePadding(3);                                  // 3
        w.Write((int)MediusCallbackStatus.MediusSuccess);   // 4
        w.Write(0);                                         // 4 — MediusWorldSecurityLevelNone

        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.GetWorldSecurityLevelResponse, w.ToArray()), ct);
    }

    private async Task HandlePolicyAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        byte[] msgId = packet.Payload.Length >= MediusConstants.MESSAGEID_MAXLEN
            ? packet.Payload[..MediusConstants.MESSAGEID_MAXLEN]
            : new byte[MediusConstants.MESSAGEID_MAXLEN];

        string policyText = _config.EulaText;

        // PolicyResponse — same layout horizon uses (see HandleVersionServerAsync
        // for the byte-by-byte breakdown). Critical: policy text comes BEFORE
        // EndOfText byte, not after — the previous order swapped those.
        var w = new MediusWriter();
        w.Write(msgId);                                                   // 21
        w.WritePadding(3);                                                // 3
        w.Write((int)MediusCallbackStatus.MediusSuccess);                 // 4
        w.WriteString(policyText, MediusConstants.POLICY_MAXLEN);         // 256
        w.Write((byte)1);                                                 // 1 — EndOfText
        w.WritePadding(3);                                                // 3

        await SendMediusAsync(tcp, MediusPacket.BuildLobby(MediusLobbyMessageId.PolicyResponse, w.ToArray()), ct);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// <summary>A name the client can log in with: not empty or blank.</summary>
    private static bool IsValidAccountName(string name) => !string.IsNullOrWhiteSpace(name);

    /// <summary>The reason <paramref name="accountName"/> (when given) or the connection's IP is banned, or null.</summary>
    private string? BanFor(string? accountName, TcpClient tcp)
    {
        var ip = (tcp.Client.RemoteEndPoint as System.Net.IPEndPoint)?.Address;
        var ban = (accountName != null ? _admin.Bans.FindAccount(accountName) : null) ?? _admin.Bans.FindIp(ip);
        return ban == null ? null : (string.IsNullOrEmpty(ban.Reason) ? "banned" : ban.Reason);
    }

    private async Task SendLoginFailure(TcpClient tcp, MediusCallbackStatus status, byte[]? msgId, CancellationToken ct,
        MediusLobbyMessageId responseType = MediusLobbyMessageId.AccountLoginResponse)
    {
        // Same response shape as the success path so the client's parser
        // doesn't choke on the size; only StatusCode differs. The MLS/NAT
        // addresses are zeroed since there's nowhere for the client to go.
        var w = new MediusWriter();
        w.Write(msgId ?? new byte[MediusConstants.MESSAGEID_MAXLEN]);   // 21
        w.WritePadding(3);                                                // 3
        w.Write((int)status);                                              // 4
        w.Write(0);                                                        // 4 AccountId
        w.Write((int)MediusAccountType.MediusMasterAccount);               // 4
        w.Write(0);                                                        // 4 MediusWorldID
        w.WriteNetConnectionInfo(                                          // 154
            NetConnectionType.None,
            mls: null,
            nat: null,
            worldId: 0,
            serverKey: null,
            sessionKey: "",
            accessKey: "");

        await SendMediusAsync(tcp, MediusPacket.BuildLobby(responseType, w.ToArray()), ct);
    }

    /// <summary>16 hex chars from a CSPRNG: the key later stands in for the player on MLS and DME.</summary>
    private static string GenerateSessionKey() => Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
}

/// <summary>
/// NetAddressType values match horizon-server's RT.Common.NetAddressType.
/// Used inside <see cref="MediusWriterExtensions.WriteNetAddress"/> entries.
/// </summary>
internal enum NetAddressType : int
{
    None                       = 0,
    External                   = 1,
    Internal                   = 2,
    NATService                 = 3,
    BinaryExternal             = 4,
    BinaryInternal             = 5,
    BinaryExternalVport        = 6,
    BinaryInternalVport        = 7,
    BinaryNATServices          = 8,
}

/// <summary>
/// NetConnectionType values match horizon-server's RT.Common.NetConnectionType.
/// </summary>
internal enum NetConnectionType : int
{
    None                            = 0,
    ClientServerTCP                 = 1,
    PeerToPeerUDP                   = 2,
    ClientServerTCPAuxUDP           = 3,
    ClientListenerTCP               = 4,
}

// ---------------------------------------------------------------------------
// Extension helpers for MediusWriter (keeps them near where they are used)
// ---------------------------------------------------------------------------
internal static class MediusWriterExtensions
{
    /// <summary>
    /// Write a single NetAddress block (24 bytes):
    ///   [type:4 int LE][address:16 ASCII null-padded][port:4 uint LE]
    /// Matches horizon-server RT.Models.Misc.NetAddress.Serialize().
    /// </summary>
    public static void WriteNetAddress(this MediusWriter w, NetAddressType type, string address, int port)
    {
        w.Write((int)type);
        w.WriteString(address, 16);          // NET_MAX_NETADDRESS_LENGTH
        w.Write((uint)port);                  // uint, NOT ushort — critical!
    }

    /// <summary>
    /// Write the fixed-size NetAddressList block (48 bytes for 2 entries).
    /// Pass null for an unused slot — writes a zero-filled NetAddress.
    /// </summary>
    public static void WriteNetAddressList(this MediusWriter w,
        (NetAddressType type, string address, int port)? slot0,
        (NetAddressType type, string address, int port)? slot1)
    {
        if (slot0 is var s0 && s0 is not null) w.WriteNetAddress(s0.Value.type, s0.Value.address, s0.Value.port);
        else                                    w.WriteNetAddress(NetAddressType.None, "", 0);
        if (slot1 is var s1 && s1 is not null) w.WriteNetAddress(s1.Value.type, s1.Value.address, s1.Value.port);
        else                                    w.WriteNetAddress(NetAddressType.None, "", 0);
    }

    /// <summary>
    /// Write the 64-byte RSA_KEY block (16 uint dwords). For login responses
    /// that don't need a real server key, pass null to emit zeros.
    /// </summary>
    public static void WriteRsaKey(this MediusWriter w, byte[]? key)
    {
        const int sizeDwords = 16;
        if (key == null || key.Length == 0)
        {
            for (int i = 0; i < sizeDwords; i++) w.Write((uint)0);
            return;
        }
        for (int i = 0; i < sizeDwords; i++)
        {
            uint v = 0;
            for (int b = 0; b < 4; b++)
            {
                int idx = i * 4 + b;
                if (idx < key.Length) v |= (uint)key[idx] << (b * 8);
            }
            w.Write(v);
        }
    }

    /// <summary>
    /// Write the full NetConnectionInfo block as PS2-era (MediusVersion ≤ 108)
    /// clients expect it. Layout matches horizon-server RT.Models.Misc.NetConnectionInfo.Serialize():
    ///
    ///   [Type:4 int]
    ///   [AddressList: 2 × NetAddress = 48 bytes]
    ///   [WorldID:4 int]
    ///   [ServerKey: 64 bytes RSA_KEY]
    ///   [SessionKey:17 ASCII]
    ///   [AccessKey:17 ASCII]
    ///   (no extra padding when MediusVersion ≤ 108)
    ///
    /// Total = 154 bytes.
    /// </summary>
    public static void WriteNetConnectionInfo(this MediusWriter w,
        NetConnectionType type,
        (NetAddressType, string, int)? mls,
        (NetAddressType, string, int)? nat,
        int worldId,
        byte[]? serverKey,
        string sessionKey,
        string accessKey)
    {
        w.Write((int)type);
        w.WriteNetAddressList(mls, nat);
        w.Write(worldId);
        w.WriteRsaKey(serverKey);
        w.WriteString(sessionKey, MediusConstants.SESSIONKEY_MAXLEN);
        w.WriteString(accessKey,  MediusConstants.NET_ACCESS_KEY_LEN);

        // EXPERIMENT: emit the 2 trailing bytes horizon writes only for MediusVersion > 108.
        // SessionBeginResponse (no ConnInfo) is accepted, but the AccountLoginResponse is the
        // ONLY message we send that carries a NetConnectionInfo — and SOCOM II rejects it
        // every time. If the PS2 parser expects those 2 bytes, our block is a 2-byte short
        // read here and nowhere else, which fits the symptom exactly. Total = 156 bytes.
        w.WritePadding(2);
    }

    /// <summary>
    /// Write an MLS connection address block:
    /// [ip string 16 bytes][port 2 bytes][pad 2 bytes]
    /// The PS2 client reads this to know where to connect for lobby.
    /// </summary>
    public static void WriteMlsAddress(this MediusWriter w, string ip, int port)
    {
        w.WriteString(ip, 16);
        w.Write((ushort)port);
        w.WritePadding(2);
    }
}
// ---------------------------------------------------------------------------
// Extension helpers for MediusWriter (keeps them near where they are used)
