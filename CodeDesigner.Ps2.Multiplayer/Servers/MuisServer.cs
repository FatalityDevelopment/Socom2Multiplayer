using System.Net;
using System.Net.Sockets;
using CodeDesigner.Ps2.Multiplayer.Config;
using CodeDesigner.Ps2.Multiplayer.Models;
using CodeDesigner.Ps2.Multiplayer.Protocol;
using CodeDesigner.Ps2.Multiplayer.Storage;
using Microsoft.Extensions.Logging;

namespace CodeDesigner.Ps2.Multiplayer.Servers;

/// <summary>
/// MUIS - Medius Universe Information Server.
///
/// This is the very first server SOCOM II contacts during boot. It returns the
/// MAS IP address and port so the game knows where to authenticate.
///
/// Default port: 10071 (TCP)
///
/// Protocol (old Medius v108):
///   Full standard SCERT handshake (handled by base class)
///   Server PUSHES LobbyExt:UniverseStatusList_ExtraInfoResponse immediately
///   after CONNECT_COMPLETE - PS2 does NOT send GetUniverse_ExtraInfo first.
///   PS2 reads the pushed universe info and connects to MAS.
///
///   Binary layout reverse-engineered from SOCOM II handler at 0x0031AE88:
///     lw(payload+0x18) MUST be 0 (StatusCode=0) → long parse path
///     lb(payload+0x2B4) MUST be non-zero          → triggers MAS connection
/// </summary>
public class MuisServer : BaseMediusTcpServer
{
    private readonly MultiplayerConfig   _config;
    private readonly PresenceRegistry    _presence;
    private readonly ILogger<MuisServer> _log;

    public MuisServer(MultiplayerConfig config, PresenceRegistry presence, ILogger<MuisServer> log)
        : base(log, config)
    {
        _presence = presence;
        _config    = config;
        _log       = log;
        ServerName = "MUIS";
    }

    public Task StartAsync(CancellationToken ct) =>
        StartAsync(_config.BindAddress, _config.MuisPort, ct);

    // MUIS sends CRYPTKEY_GAME — the PS2 uses the payload bytes directly as its RC4
    // working key.  Required: without it the PS2 cannot decrypt subsequent CHEAT_QUERY
    // and SERVER_APP packets.
    protected override bool SendCryptKeyGameOnConnect => true;

    // SOCOM II v108 flow (confirmed from 2012 live capture):
    //   After CONNECT_COMPLETE the PS2 sends GetUniverse_ExtraInfo.
    //   Server responds with CHEAT_QUERY (3 rounds), then encrypted universe info.
    //   PS2 never sends CLIENT_CONNECT_READY_TCP on MUIS.
    //   Do NOT push proactively — wait for the PS2's request.

    // =========================================================================
    // Medius message dispatch (handles explicit requests as fallback)
    // =========================================================================

    protected override async Task HandleMediusMessageAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        if (packet.MessageClass == NetMessageClass.MessageClassLobbyExt)
        {
            var typeId = (MediusLobbyExtMessageId)packet.MessageType;
            _log.LogDebug("[MUIS] LobbyExt msg: {Type}", typeId);

            switch (typeId)
            {
                case MediusLobbyExtMessageId.GetUniverse_ExtraInfo:
                    await HandleGetUniverseInfoAsync(packet, state, tcp, ct);
                    break;

                default:
                    _log.LogDebug("[MUIS] Unhandled LobbyExt msg 0x{T:X2}", packet.MessageType);
                    break;
            }
        }
        else if (packet.MessageClass == NetMessageClass.MessageClassLobby)
        {
            var typeId = (MediusLobbyMessageId)packet.MessageType;
            _log.LogDebug("[MUIS] Lobby msg: {Type}", typeId);

            switch (typeId)
            {
                case MediusLobbyMessageId.GetUniverse:
                    await HandleGetUniverseInfoAsync(packet, state, tcp, ct);
                    break;

                default:
                    _log.LogDebug("[MUIS] Unhandled Lobby msg 0x{T:X2}", packet.MessageType);
                    break;
            }
        }
        else
        {
            _log.LogDebug("[MUIS] Unhandled class {Cls} msg 0x{T:X2}", packet.MessageClass, packet.MessageType);
        }
    }

    // =========================================================================
    // Universe Info
    // =========================================================================

    private async Task HandleGetUniverseInfoAsync(MediusPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        var r = new MediusReader(packet.Payload);
        // Always capture the request context so the universe response echoes the correct msgId.
        state.MuisMsgId       = r.Remaining >= MediusConstants.MESSAGEID_MAXLEN
            ? r.ReadBytes(MediusConstants.MESSAGEID_MAXLEN)
            : new byte[MediusConstants.MESSAGEID_MAXLEN];
        state.MuisInfoType    = r.Remaining >= 4 ? r.ReadUInt32() : 0xFFFFFFFF;
        state.MuisUseLobbyExt = packet.MessageClass == NetMessageClass.MessageClassLobbyExt;

        _log.LogInformation("[MUIS] GetUniverseInfo from {Ep} (cheat round already={R})", state.RemoteEndpoint, state.MuisCheatRound);

        // Cheat exchange may have already been started proactively from OnSessionEstablishedAsync.
        // If so, just update msgId/infoType and let the exchange complete naturally.
        if (state.MuisCheatRound > 0) return;

        // Otherwise start round 1 now (PS2 sent GetUniverseInfo before we started).
        state.MuisCheatRound = 1;
        await SendPacketAsync(tcp, ScertPacket.CreateCheatQuery(), state, ct);
    }

    protected override async Task HandleCheatQueryResponseAsync(ScertPacket packet, MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        if (state.MuisCheatRound == 0) return; // not in a MUIS exchange

        // Reply to our early test peek (see SendEarlyPeekPokeAsync) — not one of the retail rounds.
        if (IsEarlyPeekReply(packet.Payload))
        {
            var p = packet.Payload;
            _log.LogInformation("[MUIS] EARLY PEEK reply from {Ep}: addr=0x{Addr:X8} len={Len} data={Hex}",
                state.RemoteEndpoint, BitConverter.ToUInt32(p, 5), p.Length - 13,
                BitConverter.ToString(p, 13).Replace("-", " "));
            return;
        }

        state.MuisCheatRound++;
        _log.LogInformation("[MUIS] Cheat round {R} response received", state.MuisCheatRound - 1);

        switch (state.MuisCheatRound)
        {
            case 2:
                // Experiment: push our own pokes/peek here, the earliest point the PS2 has its RC4 key
                // and is known (round 1 just answered) to be servicing 0x1D/0x1E on this connection.
                await SendEarlyPeekPokeAsync(state, tcp, ct);

                // Round 2: send MEMORY_POKE + CHEAT_QUERY in one write.
                await SendPacketAsync(tcp, ScertPacket.CreateMemoryPoke(), state, ct);
                await SendPacketAsync(tcp, ScertPacket.CreateCheatQuery(), state, ct);
                break;

            case 3:
                // Round 3: send another CHEAT_QUERY.
                await SendPacketAsync(tcp, ScertPacket.CreateCheatQuery(), state, ct);
                break;

            case 4:
                // All 3 responses received — now send the universe data.
                _log.LogInformation("[MUIS] Cheat exchange complete — sending universe info to {Ep}", state.RemoteEndpoint);
                await SendUniverseInfoAsync(state.MuisMsgId, state.MuisInfoType,
                    state.MuisUseLobbyExt, state, tcp, ct);
                break;
        }
    }

    // -------------------------------------------------------------------------
    // Early peek/poke experiment (MuisEarlyInject / MuisEarlyPeekAddress)
    // -------------------------------------------------------------------------

    /// <summary>SequenceId stamped on the early test peek. The retail MUIS rounds use the all-zero 13-byte
    /// query (RAW_MEMORY, seq 0), so a non-zero seq is what tells the peek reply apart from a round reply.</summary>
    private const int EarlyPeekSeq = 0x5EEC;

    private static bool IsEarlyPeekReply(byte[] p) =>
        p.Length > 13
        && p[0] == (byte)CheatQueryType.DME_SERVER_CHEAT_QUERY_RAW_MEMORY
        && BitConverter.ToInt32(p, 1) == EarlyPeekSeq;

    /// <summary>
    /// Between MUIS cheat rounds 1 and 2: send the configured binary injections (plaintext MEMORY_POKEs,
    /// same as the lobby path) and/or one RAW_MEMORY CHEAT_QUERY whose reply is logged by
    /// <see cref="HandleCheatQueryResponseAsync"/>. Both are off unless enabled in config.
    /// </summary>
    private async Task SendEarlyPeekPokeAsync(MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        if (_config.MuisEarlyInject)
        {
            _log.LogInformation("[MUIS] EARLY INJECT: sending {N} configured injection(s) to {Ep}",
                _config.Injections.Count(i => i.Enabled), state.RemoteEndpoint);
            await SendConfiguredInjectionsAsync(tcp, ct);
        }

        if (TryParseAddr(_config.MuisEarlyPeekAddress, out uint peekAddr))
        {
            int len = Math.Clamp(_config.MuisEarlyPeekLength, 4, 1024);
            _log.LogInformation("[MUIS] EARLY PEEK: RAW_MEMORY 0x{Addr:X8} +{Len} to {Ep}", peekAddr, len, state.RemoteEndpoint);
            await SendPacketAsync(tcp, ScertPacket.CreateRawMemoryQuery(EarlyPeekSeq, peekAddr, len), state, ct);
        }
    }

    private async Task SendUniverseInfoAsync(byte[] msgId, uint infoType, bool useLobbyExt,
        MediusClientState state, TcpClient tcp, CancellationToken ct)
    {
        _log.LogInformation("[MUIS] Sending universe info - MAS={Ip}:{Port}", _config.ServerIp, _config.MasPort);

        var payload = !useLobbyExt && _config.WireFixes.MuisLegacyGetUniverse
            ? BuildLegacyGetUniverseResponsePayload(msgId)   // the 0x120-byte Lobby GetUniverseResponse body
            : BuildLegacyUniverseStatusPayload(msgId);

        MediusPacket response;
        if (useLobbyExt)
        {
            // SOCOM II (old Medius v108) understands only UniverseStatusList_ExtraInfoResponse (0x04).
            response = MediusPacket.BuildLobbyExt(
                MediusLobbyExtMessageId.UniverseStatusList_ExtraInfoResponse, payload);
        }
        else
        {
            response = MediusPacket.BuildLobby(MediusLobbyMessageId.GetUniverseResponse, payload);
        }

        var appBytes = response.Serialize();
        _log.LogInformation(
            "[MUIS] Universe app payloadLen=0x{PayloadLen:X} appLen=0x{AppLen:X} status@0x18={Status} flag@0x2B4=0x{Flag:X2} endOfList@0x335=0x{Eol:X2} head={Head} tail={Tail}",
            payload.Length,
            appBytes.Length,
            BitConverter.ToString(payload, 0x18, 4).Replace("-", " "),
            payload[0x2B4],
            payload[0x335],
            HexSlice(appBytes, 0x00, Math.Min(0x20, appBytes.Length)),
            HexSlice(appBytes, 0x2B0, Math.Min(0x20, Math.Max(0, appBytes.Length - 0x2B0))));

        // Send ENCRYPTED (0x8A) — confirmed from 2012 live capture (Frame 176).
        // The PS2 activates its game RC4 key upon receiving CRYPTKEY_GAME and will
        // decrypt all subsequent SERVER_APP packets.  Sending plain (0x0A) causes
        // the PS2 to RC4-"decrypt" the plaintext → garbage → status check fails →
        // parser takes failure path → no universe entry added → disconnect.
        await SendMediusAsync(tcp, response, state, ct);

        // ---- Second message (always): Lobby::UniverseNewsResponse (PS2 handler 0x0031B270) ----
        // Confirmed from PS2 context global 0x00421870 which begins with string "UniverseNews",
        // identifying this handler as the UniverseNewsResponse (Lobby class 0x01, type 0xC9)
        // consumer.  The 2012 MUIS capture Frame 177 (297 bytes = 7 SCERT + 290-byte payload)
        // is this message.
        // The PS2 registers handlers for BOTH LobbyExt::UniverseStatusList_ExtraInfoResponse
        // (0x0031AE90, sets flag 0x453150) AND Lobby::UniverseNewsResponse (0x0031B270, sets
        // flag 0x453158).  The state-machine at 0x00318788 checks (0x453150 AND 0x453158) before
        // proceeding to MAS; without this second packet 0x453158 is never set, the PS2 never
        // closes the MUIS socket, and stays in a CLIENT_ECHO keepalive loop showing
        // "Disconnected from network".
        var payload2  = BuildLegacyUniverseNewsPayload(msgId);
        var response2 = MediusPacket.BuildLobby(MediusLobbyMessageId.UniverseNewsResponse, payload2);
        _log.LogInformation(
            "[MUIS] Sending second universe message (Lobby::UniverseNewsResponse 0x{Len:X} bytes)",
            payload2.Length);
        await SendMediusAsync(tcp, response2, state, ct);
    }

    private byte[] BuildLegacyUniverseNewsPayload(byte[] msgId)
    {
        // Lobby::UniverseNewsResponse body — 0x120 = 288 bytes.
        // Confirmed by PS2 context global 0x00421870 which starts with string "UniverseNews",
        // identifying handler 0x0031B270 as the UniverseNewsResponse consumer.
        // Commit function 0x0031CCF0 (called from handler 0x0031B270) copies 0x120 bytes:
        //   0x00..0x14 (21 bytes): MessageID
        //   0x18       (  4 bytes): StatusCode — MUST be 0 (gate at 0x0031B288)
        //   0x1C..0x11B (256 bytes): news text / padding
        //   0x11C       (  1 byte):  end-of-news flag — MUST be non-zero to set 0x453158
        //                             (checked at lb 0x11C(s0) / beqz at 0x0031B2CC)
        // 2012 live capture: Frame 177 (297 bytes = 3 SCERT + 4 hash + 290-byte Medius payload;
        //   Medius = 2-byte class/type header + 288-byte body = this struct).
        var payload = new byte[0x120];

        static void WriteFixedAscii(byte[] dst, int offset, int len, string text)
        {
            var s   = text ?? string.Empty;
            var max = Math.Max(0, len - 1);
            var n   = Math.Min(s.Length, max);
            for (var i = 0; i < n; i++)
                dst[offset + i] = (byte)(s[i] <= 0x7F ? s[i] : '?');
        }

        Array.Copy(msgId, 0, payload, 0, Math.Min(msgId.Length, MediusConstants.MESSAGEID_MAXLEN));
        // StatusCode at 0x18 = 0 (zero-initialized array)
        WriteFixedAscii(payload, 0x01C, 256, _config.UniverseNews);  // News text at 0x1C..0x11B
        payload[0x11C] = 0x01;  // end-of-news flag; must be non-zero to set 0x453158

        return payload;
    }

    private byte[] BuildLegacyGetUniverseResponsePayload(byte[] msgId)
    {
        // Old Medius Lobby::GetUniverseResponse body — 0x120 = 288 bytes.
        // Confirmed from disassembly of PS2 handler 0x0031B270 and commit function 0x0031CCF0.
        //
        // Commit function copies from payload into a second universe list (entry size = 0x120):
        //   0x00..0x14 ( 21 bytes): MessageID
        //   0x18       (  4 bytes): StatusCode        — MUST be 0
        //   0x1C..0x5B ( 64 bytes): DisplayName
        //   0x5C..0xDB (128 bytes): Description
        //   0xDC..0x11B ( 64 bytes): Hostname/URL
        //   0x11C       (  1 byte):  MAS flag          — MUST be non-zero (checked by lb then bnez)
        //   0x11D..0x11F (3 bytes):  padding
        //
        // 2012 live capture: Frame 177 (297 bytes = 3 SCERT + 4 hash + 290-byte payload).
        var payload = new byte[0x120];

        static void WriteFixedAscii(byte[] dst, int offset, int len, string text)
        {
            var s   = text ?? string.Empty;
            var max = Math.Max(0, len - 1);
            var n   = Math.Min(s.Length, max);
            for (var i = 0; i < n; i++)
                dst[offset + i] = (byte)(s[i] <= 0x7F ? s[i] : '?');
        }

        Array.Copy(msgId, 0, payload, 0, Math.Min(msgId.Length, MediusConstants.MESSAGEID_MAXLEN));
        // StatusCode at 0x18 = 0 (zero-initialized array)
        WriteFixedAscii(payload, 0x1C,  64, _config.UniverseName);
        WriteFixedAscii(payload, 0x5C, 128, _config.UniverseDescription);
        WriteFixedAscii(payload, 0xDC,  64, _config.ServerIp);
        payload[0x11C] = 0x01;  // MAS available flag — handler 0x0031B270 checks this byte

        return payload;
    }

    private byte[] BuildLegacyUniverseStatusPayload(byte[] msgId)
    {
        // UniverseStatusList payload laid out to match SOCOM II runtime offsets.
        // Confirmed from live PSRewired memory dump + disassembly of 0x0031AE88.
        //
        // Parser reads (s2 = payload pointer):
        //   0x000 (21): MessageID
        //   0x018 ( 4): StatusCode — MUST be 0, any other value skips the entire handler
        //   0x01C (64): display name       → entry+0x01C
        //   0x09C (64): MAS hostname/IP    → entry+0x09C  ← PS2 connects here
        //   0x11C ( 4): MAS port (int32)   → entry+0x11C
        //   0x120 (128): description       → entry+0x120
        //   0x220 ( 4): user count         → entry+0x220
        //   0x224 ( 4): max users          → entry+0x224
        //   0x228 ( 4): unknown            → entry+0x228
        //   0x22C ( 4): active flag        → entry+0x22C
        //   0x234 (64): unknown field      → entry+0x234
        //   0x2B4 ( 1): MAS enable flag (non-zero = initiate MAS TCP connection)
        //   0x2B5 (128): "<version> <patchUrl>" — split by strtok(" \t") (0x0019AA00) into
        //                entry+0x338 (version, 32) and entry+0x358 (URL, 128). VerifyPatchLevel
        //                (0x0031AA80) passes when entry+0x338 is empty or equals the client's built-in
        //                level; otherwise the client GETs <URL>APACHE00.ZDB (CSMDownloadPatch).
        //   0x335 ( 1): EndOfList — MUST be 1 on final entry; PS2 parser loops until
        //                this is non-zero before committing the universe and connecting to MAS.
        //   0x336..0x337: struct padding (2 bytes, zeros)
        // Total entry size = 0x338 bytes → Medius app = 2-byte header + 0x338-byte payload
        //   = 0x33A = 826 bytes, matching 2012 live capture Frame 176 ciphertext len.
        // Field sizes confirmed from disassembly of 0x0031AE88 loop counts and live
        // PSRewired memory dump.
        var payload = new byte[0x338];

        static void WriteInt32Le(byte[] dst, int offset, int value)
        {
            dst[offset + 0] = (byte)(value & 0xFF);
            dst[offset + 1] = (byte)((value >> 8) & 0xFF);
            dst[offset + 2] = (byte)((value >> 16) & 0xFF);
            dst[offset + 3] = (byte)((value >> 24) & 0xFF);
        }

        static void WriteFixedAscii(byte[] dst, int offset, int len, string text)
        {
            var s = text ?? string.Empty;
            var max = Math.Max(0, len - 1);
            var writeLen = Math.Min(s.Length, max);
            for (var i = 0; i < writeLen; i++)
                dst[offset + i] = (byte)(s[i] <= 0x7F ? s[i] : '?');
            // Remaining bytes stay zero (null-terminated fixed field).
        }

        // 0x000: MessageID (21 bytes). payload[0x018] = StatusCode MUST stay 0 —
        //        parser does lw a1,0x18(a3) → if non-zero, skips the entire handler.
        Array.Copy(msgId, 0, payload, 0, Math.Min(msgId.Length, MediusConstants.MESSAGEID_MAXLEN));
        // 0x01C: display name (parser copies 128 bytes: 0x40 iterations × 2)
        WriteFixedAscii(payload, 0x01C, 128, _config.UniverseName);
        // 0x09C: MAS hostname/IP (parser copies 128 bytes) — PS2 connects to MAS here
        WriteFixedAscii(payload, 0x09C, 128, _config.ServerIp);
        // 0x11C: MAS port (lw, 4 bytes LE)
        WriteInt32Le(payload, 0x11C, _config.MasPort);
        // 0x120: description (parser copies 256 bytes: 0x80 iterations × 2)
        WriteFixedAscii(payload, 0x120, 256, _config.UniverseDescription);
        // 0x220: status dot — 1 = green (confirmed from PSRewired dump: entry+0x220 = 1)
        WriteInt32Le(payload, 0x220, 1);
        // 0x224: user count shown in the universe list (the dump held 0x20) — players online right now.
        WriteInt32Le(payload, 0x224, _presence.OnlineCount);
        // 0x228: max users (confirmed from dump: entry+0x228 = 0x2710)
        WriteInt32Le(payload, 0x228, Math.Max(1, _config.MaxClients));
        // 0x22C: 8 bytes copied by parser — zeros (confirmed from dump: entry+0x22C = 0)
        // 0x234: 128 bytes copied by parser — zeros
        // 0x2B4: MAS enable flag — non-zero triggers immediate MAS TCP connection
        payload[0x2B4] = 0x01;
        // 0x2B5: "<version> <patchUrl>" (parser copies 128 bytes) — retail sent
        //        "r0004 http://updates.pdonline.scea.com:80/_socom2-prod/currentpatch/" (retail dump).
        //        A version with no URL leaves unpatched (r0001) clients failing with "Bad URI".
        WriteFixedAscii(payload, 0x2B5, 128, string.IsNullOrWhiteSpace(_config.UniversePatchVersion)
            ? ""
            : $"{_config.UniversePatchVersion.Trim()} {_config.EffectivePatchUrl}");
        // 0x335: EndOfList — PS2 universe parser loops until this byte is non-zero.
        //        Without it the PS2 waits for more entries indefinitely and never
        //        proceeds to connect to MAS.  Must be 1 on the final (or only) entry.
        payload[0x335] = 0x01;
        // 0x336..0x337: struct tail-padding (2 bytes, zeros)

        return payload;
    }

    private static string HexSlice(byte[] data, int offset, int length)
    {
        if (offset < 0 || offset >= data.Length || length <= 0)
            return string.Empty;

        var count = Math.Min(length, data.Length - offset);
        return BitConverter.ToString(data, offset, count).Replace("-", " ");
    }
}
