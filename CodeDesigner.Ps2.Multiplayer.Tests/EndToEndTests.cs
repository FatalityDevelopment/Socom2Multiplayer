using System.Net;
using System.Net.Sockets;
using System.Text;
using CodeDesigner.Ps2.Multiplayer.Config;
using CodeDesigner.Ps2.Multiplayer.Crypto;
using CodeDesigner.Ps2.Multiplayer.Protocol;
using CodeDesigner.Ps2.Multiplayer.Servers;
using CodeDesigner.Ps2.Multiplayer.Storage;
using Microsoft.Extensions.Logging.Abstractions;

namespace CodeDesigner.Ps2.Multiplayer.Tests;

/// <summary>
/// Runs MAS, MLS and DME in-process on loopback ports and drives them with a scripted v108 console: the SCERT key
/// exchange, login, create/join a game and the DME connect.
/// </summary>
[Collection("DmeWorlds")]
public sealed class EndToEndTests : IAsyncLifetime
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "socom2-e2e-" + Guid.NewGuid().ToString("N"));
    private readonly CancellationTokenSource _cts = new();
    private MultiplayerConfig _config = null!;
    private InMemoryStorage _store = null!;
    private AdminSettings _admin = null!;
    private MasServer _mas = null!;
    private MlsServer _mls = null!;
    private DmeServer _dme = null!;

    public async Task InitializeAsync()
    {
        _config = new MultiplayerConfig
        {
            BindAddress = "127.0.0.1", ServerIp = "127.0.0.1", DataDirectory = _dir,
            MasPort = FreePort(), MlsPort = FreePort(), DmePort = FreePort(),
            MaxConnectionsPerIp = 0,
        };
        _store = new InMemoryStorage(_config, NullLogger<InMemoryStorage>.Instance);
        _admin = new AdminSettings(_config, NullLogger<AdminSettings>.Instance);
        var presence = new PresenceRegistry();
        _mas = new MasServer(_config, _store, _admin, NullLogger<MasServer>.Instance);
        _mls = new MlsServer(_config, _store, presence, _admin, NullLogger<MlsServer>.Instance);
        _dme = new DmeServer(_config, presence, _store, _admin, NullLogger<DmeServer>.Instance);
        await _mas.StartAsync(_cts.Token);
        await _mls.StartAsync(_cts.Token);
        await _dme.StartAsync(_cts.Token);
    }

    public Task DisposeAsync()
    {
        _cts.Cancel();
        _mas.Stop(); _mls.Stop(); _dme.Stop();
        _admin.Dispose();
        _store.Dispose();
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
        return Task.CompletedTask;
    }

    [Fact]
    public async Task Login_CreateGame_JoinGame_ConnectDme()
    {
        // MAS: session, then an account login (auto-creates the account).
        using var mas = await TestConsole.ConnectAsync(_config.MasPort, world: 1, accessKey: "");
        var session = await mas.RequestAsync(MediusLobbyMessageId.SessionBegin, Body(new byte[12]));
        string sessionKey = Encoding.ASCII.GetString(session, 28, 16);
        var login = await mas.RequestAsync(MediusLobbyMessageId.AccountLogin, Body(Key(sessionKey), Name("Masquarr"), Name("pw")));
        Assert.Equal((int)MediusCallbackStatus.MediusSuccess, Status(login));

        // MLS (briefing room 0x44): the session key is the access key.
        using var mls = await TestConsole.ConnectAsync(_config.MlsPort, world: 0x44, accessKey: sessionKey);
        var create = await mls.RequestAsync(MediusLobbyMessageId.CreateGame1, Body(Key(sessionKey), new byte[2],
            I(10472), I(2), I(8), I(0), Fixed("e2e game", 64), new byte[32], new byte[32], I(0), I(0), I(0x44), I(0), I(0), I(0), I(0)));
        Assert.Equal((int)MediusCallbackStatus.MediusSuccess, Status(create));
        int gameId = BitConverter.ToInt32(create, 28);

        var join = await mls.RequestAsync(MediusLobbyMessageId.JoinGame, Body(Key(sessionKey), new byte[2],
            I(gameId), I(0), new byte[32], I(0), new byte[64], new byte[48]));
        Assert.Equal((int)MediusCallbackStatus.MediusSuccess, Status(join));
        int dmeWorld = BitConverter.ToInt32(join, 28 + 4 + 4 + 48);
        string accessKey = Encoding.ASCII.GetString(join, 28 + 4 + 4 + 48 + 4 + 64 + 17, 16);

        // DME: the slot's token binds the connection; a second connection with the same token is refused.
        using var dme = await TestConsole.ConnectAsync(_config.DmePort, world: dmeWorld, accessKey: accessKey);
        Assert.True(dme.Accepted);
        using var hijack = await TestConsole.ConnectAsync(_config.DmePort, world: dmeWorld, accessKey: accessKey);
        Assert.False(hijack.Accepted);
    }

    [Fact]
    public async Task TicketLogin_CannotTakeOverPasswordedAccount()
    {
        _store.TryCreateAccount("Victim", PasswordHasher.Hash("secret"));

        using var mas = await TestConsole.ConnectAsync(_config.MasPort, world: 1, accessKey: "");
        var session = await mas.RequestAsync(MediusLobbyMessageId.SessionBegin, Body(new byte[12]));
        string sessionKey = Encoding.ASCII.GetString(session, 28, 16);

        var ticket = await mas.RequestAsync(MediusLobbyMessageId.TicketLogin, Body(Key(sessionKey), Name("Victim"), new byte[16]));
        Assert.Equal((int)MediusCallbackStatus.MediusInvalidPassword, Status(ticket));

        var wrong = await mas.RequestAsync(MediusLobbyMessageId.AccountLogin, Body(Key(sessionKey), Name("Victim"), Name("guess")));
        Assert.Equal((int)MediusCallbackStatus.MediusLoginFailed, Status(wrong));
        var right = await mas.RequestAsync(MediusLobbyMessageId.AccountLogin, Body(Key(sessionKey), Name("Victim"), Name("secret")));
        Assert.Equal((int)MediusCallbackStatus.MediusSuccess, Status(right));
    }

    [Fact]
    public async Task EmptyCryptKey_ClosesConnectionWithoutHangingServer()
    {
        using (var bad = new TcpClient())
        {
            await bad.ConnectAsync(IPAddress.Loopback, _config.MasPort);
            var stream = bad.GetStream();
            await stream.WriteAsync(new byte[] { (byte)RT_MSG_TYPE.RT_MSG_CLIENT_CRYPTKEY_PUBLIC, 0, 0 });
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            int read = await stream.ReadAsync(new byte[16], timeout.Token);
            Assert.Equal(0, read);   // the server closed it
        }

        // ...and keeps serving everyone else.
        using var ok = await TestConsole.ConnectAsync(_config.MasPort, world: 1, accessKey: "");
        Assert.True(ok.Accepted);
    }

    // ── request building ───────────────────────────────────────────────────────

    private static byte[] Body(params byte[][] parts) => [.. new byte[21], .. parts.SelectMany(p => p)];   // MessageID[21] first
    private static byte[] I(int v) => BitConverter.GetBytes(v);
    private static byte[] Fixed(string s, int len) { var b = new byte[len]; Encoding.ASCII.GetBytes(s).CopyTo(b, 0); return b; }
    private static byte[] Key(string sessionKey) => Fixed(sessionKey, MediusConstants.SESSIONKEY_MAXLEN);
    private static byte[] Name(string name) => Fixed(name, MediusConstants.ACCOUNTNAME_MAXLEN);
    private static int Status(byte[] reply) => BitConverter.ToInt32(reply, 24);

    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    /// <summary>A minimal SOCOM II-style (v108) SCERT client.</summary>
    private sealed class TestConsole : IDisposable
    {
        private readonly TcpClient _tcp = new();
        private readonly byte[] _buf = new byte[1 << 17];
        private int _len;
        private byte[] _key = [];

        public bool Accepted { get; private set; }

        public static async Task<TestConsole> ConnectAsync(int port, int world, string accessKey)
        {
            var c = new TestConsole();
            await c._tcp.ConnectAsync(IPAddress.Loopback, port);
            var rsa = Ps2Rsa.GenerateKeyPair();

            await c.SendAsync(RT_MSG_TYPE.RT_MSG_CLIENT_CONNECT_TCP, []);
            // A zero hash means plaintext: the server takes the 64 bytes as the client's modulus directly.
            await c.SendAsync(RT_MSG_TYPE.RT_MSG_CLIENT_CRYPTKEY_PUBLIC, rsa.GetPublicKey());
            c._key = (await c.ReadUntilAsync(RT_MSG_TYPE.RT_MSG_SERVER_CRYPTKEY_PEER))!.Payload;

            // v108 CONNECT_TCP: [TargetWorldId:4 (world in the high byte)][UNK0:1][AppId:4][RSA_KEY:64][SessionKey:17][AccessKey:17]
            var connect = new byte[107];
            BitConverter.GetBytes((uint)world << 24 | 0x00D20801u).CopyTo(connect, 0);
            BitConverter.GetBytes(10472).CopyTo(connect, 5);
            Encoding.ASCII.GetBytes(accessKey).CopyTo(connect, 4 + 1 + 4 + 64 + 17);
            await c.SendAsync(RT_MSG_TYPE.RT_MSG_CLIENT_CONNECT_TCP, connect);

            var done = await c.ReadUntilAsync(RT_MSG_TYPE.RT_MSG_SERVER_CONNECT_COMPLETE, RT_MSG_TYPE.RT_MSG_SERVER_FORCED_DISCONNECT);
            c.Accepted = done?.MessageType == RT_MSG_TYPE.RT_MSG_SERVER_CONNECT_COMPLETE;
            return c;
        }

        /// <summary>Send a Lobby request and return the payload of the first SERVER_APP reply (after the class/type bytes).</summary>
        public async Task<byte[]> RequestAsync(MediusLobbyMessageId type, byte[] body)
        {
            await SendAsync(RT_MSG_TYPE.RT_MSG_CLIENT_APP_TOSERVER, MediusPacket.BuildLobby(type, body).Serialize());
            var reply = await ReadUntilAsync(RT_MSG_TYPE.RT_MSG_SERVER_APP)
                        ?? throw new InvalidOperationException($"no reply to {type}");
            return reply.Payload[2..];
        }

        private Task SendAsync(RT_MSG_TYPE type, byte[] payload)
            => _tcp.GetStream().WriteAsync(new ScertPacket { MessageType = type, Payload = payload }.Serialize()).AsTask();

        private async Task<ScertPacket?> ReadUntilAsync(params RT_MSG_TYPE[] wanted)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            while (true)
            {
                var p = ScertPacket.TryRead(_buf, 0, _len, out int used);
                if (p != null)
                {
                    Buffer.BlockCopy(_buf, used, _buf, 0, _len - used);
                    _len -= used;
                    if (p.Hash != null && _key.Length > 0) PS2_RC4.Decrypt(_key, p.Hash, p.Payload);
                    if (wanted.Contains(p.MessageType)) return p;
                    continue;
                }
                int read = await _tcp.GetStream().ReadAsync(_buf.AsMemory(_len), timeout.Token);
                if (read == 0) return null;
                _len += read;
            }
        }

        public void Dispose() => _tcp.Dispose();
    }
}
