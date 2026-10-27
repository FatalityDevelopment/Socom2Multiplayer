# SOCOM II Multiplayer

A private online server for SOCOM U.S. Navy SEALs II (PS2) in a single container. It runs:

| Service | Port | Purpose |
|---|---|---|
| DNS | 53/udp | The PS2's primary DNS. Answers `*.dnas.playstation.org` and `*.pdonline.scea.com` with this server's IP |
| Patch HTTP | 80/tcp | Serves `APACHE00.ZDB` (r0004 patch) to unpatched consoles |
| DNAS | 443/tcp | [DnaSDK](https://github.com/FatalityDevelopment/DnaSDK): live DNAS authentication for unmodified retail discs |
| NAT | 10069/udp | NAT helper |
| DME | 10070/tcp | Game worlds |
| MUIS | 10071/tcp | Universe list, news, patch announcement |
| MLS | 10075/tcp | Lobby, chat, clans, stats |
| MAS | 10077/tcp | Account login |

The server came from `CodeDesigner.Ps2.Multiplayer` in [CodeDesignerPS2](https://github.com/FatalityDevelopment/CodeDesignerPS2).
It keeps the same project name and namespaces, so changes can be copied between the two repos.

## Run it (Docker)

```bash
SERVER_IP=192.168.1.20 docker compose up --build -d
```

Set `SERVER_IP` to the address the PS2 can reach, usually this machine's LAN IP. You can also put
`SERVER_IP=...` in a `.env` file next to `docker-compose.yml`. On the PS2, set **Primary DNS** to that IP.
DNS points the console at everything else.

Logs: `docker compose logs -f`. Set `LOG_LEVEL=Debug` to log full packet hex.

Ports 53, 80 and 443 must be free on the host. On Linux, `systemd-resolved` often holds 53. On Windows,
IIS or another web server may hold 80 or 443.

### Persistent data (`/data` volume)

| Path | Contents |
|---|---|
| `server-data.json`, `bans.json`, `cheat-scan.json` | Accounts, stats, friends, clans, bans |
| `dnas/RSA/Signatures/<SERIAL>.BIN` | DNAS tickets (SOCOM II's is installed on first start; other titles are fetched from DNASrep and cached) |
| `dnas/PacketLogs/` | DnaSDK's per-session DNAS request/response captures |
| `patch/APACHE00.ZDB` | The patch file to serve. Copy it in yourself; it is not in this repo |

To copy the patch file into the volume:

```bash
docker compose cp APACHE00.ZDB socom2-server:/data/patch/APACHE00.ZDB
```

## Configuration

Settings come from `CodeDesigner.Ps2.Multiplayer/config.json`. Environment variables named `Online__<Setting>`
override them, and so does an extra JSON file named by `MULTIPLAYER_CONFIG`. The container defaults are:

| Variable | Default | Notes |
|---|---|---|
| `Online__ServerIp` | `auto` | The IP announced to consoles. `auto` resolves `Online__PublicHostname`, or falls back to a public-IP lookup |
| `Online__DnsForwardUnknown` | `false` | `true` forwards other DNS names upstream (compose turns this on for LAN use). Keep it `false` on a public IP |
| `Online__DataDirectory` | `/data` | |
| `MULTIPLAYER_LOG_FILE` | `none` | Logs go to stdout only |

DNAS settings (all optional):

| Setting | Default |
|---|---|
| `DnasHttpsPort` | `443` (`0` disables DNAS) |
| `DnasCertPath` / `DnasKeyPath` / `DnasCaPath` | The `gate1.us.dnas.playstation.org` chain bundled with DnaSDK |
| `DnasRsaDirectory` | `<DataDirectory>/dnas/RSA` |
| `DnasCaptureDirectory` | `<DataDirectory>/dnas/PacketLogs` |
| `DnasRepositoryUrl` | DNASrep (`https://raw.githubusercontent.com/FogNo23/DNASrep/master/www/dnas`) |

## Cloud deployment

See [deploy/azure/README.md](deploy/azure/README.md). It covers Azure Container Instances, which can expose UDP ports.

## Layout

```
CodeDesigner.Ps2.Multiplayer/   Medius/DME/NAT/DNS/patch server (.NET 10)
  Servers/DnasServer.cs         Hosts DnaSDK's TLS/DNAS listener in-process
  Dnas/Signatures/              Bundled original DNAS tickets (SCUS97275)
DnaSDK/                         DnaSDK source (FatalityDevelopment/DnaSDK), used as a project reference
deploy/azure/                   ACI bicep + deploy script
Dockerfile, docker-compose.yml
```

### Updating DnaSDK

`DnaSDK/` is a copy of the `DnaSDK/` folder from the upstream repo. The only local change is an
`InternalsVisibleTo` in `DnaSDK.csproj`, which lets the server start its `TcpServer`. To update, copy the
upstream folder over this one and keep that `ItemGroup`. Don't copy upstream's `Dockerfile`; the root
`Dockerfile` builds both projects.

## Building without Docker

```bash
dotnet build Socom2Multiplayer.slnx
dotnet run --project CodeDesigner.Ps2.Multiplayer
```

This needs the .NET 10 SDK. Binding ports 53, 80 and 443 needs admin/root.
