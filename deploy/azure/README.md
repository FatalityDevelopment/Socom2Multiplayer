# SOCOM II server on Azure (test deployment)

Runs the server (MUIS, MAS, MLS, DME, NAT, DnaSDK DNAS, DNS) as one container on
**Azure Container Instances**. ACI is used because the server needs public **UDP** ports (DNS 53, NAT 10069)
next to its TCP ports on one fixed IP; Azure Container Apps can't expose UDP.

## Prerequisites

- Azure CLI: `winget install Microsoft.AzureCLI`, then `az login`.
- No local Docker needed: the image is built in Azure with `az acr build`.

## Deploy

```powershell
./deploy/azure/deploy-aci.ps1 -AcrName <uniqueregistryname> -DnsNameLabel <label>
```

The script creates the resource group and registry, builds the image from the repo root
(the working tree, so no commit is needed), and deploys `main.bicep`. It prints the FQDN and public IP.
Re-run it to ship a new build.

**On the PS2**, set **Primary DNS** to the printed public IP. Everything else follows from DNS: DNAS and
`*.pdonline.scea.com` resolve to the server, and the server announces its own public IP to the console.

## Operate

| | |
|---|---|
| Live logs | `az container logs -g socom2-test-rg -n socom2-server --follow` |
| Stop (stops billing) | `az container stop -g socom2-test-rg -n socom2-server` |
| Start | `az container start -g socom2-test-rg -n socom2-server` |
| Delete everything | `az group delete -n socom2-test-rg` |

## How it's configured

Settings come from `config.json` in the image, overridden by `Online__<Setting>` environment variables
(set in `main.bicep`):

| Variable | Value | Why |
|---|---|---|
| `Online__ServerIp` | `auto` | Resolved at startup from `Online__PublicHostname` (the group's FQDN). ACI's outbound IP can differ from its inbound IP, so a what's-my-IP lookup would be wrong. |
| `Online__DnsForwardUnknown` | `false` | Only DNAS/Medius names are answered; everything else is REFUSED, so the public DNS port isn't an open resolver. |
| `MULTIPLAYER_LOG_FILE` | `none` | Logs go to stdout (`az container logs`), not an ever-growing file. |
| `Logging__LogLevel__Default` | `Debug` | Full packet hex while testing; deploy with `-LogLevel Information` to quiet it. |
| `Online__ExternalDnasServer` | empty | Set with `-ExternalDnasServer <ip-or-host>` to send consoles to another DNAS server. The built-in DnaSDK gateway then stays off, and DNS answers `*.dnas.playstation.org` with that server's address. |

## Test-deployment caveats

- **Persistent data** (accounts, stats, friends/ignore lists, clans, DNAS tickets and DNAS packet logs) lives in `server-data.json` on an Azure Files
  share mounted at `/data`, so it survives restarts and redeploys. `az group delete` removes it too.
- **Patch download**: put the APACHE00.ZDB to serve at `patch/APACHE00.ZDB` on that share. Unpatched (disc r0001)
  consoles download it from `http://<fqdn>:80/_socom2-prod/currentpatch/APACHE00.ZDB` and save it to the memory card.
  Games, briefing-room occupancy and online presence are runtime-only.
- **The container runs as root** because the console needs the fixed privileged ports 53 and 443.
- **Accounts are auto-created** on first login (`AutoCreateAccounts`). Anyone who points a PS2 at the IP can play.
- **The IP can change** if the container group is deleted and recreated. `az container stop`/`start` normally keeps
  the DNS label, and the server re-resolves its FQDN on every start, but the PS2's DNS setting must match the new IP.
- **Cost:** 1 vCPU / 2 GB running 24/7 is roughly US$35–45 a month. Stop the group when you're not testing.

## Local container test

See the repo README (`docker compose up --build` from the repo root).
