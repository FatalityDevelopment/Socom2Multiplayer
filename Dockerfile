# SOCOM II online server — MUIS / MAS / MLS / DME / NAT / DNS / patch HTTP + DnaSDK DNAS, one container.
#   docker compose up --build              (local / LAN, see docker-compose.yml)
#   docker build -t socom2-server .
#   az acr build -r <registry> -t socom2-server:<tag> .

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY CodeDesigner.Ps2.Multiplayer/CodeDesigner.Ps2.Multiplayer.csproj CodeDesigner.Ps2.Multiplayer/
COPY DnaSDK/DnaSDK.csproj DnaSDK/
RUN dotnet restore CodeDesigner.Ps2.Multiplayer/CodeDesigner.Ps2.Multiplayer.csproj
COPY . .
RUN dotnet publish CodeDesigner.Ps2.Multiplayer/CodeDesigner.Ps2.Multiplayer.csproj \
    -c Release -o /app --no-restore -p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/runtime:10.0
WORKDIR /app
COPY --from=build /app .

# Container defaults — override any setting with Online__<Name> environment variables.
#   Online__ServerIp=auto + Online__PublicHostname=<fqdn>  → announce the IP the FQDN resolves to
#   Online__DnsForwardUnknown=false                        → never act as an open DNS resolver
#   Online__DataDirectory=/data                            → accounts, stats, clans, DNAS tickets + captures,
#                                                            patch/APACHE00.ZDB (mount a volume)
#   MULTIPLAYER_LOG_FILE=none                              → log to stdout only
ENV Online__BindAddress=0.0.0.0 \
    Online__DataDirectory=/data \
    Online__ServerIp=auto \
    Online__DnsForwardUnknown=false \
    MULTIPLAYER_LOG_FILE=none \
    Logging__Console__FormatterName=simple \
    Logging__Console__FormatterOptions__SingleLine=true \
    Logging__Console__FormatterOptions__TimestampFormat="HH:mm:ss.fff "

VOLUME /data

# DNS (PS2 primary DNS), patch HTTP, DNAS HTTPS, NAT, DME, MUIS, MLS, MAS.
EXPOSE 53/udp 80/tcp 443/tcp 10069/udp 10070/tcp 10071/tcp 10075/tcp 10077/tcp

# Runs as root: the PS2 needs the fixed privileged ports 53 (DNS), 80 (patch) and 443 (DNAS).
ENTRYPOINT ["dotnet", "CodeDesigner.Ps2.Multiplayer.dll"]
