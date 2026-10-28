// Azure Container Instances deployment of the PS2 Medius server (SOCOM II).
// ACI is used (not Container Apps) because the server needs public UDP ports (DNS 53, NAT 10069) and
// several raw TCP ports on one fixed public IP.
//
// Deployed by deploy-aci.ps1; can also be run directly:
//   az deployment group create -g <rg> -f main.bicep -p acrName=<acr> dnsNameLabel=<label> imageTag=<tag>

@description('Region for the container group.')
param location string = resourceGroup().location

@description('Existing Azure Container Registry (admin user enabled) holding the image.')
param acrName string

@description('Image repository in the registry.')
param imageName string = 'socom2-server'

@description('Image tag to run.')
param imageTag string = 'latest'

@description('DNS name label — the server becomes <label>.<region>.azurecontainer.io. Unique per region.')
param dnsNameLabel string

param containerGroupName string = 'socom2-server'
param cpuCores int = 1
param memoryInGb int = 2

@description('Console log level: Information, or Debug for full packet hex while testing.')
@allowed([ 'Debug', 'Information', 'Warning' ])
param logLevel string = 'Information'

@description('Optional external DNAS server (IP or hostname). Empty = DNAS runs in this container.')
param externalDnasServer string = ''

@description('DNAS region: picks the gateway certificate and the packet region searched first.')
@allowed([ 'us-gw', 'eu-gw', 'gai-gw' ])
param dnasRegion string = 'us-gw'

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: acrName
}

// Persistent server data (accounts, stats, friends, clans) — an Azure Files share mounted at /data, so it
// survives container restarts and redeploys.
resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'socom2${uniqueString(resourceGroup().id)}'
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
  }
}

resource dataShare 'Microsoft.Storage/storageAccounts/fileServices/shares@2023-01-01' = {
  name: '${storage.name}/default/socom2-data'
  properties: { shareQuota: 5 }   // GiB; DNAS packet logs accumulate under /data/dnas/PacketLogs
}

var fqdn = '${dnsNameLabel}.${location}.azurecontainer.io'

var ports = [
  { port: 53, protocol: 'UDP' }      // DNS — the PS2's primary DNS server
  { port: 80, protocol: 'TCP' }      // patch download (APACHE00.ZDB)
  { port: 443, protocol: 'TCP' }     // DNAS HTTPS (DnaSDK)
  { port: 10069, protocol: 'UDP' }   // NAT service
  { port: 10070, protocol: 'TCP' }   // DME (game worlds)
  { port: 10071, protocol: 'TCP' }   // MUIS
  { port: 10075, protocol: 'TCP' }   // MLS (lobby)
  { port: 10077, protocol: 'TCP' }   // MAS (auth)
]

resource containerGroup 'Microsoft.ContainerInstance/containerGroups@2023-05-01' = {
  name: containerGroupName
  location: location
  properties: {
    osType: 'Linux'
    restartPolicy: 'Always'
    imageRegistryCredentials: [
      {
        server: acr.properties.loginServer
        username: acr.listCredentials().username
        password: acr.listCredentials().passwords[0].value
      }
    ]
    ipAddress: {
      type: 'Public'
      dnsNameLabel: dnsNameLabel
      ports: ports
    }
    containers: [
      {
        name: 'server'
        properties: {
          image: '${acr.properties.loginServer}/${imageName}:${imageTag}'
          ports: ports
          resources: {
            requests: {
              cpu: cpuCores
              memoryInGB: memoryInGb
            }
          }
          environmentVariables: [
            // ACI's outbound IP can differ from its inbound IP, so derive the announced IP from our own FQDN.
            { name: 'Online__ServerIp', value: 'auto' }
            { name: 'Online__PublicHostname', value: fqdn }
            { name: 'Online__DnsForwardUnknown', value: 'false' }
            { name: 'MULTIPLAYER_LOG_FILE', value: 'none' }
            { name: 'Logging__LogLevel__Default', value: logLevel }
            { name: 'Online__DataDirectory', value: '/data' }
            { name: 'Online__ExternalDnasServer', value: externalDnasServer }
            { name: 'Online__DnasRegion', value: dnasRegion }
          ]
          // Restart the container if it stops answering the patch server's /stats endpoint (same check as the
          // Dockerfile HEALTHCHECK). Generous thresholds: a slow start or a brief stall must not cause a restart loop.
          livenessProbe: {
            exec: {
              command: [ 'bash', '-c', 'exec 3<>/dev/tcp/127.0.0.1/80 && printf "GET /stats HTTP/1.0\\r\\n\\r\\n" >&3 && head -c 12 <&3 | grep -q " 200"' ]
            }
            initialDelaySeconds: 60
            periodSeconds: 30
            timeoutSeconds: 5
            failureThreshold: 5
          }
          volumeMounts: [
            { name: 'data', mountPath: '/data' }
          ]
        }
      }
    ]
    volumes: [
      {
        name: 'data'
        azureFile: {
          shareName: 'socom2-data'
          storageAccountName: storage.name
          storageAccountKey: storage.listKeys().keys[0].value
        }
      }
    ]
  }
  dependsOn: [ dataShare ]
}

output fqdn string = containerGroup.properties.ipAddress.fqdn
output publicIp string = containerGroup.properties.ipAddress.ip
