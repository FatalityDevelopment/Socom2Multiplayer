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

@description('Console log level: Debug (full packet hex, useful while testing) or Information.')
@allowed([ 'Debug', 'Information', 'Warning' ])
param logLevel string = 'Debug'

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
  properties: { shareQuota: 1 }
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
          ]
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
