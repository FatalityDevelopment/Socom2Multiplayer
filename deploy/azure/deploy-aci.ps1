<#
.SYNOPSIS
  Build the SOCOM II server image in Azure and run it on Azure Container Instances.

.DESCRIPTION
  1. Creates the resource group and an Azure Container Registry (Basic, admin user on) if missing.
  2. Builds the image IN AZURE with `az acr build` — no local Docker needed.
  3. Deploys main.bicep: one container group with a public IP + DNS label and all TCP/UDP ports.

  Requires the Azure CLI (`az login` first). Re-run it to ship a new build; the same DNS name is kept.

.EXAMPLE
  ./deploy/azure/deploy-aci.ps1 -AcrName socom2acr123 -DnsNameLabel socom2-test
#>
param(
    [Parameter(Mandatory)] [string] $AcrName,        # globally unique, lowercase letters/digits
    [Parameter(Mandatory)] [string] $DnsNameLabel,   # unique within the region
    [string] $ResourceGroup = 'socom2-test-rg',
    [string] $Location      = 'eastus',
    [string] $ImageTag      = $(git rev-parse --short HEAD),
    [ValidateSet('Debug', 'Information', 'Warning')] [string] $LogLevel = 'Debug'
)

$ErrorActionPreference = 'Stop'
$repoRoot   = Resolve-Path (Join-Path $PSScriptRoot '../..')
$projectDir = $repoRoot   # Dockerfile at the repo root builds the server + DnaSDK

function Invoke-Az {
    az @args
    if ($LASTEXITCODE -ne 0) { throw "az $($args -join ' ') failed ($LASTEXITCODE)" }
}

Write-Host "==> Resource group $ResourceGroup ($Location)"
Invoke-Az group create --name $ResourceGroup --location $Location --output none

Write-Host "==> Container registry $AcrName"
az acr show --name $AcrName --resource-group $ResourceGroup --output none 2>$null
if ($LASTEXITCODE -ne 0) {
    Invoke-Az acr create --name $AcrName --resource-group $ResourceGroup --location $Location `
        --sku Basic --admin-enabled true --output none
}

Write-Host "==> Building socom2-server:$ImageTag in ACR (cloud build)"
Invoke-Az acr build --registry $AcrName --image "socom2-server:$ImageTag" --image socom2-server:latest $projectDir

Write-Host "==> Deploying container group"
$out = Invoke-Az deployment group create --resource-group $ResourceGroup `
    --template-file (Join-Path $PSScriptRoot 'main.bicep') `
    --parameters acrName=$AcrName dnsNameLabel=$DnsNameLabel imageTag=$ImageTag logLevel=$LogLevel `
    --query properties.outputs --output json | ConvertFrom-Json

Write-Host ""
Write-Host "Server is up:" -ForegroundColor Green
Write-Host "  FQDN      : $($out.fqdn.value)"
Write-Host "  Public IP : $($out.publicIp.value)"
Write-Host ""
Write-Host "Set the PS2's network settings: Primary DNS = $($out.publicIp.value)"
Write-Host "Logs  : az container logs -g $ResourceGroup -n socom2-server --follow"
Write-Host "Stop  : az container stop -g $ResourceGroup -n socom2-server   (billing stops; start again with 'az container start')"
Write-Host "Remove: az group delete -n $ResourceGroup"
