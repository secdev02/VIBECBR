# deploy.ps1
# Deploy and configure the EDR Telemetry Collector
# Must be run as Administrator with test signing enabled (dev) or EV certificate (prod)
#
# Usage:
#   .\deploy.ps1 -Action Install   -BinDir "C:\EdrCollector"
#   .\deploy.ps1 -Action Uninstall
#   .\deploy.ps1 -Action Start
#   .\deploy.ps1 -Action Stop
#   .\deploy.ps1 -Action Status

param(
    [ValidateSet("Install","Uninstall","Start","Stop","Status","SetEnv")]
    [string]$Action = "Status",

    [string]$BinDir = "C:\EdrCollector",

    # CB EDR
    [string]$CbEdrServerUrl  = "",
    [string]$CbEdrApiToken   = "",
    [string]$CbEdrVerifySsl  = "true",

    # Azure
    [string]$AzureConnectionString = "",
    [string]$AzureContainer        = "edr-telemetry",

    # AWS S3
    [string]$AwsAccessKeyId     = "",
    [string]$AwsSecretAccessKey = "",
    [string]$AwsRegion          = "us-east-1",
    [string]$S3BucketName       = "",
    [string]$S3KeyPrefix        = "collector/",

    # Batch
    [int]$BatchMaxSizeMb      = 64,
    [int]$BatchMaxIntervalSec = 300,
    [string]$BatchCompress    = "true"
)

$ErrorActionPreference = "Stop"

$DriverName  = "EdrCollector"
$ServiceName = "EdrCollectorSvc"
$DriverSys   = Join-Path $BinDir "EdrCollectorDriver.sys"
$ServiceExe  = Join-Path $BinDir "EdrCollectorService.exe"

function Write-Step([string]$msg) {
    Write-Host "[EDR] $msg" -ForegroundColor Cyan
}

function Assert-Admin {
    $current = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run as Administrator."
    }
}

function Set-EnvironmentVariables {
    Write-Step "Setting environment variables for service account..."

    $vars = @{
        "CBEDR_SERVER_URL"                = $CbEdrServerUrl
        "CBEDR_API_TOKEN"                 = $CbEdrApiToken
        "CBEDR_VERIFY_SSL"                = $CbEdrVerifySsl
        "AZURE_STORAGE_CONNECTION_STRING" = $AzureConnectionString
        "AZURE_STORAGE_CONTAINER"         = $AzureContainer
        "AWS_ACCESS_KEY_ID"               = $AwsAccessKeyId
        "AWS_SECRET_ACCESS_KEY"           = $AwsSecretAccessKey
        "AWS_REGION"                      = $AwsRegion
        "S3_BUCKET_NAME"                  = $S3BucketName
        "S3_KEY_PREFIX"                   = $S3KeyPrefix
        "BATCH_MAX_SIZE_MB"               = [string]$BatchMaxSizeMb
        "BATCH_MAX_INTERVAL_SEC"          = [string]$BatchMaxIntervalSec
        "BATCH_COMPRESS"                  = $BatchCompress
    }

    foreach ($kv in $vars.GetEnumerator()) {
        if ($kv.Value -ne "") {
            [Environment]::SetEnvironmentVariable(
                $kv.Key, $kv.Value,
                [EnvironmentVariableTarget]::Machine)
            Write-Host "  Set $($kv.Key)"
        }
    }

    Write-Host ""
    Write-Host "NOTE: Sensitive values (tokens, keys) are stored as Machine-scope" -ForegroundColor Yellow
    Write-Host "environment variables. Consider using DPAPI or a secrets vault" -ForegroundColor Yellow
    Write-Host "for production deployments." -ForegroundColor Yellow
}

function Install-Driver {
    Write-Step "Installing kernel driver: $DriverName"

    if (-not (Test-Path $DriverSys)) {
        throw "Driver binary not found: $DriverSys"
    }

    $existing = Get-Service -Name $DriverName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  Driver service already exists, skipping creation."
        return
    }

    & sc.exe create $DriverName `
        type=  kernel `
        binPath= $DriverSys `
        start=  demand `
        DisplayName= "EDR Telemetry Collector Driver"

    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe create failed for driver (exit $LASTEXITCODE)"
    }

    Write-Host "  Driver service created."
}

function Install-Service {
    Write-Step "Installing user-mode service: $ServiceName"

    if (-not (Test-Path $ServiceExe)) {
        throw "Service binary not found: $ServiceExe"
    }

    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  Service already exists, skipping creation."
        return
    }

    & sc.exe create $ServiceName `
        binPath=  $ServiceExe `
        start=    auto `
        type=     own `
        DisplayName= "EDR Telemetry Collector Service"

    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe create failed for service (exit $LASTEXITCODE)"
    }

    # Set description
    & sc.exe description $ServiceName "Captures kernel telemetry and uploads to Azure/S3"

    Write-Host "  Service created."
}

function Start-Components {
    Write-Step "Starting driver..."
    & sc.exe start $DriverName
    Start-Sleep -Seconds 1

    Write-Step "Starting service..."
    & sc.exe start $ServiceName
    Start-Sleep -Seconds 2

    Show-Status
}

function Stop-Components {
    Write-Step "Stopping service..."
    & sc.exe stop $ServiceName
    Start-Sleep -Seconds 2

    Write-Step "Stopping driver..."
    & sc.exe stop $DriverName
}

function Uninstall-Components {
    Stop-Components

    Write-Step "Removing service..."
    & sc.exe delete $ServiceName

    Write-Step "Removing driver..."
    & sc.exe delete $DriverName
}

function Show-Status {
    Write-Step "Component status:"

    foreach ($name in @($DriverName, $ServiceName)) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($svc) {
            $color = if ($svc.Status -eq "Running") { "Green" } else { "Yellow" }
            Write-Host ("  {0,-30} {1}" -f $name, $svc.Status) -ForegroundColor $color
        } else {
            Write-Host ("  {0,-30} Not installed" -f $name) -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Step "Environment variables:"
    $keys = @(
        "CBEDR_SERVER_URL", "CBEDR_API_TOKEN",
        "AZURE_STORAGE_CONTAINER", "S3_BUCKET_NAME", "AWS_REGION",
        "BATCH_MAX_SIZE_MB", "BATCH_MAX_INTERVAL_SEC"
    )
    foreach ($k in $keys) {
        $v = [Environment]::GetEnvironmentVariable($k, "Machine")
        if ($k -match "TOKEN|KEY|SECRET|CONNECTION") {
            $v = if ($v) { "***set***" } else { "(not set)" }
        } elseif (-not $v) {
            $v = "(not set)"
        }
        Write-Host ("  {0,-40} {1}" -f $k, $v)
    }
}

# -------------------------------------------------------------------------
# Entrypoint
# -------------------------------------------------------------------------
Assert-Admin

switch ($Action) {
    "Install" {
        if (-not (Test-Path $BinDir)) {
            New-Item -ItemType Directory -Path $BinDir | Out-Null
        }
        Set-EnvironmentVariables
        Install-Driver
        Install-Service
        Write-Step "Installation complete. Run with -Action Start to begin collecting."
    }
    "Uninstall" { Uninstall-Components }
    "Start"     { Start-Components }
    "Stop"      { Stop-Components }
    "Status"    { Show-Status }
    "SetEnv"    { Set-EnvironmentVariables }
}
