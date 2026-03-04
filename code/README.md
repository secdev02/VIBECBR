# EDR Telemetry Collector

A dual-layer endpoint telemetry collection system combining a Windows Kernel Driver
(WFP + ETW + minifilter) for raw OS capture with the Carbon Black EDR REST API for
enrichment, batching results to Azure Blob Storage and/or AWS S3.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    KERNEL SPACE                         │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  WFP Callout │  │  ETW / PsSet │  │  Minifilter  │  │
│  │  (Network)   │  │  (Process)   │  │  (File I/O)  │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│         └─────────────────┼─────────────────┘          │
│                           │                             │
│                    ┌──────▼───────┐                     │
│                    │  Event Queue │                     │
│                    │  (lock-free) │                     │
│                    └──────┬───────┘                     │
└───────────────────────────┼─────────────────────────────┘
                            │ DeviceIoControl / ReadFile
┌───────────────────────────┼─────────────────────────────┐
│                    USER SPACE                           │
│                           │                             │
│                    ┌──────▼───────┐                     │
│                    │  Collector   │                     │
│                    │  Service     │                     │
│                    └──────┬───────┘                     │
│                           │                             │
│              ┌────────────┼────────────┐                │
│              │            │            │                │
│       ┌──────▼───┐  ┌─────▼────┐  ┌───▼──────┐         │
│       │ CB EDR   │  │  Batch   │  │  Schema  │         │
│       │ Enricher │  │  Buffer  │  │  Writer  │         │
│       └──────┬───┘  └─────┬────┘  └──────────┘         │
│              └────────────┘                             │
│                           │                             │
│                    ┌──────▼───────┐                     │
│                    │   Uploader   │                     │
│                    │ Azure │  S3  │                     │
│                    └──────────────┘                     │
└─────────────────────────────────────────────────────────┘
```

## Components

| Component | Path | Description |
|-----------|------|-------------|
| Kernel Driver | `driver/` | WFP callout, ETW consumer, minifilter |
| Collector Service | `usermode/` | Ring buffer reader, CB EDR enrichment, batch management |
| Uploader | `uploader/` | Azure Blob + S3 dual upload with retry |
| Shared | `shared/` | IOCTLs, event structs shared across kernel/user |
| Config | `config/` | INI-based configuration |

## Captured Telemetry

### Kernel Layer (raw)
- **Network**: src/dst IP (IPv4+IPv6), src/dst port, protocol (TCP/UDP), direction (ingress/egress), PID, timestamp
- **Process**: create/terminate, PID, PPID, image path, command line, token user
- **File**: create/write/delete/rename, path, file type

### CB EDR Enrichment Layer
All kernel events are enriched with CB EDR facet data:
- `hostname`, `group`, `os_type`, `host_type`
- `process_name`, `process_md5`, `parent_name`, `path_full`
- `username_full`, `hour_of_day`, `day_of_week`
- `digsig_result`, `company_name`, `product_name`
- Alert/watchlist hit correlation

## Environment Variables

### CB EDR
```
CBEDR_SERVER_URL        https://your-cb-server
CBEDR_API_TOKEN         your-api-token
CBEDR_VERIFY_SSL        true|false (default: true)
```

### Azure Blob Storage
```
AZURE_STORAGE_CONNECTION_STRING   your-connection-string
AZURE_STORAGE_CONTAINER           edr-telemetry
```

### AWS S3
```
AWS_ACCESS_KEY_ID        your-key-id
AWS_SECRET_ACCESS_KEY    your-secret-key
AWS_REGION               us-east-1
S3_BUCKET_NAME           edr-telemetry
S3_KEY_PREFIX            collector/
```

### Batch Tuning
```
BATCH_MAX_SIZE_MB        64          # flush when buffer reaches this size
BATCH_MAX_INTERVAL_SEC   300         # flush every N seconds regardless of size
BATCH_COMPRESS           true        # gzip before upload
```

## Build Requirements

- Windows 10/11 SDK + WDK (Windows Driver Kit)
- Visual Studio 2022 with "Desktop development with C++" and "Windows Driver Kit"
- vcpkg with `aws-sdk-cpp` and `azure-storage-blobs-cpp`

## Build

```cmd
# Kernel driver (must build with WDK)
msbuild driver/EdrCollectorDriver.vcxproj /p:Configuration=Release /p:Platform=x64

# User-mode service
msbuild usermode/EdrCollectorService.vcxproj /p:Configuration=Release /p:Platform=x64
```

## Deployment

```cmd
# Install and start driver (requires admin / test signing or EV cert)
sc create EdrCollector type= kernel binPath= "C:\EdrCollector\EdrCollectorDriver.sys"
sc start EdrCollector

# Install user-mode service
sc create EdrCollectorSvc binPath= "C:\EdrCollector\EdrCollectorService.exe" start= auto
sc start EdrCollectorSvc
```

## Blob Naming Convention

Uploaded blobs are named:
```
{prefix}/{hostname}/{YYYY-MM-DD}/{HH}/{timestamp_uuid}.json.gz
```

Example:
```
collector/WORKSTATION-01/2026-03-03/14/20260303T141523Z_a3f9.json.gz
```
