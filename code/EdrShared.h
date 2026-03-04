#pragma once

//
// EdrShared.h
// Structures and IOCTLs shared between the kernel driver and user-mode service.
// This header must compile cleanly in both kernel and user mode.
//

#ifdef _KERNEL_MODE
#include <ntddk.h>
#include <wdm.h>
#else
#include <Windows.h>
#include <stdint.h>
typedef unsigned char  UINT8;
typedef unsigned short UINT16;
typedef unsigned long  UINT32;
typedef unsigned long long UINT64;
#endif

#define EDR_DEVICE_NAME     L"\\Device\\EdrCollector"
#define EDR_SYMLINK_NAME    L"\\DosDevices\\EdrCollector"
#define EDR_DEVICE_WIN32    L"\\\\.\\EdrCollector"

// -------------------------------------------------------------------------
// IOCTL codes
// -------------------------------------------------------------------------
#define EDR_IOCTL_BASE              0x8000

#define IOCTL_EDR_GET_STATS \
    CTL_CODE(EDR_IOCTL_BASE, 0x800, METHOD_BUFFERED, FILE_READ_DATA)

#define IOCTL_EDR_SET_FILTER \
    CTL_CODE(EDR_IOCTL_BASE, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_EDR_FLUSH_QUEUE \
    CTL_CODE(EDR_IOCTL_BASE, 0x802, METHOD_BUFFERED, FILE_READ_DATA)

// -------------------------------------------------------------------------
// Event type identifiers
// -------------------------------------------------------------------------
typedef enum _EDR_EVENT_TYPE
{
    EdrEventTypeNetworkConnect  = 1,
    EdrEventTypeNetworkAccept   = 2,
    EdrEventTypeNetworkSend     = 3,
    EdrEventTypeNetworkRecv     = 4,
    EdrEventTypeProcessCreate   = 10,
    EdrEventTypeProcessTerminate = 11,
    EdrEventTypeFileCreate      = 20,
    EdrEventTypeFileWrite       = 21,
    EdrEventTypeFileDelete      = 22,
    EdrEventTypeFileRename      = 23,
} EDR_EVENT_TYPE;

// -------------------------------------------------------------------------
// IP address union (supports IPv4 and IPv6)
// -------------------------------------------------------------------------
typedef struct _EDR_IP_ADDRESS
{
    UINT8   Family;      // AF_INET = 2, AF_INET6 = 23
    UINT8   _pad[3];
    union {
        UINT8  v6[16];
        struct {
            UINT8 _v6pad[12];
            UINT8 v4[4];
        };
    } Addr;
} EDR_IP_ADDRESS;

// -------------------------------------------------------------------------
// Network event  (ingress and egress, TCP and UDP)
// -------------------------------------------------------------------------
#define EDR_DIRECTION_INGRESS   0
#define EDR_DIRECTION_EGRESS    1

typedef struct _EDR_NETWORK_EVENT
{
    UINT64          Timestamp;          // FILETIME (100-ns intervals since 1601)
    EDR_EVENT_TYPE  EventType;
    UINT32          ProcessId;
    UINT32          ThreadId;
    UINT8           Direction;          // EDR_DIRECTION_*
    UINT8           Protocol;           // IPPROTO_TCP=6, IPPROTO_UDP=17
    UINT8           _pad[2];
    EDR_IP_ADDRESS  LocalAddress;
    EDR_IP_ADDRESS  RemoteAddress;
    UINT16          LocalPort;
    UINT16          RemotePort;
    UINT64          BytesTransferred;
    WCHAR           ProcessImagePath[260];
} EDR_NETWORK_EVENT;

// -------------------------------------------------------------------------
// Process event
// -------------------------------------------------------------------------
typedef struct _EDR_PROCESS_EVENT
{
    UINT64          Timestamp;
    EDR_EVENT_TYPE  EventType;          // Create or Terminate
    UINT32          ProcessId;
    UINT32          ParentProcessId;
    UINT32          SessionId;
    UINT32          _pad;
    WCHAR           ImagePath[260];
    WCHAR           CommandLine[1024];
    WCHAR           UserSid[128];       // S-1-5-... string form
} EDR_PROCESS_EVENT;

// -------------------------------------------------------------------------
// File event
// -------------------------------------------------------------------------
typedef struct _EDR_FILE_EVENT
{
    UINT64          Timestamp;
    EDR_EVENT_TYPE  EventType;
    UINT32          ProcessId;
    UINT32          _pad;
    WCHAR           FilePath[520];
    WCHAR           NewFilePath[520];   // populated for rename events only
    UINT64          FileSize;
    UINT8           Md5[16];            // populated for write events when available
} EDR_FILE_EVENT;

// -------------------------------------------------------------------------
// Generic event envelope read from the driver via ReadFile
// -------------------------------------------------------------------------
#define EDR_MAX_EVENT_PAYLOAD   (sizeof(EDR_PROCESS_EVENT))  // largest event

typedef struct _EDR_EVENT_RECORD
{
    UINT32          RecordSize;         // total size including this header
    EDR_EVENT_TYPE  EventType;
    UINT8           _pad[4];
    union {
        EDR_NETWORK_EVENT   Network;
        EDR_PROCESS_EVENT   Process;
        EDR_FILE_EVENT      File;
    } Event;
} EDR_EVENT_RECORD;

// -------------------------------------------------------------------------
// Driver statistics (returned by IOCTL_EDR_GET_STATS)
// -------------------------------------------------------------------------
typedef struct _EDR_DRIVER_STATS
{
    UINT64  EventsQueued;
    UINT64  EventsDequeued;
    UINT64  EventsDropped;             // ring buffer overflows
    UINT64  NetworkEventsCapture;
    UINT64  ProcessEventsCapture;
    UINT64  FileEventsCapture;
    UINT32  QueueDepth;
    UINT32  QueueCapacity;
} EDR_DRIVER_STATS;

// -------------------------------------------------------------------------
// Filter configuration (sent via IOCTL_EDR_SET_FILTER)
// -------------------------------------------------------------------------
typedef struct _EDR_FILTER_CONFIG
{
    UINT8   CaptureNetwork;            // 1 = enabled
    UINT8   CaptureProcess;
    UINT8   CaptureFile;
    UINT8   _pad;
    UINT16  PortFilterCount;           // 0 = capture all ports
    UINT16  PortFilter[64];            // only capture these ports when count > 0
} EDR_FILTER_CONFIG;
