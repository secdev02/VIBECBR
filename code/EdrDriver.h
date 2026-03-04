#pragma once

#include <ntddk.h>
#include <fltKernel.h>
#include "../shared/EdrShared.h"

#define EDR_POOL_TAG    'rdEE'   // 'EEdr' in little-endian

// -------------------------------------------------------------------------
// Ring buffer
// -------------------------------------------------------------------------
typedef struct _EDR_RING_BUFFER
{
    PUCHAR          Buffer;
    ULONG           Capacity;
    volatile ULONG  WritePos;
    volatile ULONG  ReadPos;
    KSPIN_LOCK      Lock;
    UINT64          Dropped;
} EDR_RING_BUFFER, *PEDR_RING_BUFFER;

// -------------------------------------------------------------------------
// Filter config (live copy applied to each sub-system)
// -------------------------------------------------------------------------
typedef struct _EDR_ACTIVE_FILTER
{
    BOOLEAN         CaptureNetwork;
    BOOLEAN         CaptureProcess;
    BOOLEAN         CaptureFile;
    KSPIN_LOCK      Lock;
    UINT16          PortFilter[64];
    UINT16          PortFilterCount;
} EDR_ACTIVE_FILTER, *PEDR_ACTIVE_FILTER;

// -------------------------------------------------------------------------
// Globals declared in EdrDriver.c, consumed by sub-modules
// -------------------------------------------------------------------------
extern EDR_RING_BUFFER      g_RingBuffer;
extern EDR_DRIVER_STATS     g_Stats;
extern KEVENT               g_DataAvailable;
extern EDR_ACTIVE_FILTER    g_Filter;

// -------------------------------------------------------------------------
// Ring buffer API
// -------------------------------------------------------------------------
NTSTATUS    EdrRingBufferInit(_Out_ PEDR_RING_BUFFER Ring, _In_ ULONG CapacityBytes);
VOID        EdrRingBufferFree(_Inout_ PEDR_RING_BUFFER Ring);
BOOLEAN     EdrRingBufferWrite(_Inout_ PEDR_RING_BUFFER Ring, _In_ PEDR_EVENT_RECORD Event);
ULONG       EdrRingBufferRead(_Inout_ PEDR_RING_BUFFER Ring, _Out_writes_bytes_(OutSize) PVOID OutBuffer, _In_ ULONG OutSize);

// -------------------------------------------------------------------------
// Sub-module APIs
// -------------------------------------------------------------------------

// WFP (EdrWfp.c)
NTSTATUS    EdrWfpRegister(_In_ PDEVICE_OBJECT DeviceObject);
VOID        EdrWfpUnregister(VOID);

// Process notify (EdrProcess.c)
NTSTATUS    EdrProcessRegister(VOID);
VOID        EdrProcessUnregister(VOID);

// Minifilter (EdrMinifilter.c)
NTSTATUS    EdrMinifilterRegister(_In_ PDRIVER_OBJECT DriverObject);
VOID        EdrMinifilterUnregister(VOID);

// Filter config
VOID        EdrApplyFilterConfig(_In_ PEDR_FILTER_CONFIG Config);

// -------------------------------------------------------------------------
// Helper: emit an event record into the global ring buffer
// -------------------------------------------------------------------------
__forceinline VOID
EdrEmitEvent(_In_ PEDR_EVENT_RECORD Record)
{
    if (EdrRingBufferWrite(&g_RingBuffer, Record))
        InterlockedIncrement64((LONGLONG *)&g_Stats.EventsQueued);
    else
        InterlockedIncrement64((LONGLONG *)&g_Stats.EventsDropped);
}

// -------------------------------------------------------------------------
// Helper: current FILETIME as UINT64
// -------------------------------------------------------------------------
__forceinline UINT64
EdrCurrentTimestamp(VOID)
{
    LARGE_INTEGER t;
    KeQuerySystemTimePrecise(&t);
    return (UINT64)t.QuadPart;
}
