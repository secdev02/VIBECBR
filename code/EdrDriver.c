/*
 * EdrDriver.c
 * Windows Kernel Driver - Entry point, device object, IRP dispatch.
 *
 * Build with WDK. Registers:
 *   - WFP callout for network capture (see EdrWfp.c)
 *   - ETW / PsSetCreateProcessNotifyRoutineEx for process capture (see EdrProcess.c)
 *   - Minifilter for file I/O capture (see EdrMinifilter.c)
 *
 * Events are pushed into a lock-free MPSC ring buffer. User mode reads
 * them via ReadFile on the device handle, or flushes via IOCTL.
 */

#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>
#include "EdrDriver.h"
#include "../shared/EdrShared.h"

// -------------------------------------------------------------------------
// Globals
// -------------------------------------------------------------------------
PDEVICE_OBJECT      g_DeviceObject  = NULL;
UNICODE_STRING      g_DeviceName    = RTL_CONSTANT_STRING(EDR_DEVICE_NAME);
UNICODE_STRING      g_SymlinkName   = RTL_CONSTANT_STRING(EDR_SYMLINK_NAME);

EDR_RING_BUFFER     g_RingBuffer    = {0};
EDR_DRIVER_STATS    g_Stats         = {0};

KEVENT              g_DataAvailable;   // signalled when events are in the ring

// -------------------------------------------------------------------------
// Ring buffer  (MPSC: multiple kernel producers, single user-mode consumer)
// -------------------------------------------------------------------------
NTSTATUS
EdrRingBufferInit(
    _Out_ PEDR_RING_BUFFER Ring,
    _In_  ULONG            CapacityBytes
)
{
    Ring->Buffer = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, CapacityBytes, EDR_POOL_TAG);

    if (!Ring->Buffer)
        return STATUS_INSUFFICIENT_RESOURCES;

    Ring->Capacity  = CapacityBytes;
    Ring->WritePos  = 0;
    Ring->ReadPos   = 0;
    Ring->Dropped   = 0;
    KeInitializeSpinLock(&Ring->Lock);
    return STATUS_SUCCESS;
}

VOID
EdrRingBufferFree(
    _Inout_ PEDR_RING_BUFFER Ring
)
{
    if (Ring->Buffer)
    {
        ExFreePoolWithTag(Ring->Buffer, EDR_POOL_TAG);
        Ring->Buffer = NULL;
    }
}

/*
 * EdrRingBufferWrite
 * Called from any IRQL <= DISPATCH_LEVEL.
 * Writes one event record (with length prefix) into the ring.
 * Returns FALSE if the ring is full and the event was dropped.
 */
BOOLEAN
EdrRingBufferWrite(
    _Inout_ PEDR_RING_BUFFER   Ring,
    _In_    PEDR_EVENT_RECORD  Event
)
{
    KIRQL   oldIrql;
    ULONG   needed;
    ULONG   used;
    ULONG   writeEnd;

    needed = Event->RecordSize;
    if (needed == 0 || needed > Ring->Capacity / 2)
        return FALSE;

    KeAcquireSpinLock(&Ring->Lock, &oldIrql);

    // Compute used space (accounting for wrap)
    used = (Ring->WritePos - Ring->ReadPos + Ring->Capacity) % Ring->Capacity;

    if (used + needed >= Ring->Capacity)
    {
        InterlockedIncrement64((LONGLONG *)&Ring->Dropped);
        KeReleaseSpinLock(&Ring->Lock, oldIrql);
        return FALSE;
    }

    // Linear copy; wrap if needed
    writeEnd = Ring->WritePos + needed;
    if (writeEnd <= Ring->Capacity)
    {
        RtlCopyMemory(Ring->Buffer + Ring->WritePos, Event, needed);
    }
    else
    {
        ULONG firstChunk = Ring->Capacity - Ring->WritePos;
        RtlCopyMemory(Ring->Buffer + Ring->WritePos, Event, firstChunk);
        RtlCopyMemory(Ring->Buffer, (PUCHAR)Event + firstChunk, needed - firstChunk);
    }

    Ring->WritePos = writeEnd % Ring->Capacity;
    KeReleaseSpinLock(&Ring->Lock, oldIrql);

    // Signal user-mode reader
    KeSetEvent(&g_DataAvailable, IO_NO_INCREMENT, FALSE);
    return TRUE;
}

/*
 * EdrRingBufferRead
 * Called from user-mode thread context (IRQL PASSIVE_LEVEL).
 * Copies up to OutSize bytes of event records into OutBuffer.
 * Returns bytes actually written.
 */
ULONG
EdrRingBufferRead(
    _Inout_                    PEDR_RING_BUFFER Ring,
    _Out_writes_bytes_(OutSize) PVOID           OutBuffer,
    _In_                       ULONG            OutSize
)
{
    KIRQL   oldIrql;
    ULONG   avail;
    ULONG   toCopy;

    KeAcquireSpinLock(&Ring->Lock, &oldIrql);

    avail = (Ring->WritePos - Ring->ReadPos + Ring->Capacity) % Ring->Capacity;
    toCopy = min(avail, OutSize);

    if (toCopy == 0)
    {
        KeReleaseSpinLock(&Ring->Lock, oldIrql);
        return 0;
    }

    if (Ring->ReadPos + toCopy <= Ring->Capacity)
    {
        RtlCopyMemory(OutBuffer, Ring->Buffer + Ring->ReadPos, toCopy);
    }
    else
    {
        ULONG firstChunk = Ring->Capacity - Ring->ReadPos;
        RtlCopyMemory(OutBuffer, Ring->Buffer + Ring->ReadPos, firstChunk);
        RtlCopyMemory((PUCHAR)OutBuffer + firstChunk, Ring->Buffer, toCopy - firstChunk);
    }

    Ring->ReadPos = (Ring->ReadPos + toCopy) % Ring->Capacity;
    KeReleaseSpinLock(&Ring->Lock, oldIrql);

    return toCopy;
}

// -------------------------------------------------------------------------
// IRP Dispatch
// -------------------------------------------------------------------------
NTSTATUS
EdrDispatchCreate(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS
EdrDispatchClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*
 * EdrDispatchRead
 * User mode calls ReadFile to drain events from the ring buffer.
 * Blocks (via KeWaitForSingleObject) if the ring is empty.
 */
NTSTATUS
EdrDispatchRead(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
)
{
    PIO_STACK_LOCATION  stackLoc;
    PVOID               outBuf;
    ULONG               outLen;
    ULONG               bytesRead;
    LARGE_INTEGER       timeout;
    NTSTATUS            status;

    UNREFERENCED_PARAMETER(DeviceObject);

    stackLoc = IoGetCurrentIrpStackLocation(Irp);
    outLen   = stackLoc->Parameters.Read.Length;
    outBuf   = Irp->AssociatedIrp.SystemBuffer;

    if (outLen < sizeof(EDR_EVENT_RECORD) || outBuf == NULL)
    {
        Irp->IoStatus.Status      = STATUS_BUFFER_TOO_SMALL;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Wait up to 500ms for data
    timeout.QuadPart = -5000000LL;   // 500 ms in 100-ns units, relative
    status = KeWaitForSingleObject(
        &g_DataAvailable, Executive, KernelMode, FALSE, &timeout);

    bytesRead = EdrRingBufferRead(&g_RingBuffer, outBuf, outLen);

    InterlockedAdd64((LONGLONG *)&g_Stats.EventsDequeued, bytesRead);

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = bytesRead;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS
EdrDispatchIoctl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
)
{
    PIO_STACK_LOCATION  stackLoc;
    ULONG               code;
    NTSTATUS            status = STATUS_INVALID_DEVICE_REQUEST;

    UNREFERENCED_PARAMETER(DeviceObject);

    stackLoc = IoGetCurrentIrpStackLocation(Irp);
    code     = stackLoc->Parameters.DeviceIoControl.IoControlCode;

    switch (code)
    {
    case IOCTL_EDR_GET_STATS:
    {
        ULONG outLen = stackLoc->Parameters.DeviceIoControl.OutputBufferLength;
        if (outLen >= sizeof(EDR_DRIVER_STATS))
        {
            g_Stats.QueueDepth    = (UINT32)((g_RingBuffer.WritePos - g_RingBuffer.ReadPos
                                     + g_RingBuffer.Capacity) % g_RingBuffer.Capacity);
            g_Stats.QueueCapacity = (UINT32)g_RingBuffer.Capacity;
            g_Stats.EventsDropped = g_RingBuffer.Dropped;

            RtlCopyMemory(
                Irp->AssociatedIrp.SystemBuffer,
                &g_Stats,
                sizeof(EDR_DRIVER_STATS));

            Irp->IoStatus.Information = sizeof(EDR_DRIVER_STATS);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_EDR_SET_FILTER:
    {
        ULONG inLen = stackLoc->Parameters.DeviceIoControl.InputBufferLength;
        if (inLen >= sizeof(EDR_FILTER_CONFIG))
        {
            PEDR_FILTER_CONFIG cfg =
                (PEDR_FILTER_CONFIG)Irp->AssociatedIrp.SystemBuffer;
            EdrApplyFilterConfig(cfg);
            Irp->IoStatus.Information = 0;
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_EDR_FLUSH_QUEUE:
        // Reset the read position to match write (discard buffered data)
        g_RingBuffer.ReadPos = g_RingBuffer.WritePos;
        Irp->IoStatus.Information = 0;
        status = STATUS_SUCCESS;
        break;

    default:
        Irp->IoStatus.Information = 0;
        break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// -------------------------------------------------------------------------
// DriverEntry / DriverUnload
// -------------------------------------------------------------------------
VOID
EdrDriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);

    EdrWfpUnregister();
    EdrProcessUnregister();
    EdrMinifilterUnregister();
    EdrRingBufferFree(&g_RingBuffer);

    IoDeleteSymbolicLink(&g_SymlinkName);
    if (g_DeviceObject)
        IoDeleteDevice(g_DeviceObject);

    DbgPrint("[EDR] Driver unloaded.\n");
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[EDR] DriverEntry start.\n");

    // Initialise ring buffer (16 MB)
    status = EdrRingBufferInit(&g_RingBuffer, 16 * 1024 * 1024);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[EDR] Ring buffer init failed: 0x%08X\n", status);
        return status;
    }

    KeInitializeEvent(&g_DataAvailable, SynchronizationEvent, FALSE);

    // Create device object
    status = IoCreateDevice(
        DriverObject,
        0,
        &g_DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[EDR] IoCreateDevice failed: 0x%08X\n", status);
        EdrRingBufferFree(&g_RingBuffer);
        return status;
    }

    status = IoCreateSymbolicLink(&g_SymlinkName, &g_DeviceName);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[EDR] IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(g_DeviceObject);
        EdrRingBufferFree(&g_RingBuffer);
        return status;
    }

    // Hook dispatch routines
    DriverObject->DriverUnload                          = EdrDriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]          = EdrDispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]           = EdrDispatchClose;
    DriverObject->MajorFunction[IRP_MJ_READ]            = EdrDispatchRead;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = EdrDispatchIoctl;

    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    // Register sub-components
    status = EdrWfpRegister(g_DeviceObject);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[EDR] WFP register failed: 0x%08X\n", status);
        goto Cleanup;
    }

    status = EdrProcessRegister();
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[EDR] Process notify register failed: 0x%08X\n", status);
        EdrWfpUnregister();
        goto Cleanup;
    }

    status = EdrMinifilterRegister(DriverObject);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[EDR] Minifilter register failed: 0x%08X\n", status);
        EdrWfpUnregister();
        EdrProcessUnregister();
        goto Cleanup;
    }

    DbgPrint("[EDR] Driver loaded successfully.\n");
    return STATUS_SUCCESS;

Cleanup:
    IoDeleteSymbolicLink(&g_SymlinkName);
    IoDeleteDevice(g_DeviceObject);
    EdrRingBufferFree(&g_RingBuffer);
    return status;
}
