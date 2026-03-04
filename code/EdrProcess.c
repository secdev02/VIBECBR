/*
 * EdrProcess.c
 * PsSetCreateProcessNotifyRoutineEx callback for process create/terminate capture.
 */

#include <ntddk.h>
#include "../inc/EdrDriver.h"

static BOOLEAN s_ProcessNotifyRegistered = FALSE;

static VOID
EdrProcessNotifyCallback(
    _Inout_ PEPROCESS           Process,
    _In_    HANDLE              ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    EDR_EVENT_RECORD    record;
    PEDR_PROCESS_EVENT  ev = &record.Event.Process;

    UNREFERENCED_PARAMETER(Process);

    if (!g_Filter.CaptureProcess)
        return;

    RtlZeroMemory(&record, sizeof(record));
    record.RecordSize = sizeof(record);
    ev->Timestamp     = EdrCurrentTimestamp();
    ev->ProcessId     = (UINT32)(ULONG_PTR)ProcessId;

    if (CreateInfo != NULL)
    {
        // Process create
        record.EventType  = EdrEventTypeProcessCreate;
        ev->EventType     = EdrEventTypeProcessCreate;
        ev->ParentProcessId = (UINT32)(ULONG_PTR)CreateInfo->ParentProcessId;
        ev->SessionId       = CreateInfo->SessionId;

        if (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Length > 0)
        {
            ULONG copyChars = min(
                CreateInfo->ImageFileName->Length / sizeof(WCHAR), 259);
            RtlCopyMemory(ev->ImagePath,
                          CreateInfo->ImageFileName->Buffer,
                          copyChars * sizeof(WCHAR));
            ev->ImagePath[copyChars] = L'\0';
        }

        if (CreateInfo->CommandLine && CreateInfo->CommandLine->Length > 0)
        {
            ULONG copyChars = min(
                CreateInfo->CommandLine->Length / sizeof(WCHAR), 1023);
            RtlCopyMemory(ev->CommandLine,
                          CreateInfo->CommandLine->Buffer,
                          copyChars * sizeof(WCHAR));
            ev->CommandLine[copyChars] = L'\0';
        }
    }
    else
    {
        // Process terminate
        record.EventType = EdrEventTypeProcessTerminate;
        ev->EventType    = EdrEventTypeProcessTerminate;
    }

    InterlockedIncrement64((LONGLONG *)&g_Stats.ProcessEventsCapture);
    EdrEmitEvent(&record);
}

NTSTATUS
EdrProcessRegister(VOID)
{
    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(
        EdrProcessNotifyCallback, FALSE);

    if (NT_SUCCESS(status))
    {
        s_ProcessNotifyRegistered = TRUE;
        DbgPrint("[EDR] Process notify registered.\n");
    }
    else
    {
        DbgPrint("[EDR] PsSetCreateProcessNotifyRoutineEx failed: 0x%08X\n", status);
    }
    return status;
}

VOID
EdrProcessUnregister(VOID)
{
    if (s_ProcessNotifyRegistered)
    {
        PsSetCreateProcessNotifyRoutineEx(EdrProcessNotifyCallback, TRUE);
        s_ProcessNotifyRegistered = FALSE;
        DbgPrint("[EDR] Process notify unregistered.\n");
    }
}
