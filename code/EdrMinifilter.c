/*
 * EdrMinifilter.c
 * File system minifilter for file create/write/delete/rename capture.
 */

#include <fltKernel.h>
#include "../inc/EdrDriver.h"

static PFLT_FILTER  s_FilterHandle  = NULL;

// -------------------------------------------------------------------------
// Post-operation callback for IRP_MJ_CREATE
// -------------------------------------------------------------------------
static FLT_POSTOP_CALLBACK_STATUS
EdrPostCreate(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID                CompletionContext,
    _In_    FLT_POST_OPERATION_FLAGS Flags
)
{
    EDR_EVENT_RECORD    record;
    PEDR_FILE_EVENT     ev = &record.Event.File;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    if (!g_Filter.CaptureFile)
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (!NT_SUCCESS(Data->IoStatus.Status))
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (!NT_SUCCESS(FltGetFileNameInformation(
            Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)))
        return FLT_POSTOP_FINISHED_PROCESSING;

    FltParseFileNameInformation(nameInfo);

    RtlZeroMemory(&record, sizeof(record));
    record.RecordSize = sizeof(record);
    record.EventType  = EdrEventTypeFileCreate;

    ev->EventType  = EdrEventTypeFileCreate;
    ev->Timestamp  = EdrCurrentTimestamp();
    ev->ProcessId  = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();

    if (nameInfo->Name.Length > 0)
    {
        ULONG copyChars = min(nameInfo->Name.Length / sizeof(WCHAR), 519);
        RtlCopyMemory(ev->FilePath, nameInfo->Name.Buffer, copyChars * sizeof(WCHAR));
        ev->FilePath[copyChars] = L'\0';
    }

    FltReleaseFileNameInformation(nameInfo);

    InterlockedIncrement64((LONGLONG *)&g_Stats.FileEventsCapture);
    EdrEmitEvent(&record);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// -------------------------------------------------------------------------
// Post-operation callback for IRP_MJ_WRITE
// -------------------------------------------------------------------------
static FLT_POSTOP_CALLBACK_STATUS
EdrPostWrite(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID                CompletionContext,
    _In_    FLT_POST_OPERATION_FLAGS Flags
)
{
    EDR_EVENT_RECORD    record;
    PEDR_FILE_EVENT     ev = &record.Event.File;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    if (!g_Filter.CaptureFile)
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (!NT_SUCCESS(Data->IoStatus.Status))
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (!NT_SUCCESS(FltGetFileNameInformation(
            Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)))
        return FLT_POSTOP_FINISHED_PROCESSING;

    FltParseFileNameInformation(nameInfo);

    RtlZeroMemory(&record, sizeof(record));
    record.RecordSize = sizeof(record);
    record.EventType  = EdrEventTypeFileWrite;

    ev->EventType  = EdrEventTypeFileWrite;
    ev->Timestamp  = EdrCurrentTimestamp();
    ev->ProcessId  = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    ev->FileSize   = (UINT64)Data->IoStatus.Information;

    if (nameInfo->Name.Length > 0)
    {
        ULONG copyChars = min(nameInfo->Name.Length / sizeof(WCHAR), 519);
        RtlCopyMemory(ev->FilePath, nameInfo->Name.Buffer, copyChars * sizeof(WCHAR));
        ev->FilePath[copyChars] = L'\0';
    }

    FltReleaseFileNameInformation(nameInfo);

    InterlockedIncrement64((LONGLONG *)&g_Stats.FileEventsCapture);
    EdrEmitEvent(&record);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// -------------------------------------------------------------------------
// Post-operation for IRP_MJ_SET_INFORMATION (delete / rename)
// -------------------------------------------------------------------------
static FLT_POSTOP_CALLBACK_STATUS
EdrPostSetInfo(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID                CompletionContext,
    _In_    FLT_POST_OPERATION_FLAGS Flags
)
{
    EDR_EVENT_RECORD    record;
    PEDR_FILE_EVENT     ev = &record.Event.File;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    FILE_INFORMATION_CLASS infoClass;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    if (!g_Filter.CaptureFile)
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (!NT_SUCCESS(Data->IoStatus.Status))
        return FLT_POSTOP_FINISHED_PROCESSING;

    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    if (infoClass != FileDispositionInformation &&
        infoClass != FileDispositionInformationEx &&
        infoClass != FileRenameInformation &&
        infoClass != FileRenameInformationEx)
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (!NT_SUCCESS(FltGetFileNameInformation(
            Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)))
        return FLT_POSTOP_FINISHED_PROCESSING;

    FltParseFileNameInformation(nameInfo);

    RtlZeroMemory(&record, sizeof(record));
    record.RecordSize = sizeof(record);

    if (infoClass == FileDispositionInformation || infoClass == FileDispositionInformationEx)
    {
        record.EventType = EdrEventTypeFileDelete;
        ev->EventType    = EdrEventTypeFileDelete;
    }
    else
    {
        record.EventType = EdrEventTypeFileRename;
        ev->EventType    = EdrEventTypeFileRename;
    }

    ev->Timestamp = EdrCurrentTimestamp();
    ev->ProcessId = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();

    if (nameInfo->Name.Length > 0)
    {
        ULONG copyChars = min(nameInfo->Name.Length / sizeof(WCHAR), 519);
        RtlCopyMemory(ev->FilePath, nameInfo->Name.Buffer, copyChars * sizeof(WCHAR));
        ev->FilePath[copyChars] = L'\0';
    }

    FltReleaseFileNameInformation(nameInfo);

    InterlockedIncrement64((LONGLONG *)&g_Stats.FileEventsCapture);
    EdrEmitEvent(&record);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// -------------------------------------------------------------------------
// Minifilter instance setup / teardown (must permit all)
// -------------------------------------------------------------------------
static NTSTATUS
EdrInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    return STATUS_SUCCESS;
}

static NTSTATUS
EdrInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

// -------------------------------------------------------------------------
// Callbacks table
// -------------------------------------------------------------------------
static const FLT_OPERATION_REGISTRATION s_Callbacks[] =
{
    { IRP_MJ_CREATE,          0, NULL, EdrPostCreate   },
    { IRP_MJ_WRITE,           0, NULL, EdrPostWrite    },
    { IRP_MJ_SET_INFORMATION, 0, NULL, EdrPostSetInfo  },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION s_FilterRegistration =
{
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                              // Flags
    NULL,                           // ContextRegistration
    s_Callbacks,
    EdrMinifilterUnregister,        // FilterUnloadCallback
    EdrInstanceSetup,
    EdrInstanceQueryTeardown,
    NULL, NULL, NULL, NULL, NULL, NULL
};

// -------------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------------
NTSTATUS
EdrMinifilterRegister(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(DriverObject);

    status = FltRegisterFilter(DriverObject, &s_FilterRegistration, &s_FilterHandle);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[EDR] FltRegisterFilter failed: 0x%08X\n", status);
        return status;
    }

    status = FltStartFiltering(s_FilterHandle);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[EDR] FltStartFiltering failed: 0x%08X\n", status);
        FltUnregisterFilter(s_FilterHandle);
        s_FilterHandle = NULL;
        return status;
    }

    DbgPrint("[EDR] Minifilter registered.\n");
    return STATUS_SUCCESS;
}

VOID
EdrMinifilterUnregister(VOID)
{
    if (s_FilterHandle)
    {
        FltUnregisterFilter(s_FilterHandle);
        s_FilterHandle = NULL;
        DbgPrint("[EDR] Minifilter unregistered.\n");
    }
}
