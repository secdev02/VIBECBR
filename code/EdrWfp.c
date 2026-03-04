/*
 * EdrWfp.c
 * Windows Filtering Platform callout for network event capture.
 *
 * Registers callouts at:
 *   FWPM_LAYER_ALE_CONNECT_V4   - outbound TCP connections (IPv4)
 *   FWPM_LAYER_ALE_CONNECT_V6   - outbound TCP connections (IPv6)
 *   FWPM_LAYER_ALE_RECV_ACCEPT_V4 - inbound accepted connections (IPv4)
 *   FWPM_LAYER_ALE_RECV_ACCEPT_V6 - inbound accepted connections (IPv6)
 *   FWPM_LAYER_DATAGRAM_DATA_V4   - UDP datagrams (IPv4)
 *   FWPM_LAYER_DATAGRAM_DATA_V6   - UDP datagrams (IPv6)
 *
 * Per-event records are pushed to the global ring buffer via EdrEmitEvent().
 */

#include <ntddk.h>
#include <fwpmk.h>
#include <fwpsk.h>
#include <mstcpip.h>
#include "../inc/EdrDriver.h"

// -------------------------------------------------------------------------
// Callout GUIDs  (generate fresh GUIDs for production builds)
// -------------------------------------------------------------------------
DEFINE_GUID(GUID_EDR_CALLOUT_CONNECT_V4,
    0xA1B2C3D4, 0x0001, 0x0001, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x01);

DEFINE_GUID(GUID_EDR_CALLOUT_CONNECT_V6,
    0xA1B2C3D4, 0x0001, 0x0002, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x02);

DEFINE_GUID(GUID_EDR_CALLOUT_ACCEPT_V4,
    0xA1B2C3D4, 0x0001, 0x0003, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x03);

DEFINE_GUID(GUID_EDR_CALLOUT_ACCEPT_V6,
    0xA1B2C3D4, 0x0001, 0x0004, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x04);

DEFINE_GUID(GUID_EDR_CALLOUT_DATAGRAM_V4,
    0xA1B2C3D4, 0x0001, 0x0005, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x05);

DEFINE_GUID(GUID_EDR_CALLOUT_DATAGRAM_V6,
    0xA1B2C3D4, 0x0001, 0x0006, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x06);

DEFINE_GUID(GUID_EDR_SUBLAYER,
    0xA1B2C3D4, 0x0001, 0x0010, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x10);

// -------------------------------------------------------------------------
// Registered callout IDs (for deregistration)
// -------------------------------------------------------------------------
static UINT32   s_CalloutIdConnectV4   = 0;
static UINT32   s_CalloutIdConnectV6   = 0;
static UINT32   s_CalloutIdAcceptV4    = 0;
static UINT32   s_CalloutIdAcceptV6    = 0;
static UINT32   s_CalloutIdDatagramV4  = 0;
static UINT32   s_CalloutIdDatagramV6  = 0;

static HANDLE   s_EngineHandle         = NULL;
static BOOLEAN  s_WfpRegistered        = FALSE;

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------
static VOID
EdrFillIpV4(
    _Out_ PEDR_IP_ADDRESS  Out,
    _In_  UINT32           Addr   // network byte order
)
{
    Out->Family = 2;  // AF_INET
    RtlZeroMemory(Out->Addr.v6, 12);
    // Convert to dotted-quad in v4[0..3]
    Out->Addr.v4[0] = (UINT8)((Addr >> 0)  & 0xFF);
    Out->Addr.v4[1] = (UINT8)((Addr >> 8)  & 0xFF);
    Out->Addr.v4[2] = (UINT8)((Addr >> 16) & 0xFF);
    Out->Addr.v4[3] = (UINT8)((Addr >> 24) & 0xFF);
}

static VOID
EdrFillIpV6(
    _Out_ PEDR_IP_ADDRESS  Out,
    _In_  const UINT8      Addr[16]
)
{
    Out->Family = 23;  // AF_INET6
    RtlCopyMemory(Out->Addr.v6, Addr, 16);
}

static VOID
EdrGetProcessImagePath(
    _In_  UINT32  Pid,
    _Out_writes_(260) PWCHAR PathOut
)
{
    PEPROCESS   process;
    NTSTATUS    status;
    PUNICODE_STRING imageName = NULL;

    PathOut[0] = L'\0';
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &process);
    if (!NT_SUCCESS(status))
        return;

    status = SeLocateProcessImageName(process, &imageName);
    if (NT_SUCCESS(status) && imageName && imageName->Length > 0)
    {
        ULONG copyChars = min(imageName->Length / sizeof(WCHAR), 259);
        RtlCopyMemory(PathOut, imageName->Buffer, copyChars * sizeof(WCHAR));
        PathOut[copyChars] = L'\0';
        ExFreePool(imageName);
    }
    ObDereferenceObject(process);
}

// -------------------------------------------------------------------------
// Core classify function - builds and emits the network event
// -------------------------------------------------------------------------
static VOID
EdrNetworkClassify(
    _In_    const FWPS_INCOMING_VALUES0          *InValues,
    _In_    const FWPS_INCOMING_METADATA_VALUES0 *MetaValues,
    _In_    UINT8                                 Protocol,
    _In_    UINT8                                 Direction,
    _In_    BOOLEAN                               IsV6,
    _Inout_ FWPS_CLASSIFY_OUT0                   *ClassifyOut
)
{
    EDR_EVENT_RECORD    record;
    PEDR_NETWORK_EVENT  ev = &record.Event.Network;
    UINT32              pid;

    ClassifyOut->actionType = FWP_ACTION_PERMIT;
    ClassifyOut->rights    &= ~FWPS_RIGHT_ACTION_WRITE;

    if (!g_Filter.CaptureNetwork)
        return;

    RtlZeroMemory(&record, sizeof(record));

    record.RecordSize  = sizeof(record);
    record.EventType   = (Direction == EDR_DIRECTION_EGRESS)
                         ? EdrEventTypeNetworkConnect
                         : EdrEventTypeNetworkAccept;

    ev->Timestamp   = EdrCurrentTimestamp();
    ev->Direction   = Direction;
    ev->Protocol    = Protocol;
    ev->EventType   = record.EventType;

    // Extract PID
    if (FWPS_IS_METADATA_FIELD_PRESENT(MetaValues, FWPS_METADATA_FIELD_PROCESS_ID))
        pid = (UINT32)MetaValues->processId;
    else
        pid = 0;

    ev->ProcessId = pid;
    EdrGetProcessImagePath(pid, ev->ProcessImagePath);

    if (!IsV6)
    {
        EdrFillIpV4(&ev->LocalAddress,
            InValues->incomingValue[FWPS_FIELD_ALE_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32);
        EdrFillIpV4(&ev->RemoteAddress,
            InValues->incomingValue[FWPS_FIELD_ALE_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32);
        ev->LocalPort  = RtlUshortByteSwap(
            InValues->incomingValue[FWPS_FIELD_ALE_CONNECT_V4_IP_LOCAL_PORT].value.uint16);
        ev->RemotePort = RtlUshortByteSwap(
            InValues->incomingValue[FWPS_FIELD_ALE_CONNECT_V4_IP_REMOTE_PORT].value.uint16);
    }
    else
    {
        EdrFillIpV6(&ev->LocalAddress,
            InValues->incomingValue[FWPS_FIELD_ALE_CONNECT_V6_IP_LOCAL_ADDRESS].value.byteArray16->byteArray16);
        EdrFillIpV6(&ev->RemoteAddress,
            InValues->incomingValue[FWPS_FIELD_ALE_CONNECT_V6_IP_REMOTE_ADDRESS].value.byteArray16->byteArray16);
        ev->LocalPort  = RtlUshortByteSwap(
            InValues->incomingValue[FWPS_FIELD_ALE_CONNECT_V6_IP_LOCAL_PORT].value.uint16);
        ev->RemotePort = RtlUshortByteSwap(
            InValues->incomingValue[FWPS_FIELD_ALE_CONNECT_V6_IP_REMOTE_PORT].value.uint16);
    }

    // Port filter check
    if (g_Filter.PortFilterCount > 0)
    {
        BOOLEAN match = FALSE;
        for (UINT16 i = 0; i < g_Filter.PortFilterCount; i++)
        {
            if (g_Filter.PortFilter[i] == ev->LocalPort ||
                g_Filter.PortFilter[i] == ev->RemotePort)
            {
                match = TRUE;
                break;
            }
        }
        if (!match)
            return;
    }

    InterlockedIncrement64((LONGLONG *)&g_Stats.NetworkEventsCapture);
    EdrEmitEvent(&record);
}

// -------------------------------------------------------------------------
// Per-layer classify callbacks
// -------------------------------------------------------------------------
static VOID NTAPI
EdrClassifyConnectV4(
    _In_        const FWPS_INCOMING_VALUES0          *InValues,
    _In_        const FWPS_INCOMING_METADATA_VALUES0 *MetaValues,
    _Inout_opt_ void                                 *LayerData,
    _In_opt_    const void                           *ClassifyContext,
    _In_        const FWPS_FILTER3                   *Filter,
    _In_        UINT64                                FlowContext,
    _Inout_     FWPS_CLASSIFY_OUT0                   *ClassifyOut
)
{
    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);
    EdrNetworkClassify(InValues, MetaValues, IPPROTO_TCP,
                       EDR_DIRECTION_EGRESS, FALSE, ClassifyOut);
}

static VOID NTAPI
EdrClassifyConnectV6(
    _In_        const FWPS_INCOMING_VALUES0          *InValues,
    _In_        const FWPS_INCOMING_METADATA_VALUES0 *MetaValues,
    _Inout_opt_ void                                 *LayerData,
    _In_opt_    const void                           *ClassifyContext,
    _In_        const FWPS_FILTER3                   *Filter,
    _In_        UINT64                                FlowContext,
    _Inout_     FWPS_CLASSIFY_OUT0                   *ClassifyOut
)
{
    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);
    EdrNetworkClassify(InValues, MetaValues, IPPROTO_TCP,
                       EDR_DIRECTION_EGRESS, TRUE, ClassifyOut);
}

static VOID NTAPI
EdrClassifyAcceptV4(
    _In_        const FWPS_INCOMING_VALUES0          *InValues,
    _In_        const FWPS_INCOMING_METADATA_VALUES0 *MetaValues,
    _Inout_opt_ void                                 *LayerData,
    _In_opt_    const void                           *ClassifyContext,
    _In_        const FWPS_FILTER3                   *Filter,
    _In_        UINT64                                FlowContext,
    _Inout_     FWPS_CLASSIFY_OUT0                   *ClassifyOut
)
{
    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);
    EdrNetworkClassify(InValues, MetaValues, IPPROTO_TCP,
                       EDR_DIRECTION_INGRESS, FALSE, ClassifyOut);
}

static VOID NTAPI
EdrClassifyAcceptV6(
    _In_        const FWPS_INCOMING_VALUES0          *InValues,
    _In_        const FWPS_INCOMING_METADATA_VALUES0 *MetaValues,
    _Inout_opt_ void                                 *LayerData,
    _In_opt_    const void                           *ClassifyContext,
    _In_        const FWPS_FILTER3                   *Filter,
    _In_        UINT64                                FlowContext,
    _Inout_     FWPS_CLASSIFY_OUT0                   *ClassifyOut
)
{
    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);
    EdrNetworkClassify(InValues, MetaValues, IPPROTO_TCP,
                       EDR_DIRECTION_INGRESS, TRUE, ClassifyOut);
}

static VOID NTAPI
EdrClassifyDatagramV4(
    _In_        const FWPS_INCOMING_VALUES0          *InValues,
    _In_        const FWPS_INCOMING_METADATA_VALUES0 *MetaValues,
    _Inout_opt_ void                                 *LayerData,
    _In_opt_    const void                           *ClassifyContext,
    _In_        const FWPS_FILTER3                   *Filter,
    _In_        UINT64                                FlowContext,
    _Inout_     FWPS_CLASSIFY_OUT0                   *ClassifyOut
)
{
    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);
    UINT8 dir = (InValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION].value.uint32
                 == FWP_DIRECTION_OUTBOUND)
                ? EDR_DIRECTION_EGRESS : EDR_DIRECTION_INGRESS;
    EdrNetworkClassify(InValues, MetaValues, IPPROTO_UDP, dir, FALSE, ClassifyOut);
}

static VOID NTAPI
EdrClassifyDatagramV6(
    _In_        const FWPS_INCOMING_VALUES0          *InValues,
    _In_        const FWPS_INCOMING_METADATA_VALUES0 *MetaValues,
    _Inout_opt_ void                                 *LayerData,
    _In_opt_    const void                           *ClassifyContext,
    _In_        const FWPS_FILTER3                   *Filter,
    _In_        UINT64                                FlowContext,
    _Inout_     FWPS_CLASSIFY_OUT0                   *ClassifyOut
)
{
    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);
    UINT8 dir = (InValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_DIRECTION].value.uint32
                 == FWP_DIRECTION_OUTBOUND)
                ? EDR_DIRECTION_EGRESS : EDR_DIRECTION_INGRESS;
    EdrNetworkClassify(InValues, MetaValues, IPPROTO_UDP, dir, TRUE, ClassifyOut);
}

static NTSTATUS NTAPI
EdrNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE  NotifyType,
    _In_ const GUID               *FilterKey,
    _Inout_ FWPS_FILTER3          *Filter
)
{
    UNREFERENCED_PARAMETER(NotifyType);
    UNREFERENCED_PARAMETER(FilterKey);
    UNREFERENCED_PARAMETER(Filter);
    return STATUS_SUCCESS;
}

// -------------------------------------------------------------------------
// Registration helpers
// -------------------------------------------------------------------------
static NTSTATUS
EdrWfpAddCallout(
    _In_  PDEVICE_OBJECT    DeviceObject,
    _In_  const GUID       *CalloutKey,
    _In_  FWPS_CALLOUT_CLASSIFY_FN3  ClassifyFn,
    _Out_ UINT32           *CalloutId
)
{
    FWPS_CALLOUT3 callout = {0};
    callout.calloutKey          = *CalloutKey;
    callout.classifyFn          = ClassifyFn;
    callout.notifyFn            = EdrNotify;
    callout.flowDeleteFn        = NULL;
    return FwpsCalloutRegister3(DeviceObject, &callout, CalloutId);
}

static NTSTATUS
EdrWfpAddFilter(
    _In_ HANDLE          EngineHandle,
    _In_ const GUID     *LayerKey,
    _In_ const GUID     *CalloutKey,
    _In_ const WCHAR    *FilterName
)
{
    FWPM_FILTER0        filter  = {0};
    FWPM_FILTER_CONDITION0 cond = {0};   // no conditions = match all
    UNICODE_STRING      name;

    RtlInitUnicodeString(&name, FilterName);

    filter.displayData.name         = name.Buffer;
    filter.layerKey                 = *LayerKey;
    filter.action.type              = FWP_ACTION_CALLOUT_INSPECTION;
    filter.action.calloutKey        = *CalloutKey;
    filter.subLayerKey              = GUID_EDR_SUBLAYER;
    filter.weight.type              = FWP_EMPTY;
    filter.numFilterConditions      = 0;
    filter.filterCondition          = NULL;

    return FwpmFilterAdd0(EngineHandle, &filter, NULL, NULL);
}

// -------------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------------
NTSTATUS
EdrWfpRegister(
    _In_ PDEVICE_OBJECT DeviceObject
)
{
    NTSTATUS    status;
    FWPM_SESSION0 session = {0};
    FWPM_SUBLAYER0 sublayer = {0};

    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &s_EngineHandle);
    if (!NT_SUCCESS(status))
        return status;

    status = FwpmTransactionBegin0(s_EngineHandle, 0);
    if (!NT_SUCCESS(status)) goto Fail;

    // Add sublayer
    sublayer.subLayerKey = GUID_EDR_SUBLAYER;
    sublayer.weight      = 0x8000;   // mid-range weight
    status = FwpmSubLayerAdd0(s_EngineHandle, &sublayer, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) goto Rollback;

    // Register callouts with the driver
    status = EdrWfpAddCallout(DeviceObject, &GUID_EDR_CALLOUT_CONNECT_V4,
                              EdrClassifyConnectV4, &s_CalloutIdConnectV4);
    if (!NT_SUCCESS(status)) goto Rollback;

    status = EdrWfpAddCallout(DeviceObject, &GUID_EDR_CALLOUT_CONNECT_V6,
                              EdrClassifyConnectV6, &s_CalloutIdConnectV6);
    if (!NT_SUCCESS(status)) goto Rollback;

    status = EdrWfpAddCallout(DeviceObject, &GUID_EDR_CALLOUT_ACCEPT_V4,
                              EdrClassifyAcceptV4, &s_CalloutIdAcceptV4);
    if (!NT_SUCCESS(status)) goto Rollback;

    status = EdrWfpAddCallout(DeviceObject, &GUID_EDR_CALLOUT_ACCEPT_V6,
                              EdrClassifyAcceptV6, &s_CalloutIdAcceptV6);
    if (!NT_SUCCESS(status)) goto Rollback;

    status = EdrWfpAddCallout(DeviceObject, &GUID_EDR_CALLOUT_DATAGRAM_V4,
                              EdrClassifyDatagramV4, &s_CalloutIdDatagramV4);
    if (!NT_SUCCESS(status)) goto Rollback;

    status = EdrWfpAddCallout(DeviceObject, &GUID_EDR_CALLOUT_DATAGRAM_V6,
                              EdrClassifyDatagramV6, &s_CalloutIdDatagramV6);
    if (!NT_SUCCESS(status)) goto Rollback;

    // Add filters to engine layers
    EdrWfpAddFilter(s_EngineHandle, &FWPM_LAYER_ALE_CONNECT_V4,
                    &GUID_EDR_CALLOUT_CONNECT_V4,   L"EdrConnectV4");
    EdrWfpAddFilter(s_EngineHandle, &FWPM_LAYER_ALE_CONNECT_V6,
                    &GUID_EDR_CALLOUT_CONNECT_V6,   L"EdrConnectV6");
    EdrWfpAddFilter(s_EngineHandle, &FWPM_LAYER_ALE_RECV_ACCEPT_V4,
                    &GUID_EDR_CALLOUT_ACCEPT_V4,    L"EdrAcceptV4");
    EdrWfpAddFilter(s_EngineHandle, &FWPM_LAYER_ALE_RECV_ACCEPT_V6,
                    &GUID_EDR_CALLOUT_ACCEPT_V6,    L"EdrAcceptV6");
    EdrWfpAddFilter(s_EngineHandle, &FWPM_LAYER_DATAGRAM_DATA_V4,
                    &GUID_EDR_CALLOUT_DATAGRAM_V4,  L"EdrDatagramV4");
    EdrWfpAddFilter(s_EngineHandle, &FWPM_LAYER_DATAGRAM_DATA_V6,
                    &GUID_EDR_CALLOUT_DATAGRAM_V6,  L"EdrDatagramV6");

    status = FwpmTransactionCommit0(s_EngineHandle);
    if (!NT_SUCCESS(status)) goto Fail;

    s_WfpRegistered = TRUE;
    DbgPrint("[EDR] WFP callouts registered.\n");
    return STATUS_SUCCESS;

Rollback:
    FwpmTransactionAbort0(s_EngineHandle);
Fail:
    FwpmEngineClose0(s_EngineHandle);
    s_EngineHandle = NULL;
    return status;
}

VOID
EdrWfpUnregister(VOID)
{
    if (!s_WfpRegistered)
        return;

    if (s_CalloutIdConnectV4)  FwpsCalloutUnregisterById0(s_CalloutIdConnectV4);
    if (s_CalloutIdConnectV6)  FwpsCalloutUnregisterById0(s_CalloutIdConnectV6);
    if (s_CalloutIdAcceptV4)   FwpsCalloutUnregisterById0(s_CalloutIdAcceptV4);
    if (s_CalloutIdAcceptV6)   FwpsCalloutUnregisterById0(s_CalloutIdAcceptV6);
    if (s_CalloutIdDatagramV4) FwpsCalloutUnregisterById0(s_CalloutIdDatagramV4);
    if (s_CalloutIdDatagramV6) FwpsCalloutUnregisterById0(s_CalloutIdDatagramV6);

    if (s_EngineHandle)
    {
        FwpmEngineClose0(s_EngineHandle);
        s_EngineHandle = NULL;
    }

    s_WfpRegistered = FALSE;
    DbgPrint("[EDR] WFP callouts unregistered.\n");
}
