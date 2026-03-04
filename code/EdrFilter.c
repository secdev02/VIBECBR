/*
 * EdrFilter.c
 * Applies EDR_FILTER_CONFIG from user mode to the live g_Filter global
 * consumed by WFP, process notify, and minifilter callbacks.
 */

#include <ntddk.h>
#include "../inc/EdrDriver.h"

EDR_ACTIVE_FILTER g_Filter = {
    .CaptureNetwork = TRUE,
    .CaptureProcess = TRUE,
    .CaptureFile    = TRUE,
    .PortFilterCount = 0
};

VOID
EdrApplyFilterConfig(
    _In_ PEDR_FILTER_CONFIG Config
)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_Filter.Lock, &oldIrql);

    g_Filter.CaptureNetwork = (BOOLEAN)Config->CaptureNetwork;
    g_Filter.CaptureProcess = (BOOLEAN)Config->CaptureProcess;
    g_Filter.CaptureFile    = (BOOLEAN)Config->CaptureFile;

    g_Filter.PortFilterCount = min(Config->PortFilterCount, 64);
    if (g_Filter.PortFilterCount > 0)
    {
        RtlCopyMemory(g_Filter.PortFilter,
                      Config->PortFilter,
                      g_Filter.PortFilterCount * sizeof(UINT16));
    }

    KeReleaseSpinLock(&g_Filter.Lock, oldIrql);

    DbgPrint("[EDR] Filter updated: net=%d proc=%d file=%d ports=%u\n",
             g_Filter.CaptureNetwork,
             g_Filter.CaptureProcess,
             g_Filter.CaptureFile,
             g_Filter.PortFilterCount);
}
