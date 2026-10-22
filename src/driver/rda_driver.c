/*
 * rda_driver.c - DriverEntry, DriverUnload, dispatch table, globals.
 *
 * Reference parity:
 *  - Service-name-derived control device (any service name -> its own device
 *    identity; %s%d hot-upgrade variants work without reboot).
 *  - DO_DIRECT_IO control device; WDM majors; real DriverUnload.
 *  - IRP_MJ_CLEANUP releases per-handle resources (the reference released on
 *    CLOSE - moved per standard WDM practice, fix F9).
 *  - IRP_MJ_CREATE/READ/WRITE/DEVICE_CONTROL/CLEANUP/CLOSE are owned by the
 *    driver; every other major completes with STATUS_INVALID_DEVICE_REQUEST
 *    through RdaDispatchDefault (the reference left those slots unassigned,
 *    which made them fall into IoInvalidDeviceRequest - same observable
 *    behavior, explicit here).
 *
 * Licensed under the MIT license. See LICENSE.
 */

#include "rda_p.h"

/* Globals. */
PDRIVER_OBJECT g_RdaDriverObject = NULL;
PDEVICE_OBJECT g_RdaControlDevice = NULL;
UNICODE_STRING g_RdaDeviceName;
UNICODE_STRING g_RdaDosName;
RDA_PARAMETERS g_RdaParameters;
ULONG g_RdaDebugLevel = RDA_LEVEL_ERROR;
volatile LONG64 g_RdaGlobalHandle = 0;

static DRIVER_DISPATCH RdaDispatchDefault;

static VOID RdaDriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    RDA_ENTER("DriverUnload");

    /* Tear down in reverse creation order: session engine, filter role,
     * control device. */
    RdaSessionShutdown();
    RdaFilterStop();
    RdaDeleteControlDevice();

    RDA_TRACE(RDA_LEVEL_INFO, "[EPMNtDrv]DriverUnload called"); /* reference string */
    RDA_EXIT("DriverUnload");
}

static NTSTATUS RdaDispatchDefault(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    /* Every unhandled major. The reference drivers left these slots empty
     * which the IO manager treats as invalid-device-request; we complete
     * explicitly for clarity and correct behavior on filter stacks. */
    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    ULONG i;

    RDA_ENTER("DriverEntry");

    g_RdaDriverObject = DriverObject;
    RtlZeroMemory(&g_RdaParameters, sizeof(g_RdaParameters));

    /* Defaults (overridden by Parameters in RdaReadParameters). */
    g_RdaParameters.MaxDisks = RDA_DISK_LIMIT_EPMNTDRV;
    g_RdaParameters.SessionsEnabled = 1;
    g_RdaParameters.IoctlBase = 0;

    status = RdaReadParameters(RegistryPath);
    if (!NT_SUCCESS(status)) {
        /* Parameter read failure is non-fatal: defaults hold. The reference
         * ignored missing keys; missing registry path entirely is fatal. */
        if (status == STATUS_OBJECT_PATH_NOT_FOUND && RegistryPath == NULL) {
            return status;
        }
    }

    status = RdaCreateControlDevice(DriverObject, RegistryPath);
    if (!NT_SUCCESS(status)) {
        RDA_TRACE(RDA_LEVEL_ERROR, "control device create failed 0x%08X", status);
        return status;
    }

    /* Dispatch table: majors we own. */
    DriverObject->MajorFunction[IRP_MJ_CREATE] = RdaDispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_READ] = RdaDispatchRead;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = RdaDispatchWrite;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = RdaDispatchDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = RdaDispatchCleanup;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = RdaDispatchClose;

    /* PnP/Power are handled when running in the filter role (installed as a
     * disk-class upper filter); on the control device they complete
     * invalid-request via the default dispatch. */
    DriverObject->MajorFunction[IRP_MJ_PNP] = RdaDispatchPnp;
    DriverObject->MajorFunction[IRP_MJ_POWER] = RdaDispatchPower;

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        if (DriverObject->MajorFunction[i] == NULL) {
            DriverObject->MajorFunction[i] = RdaDispatchDefault;
        }
    }

    DriverObject->DriverUnload = RdaDriverUnload;

    /* Copy-session engine state (session registry + worker bookkeeping). */
    RdaSessionInit();

    /* Filter role activates only when configured (WinPE deployment: service
     * registered as a disk-class UpperFilter). In the live-OS profile this is
     * a no-op. */
    if (g_RdaParameters.FilterMode != 0) {
        status = RdaFilterStart();
        if (!NT_SUCCESS(status)) {
            RDA_TRACE(RDA_LEVEL_ERROR, "filter role start failed 0x%08X", status);
            RdaSessionShutdown();
            RdaDeleteControlDevice();
            return status;
        }
    }

    RDA_TRACE(RDA_LEVEL_INFO, "[EPMNtDrv]DriverEntry ret,0x%x", STATUS_SUCCESS);
    RDA_EXIT("DriverEntry");
    return STATUS_SUCCESS;
}
