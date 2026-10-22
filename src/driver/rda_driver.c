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
static DRIVER_DISPATCH RdaDispatchMaster;

static VOID RdaDriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    RDA_ENTER("DriverUnload");

    /* Tear down in reverse creation order: session engine, disk cache,
     * filter role, control device. */
    RdaSessionShutdown();
    RdaDiskCacheShutdown();
    RdaFilterStop();
    RdaDeleteControlDevice();

    RDA_TRACE(RDA_LEVEL_INFO, "[EPMNtDrv]DriverUnload called"); /* reference string */
    RDA_EXIT("DriverUnload");
}

static NTSTATUS RdaDispatchDefault(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    /* Control-device majors we do not own. The reference drivers left these
     * slots empty which the IO manager treats as invalid-device-request; we
     * complete explicitly (same observable behavior). */
    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

/* Control-device major table (reference slot map verified 2026-10-22:
 * EPMNtDrv/EUEDKEPM register CREATE@0x00, CLOSE@0x02 (release), READ@0x03,
 * WRITE@0x04, IOCTL@0x0E, CLEANUP@0x12 (noop in the references; we release
 * at CLEANUP per fix F9), everything else invalid). */
static DRIVER_DISPATCH *const g_RdaControlMajors[] = {
    RdaDispatchCreate,        /* 0x00 IRP_MJ_CREATE */
    RdaDispatchDefault,       /* 0x01 */
    RdaDispatchClose,         /* 0x02 IRP_MJ_CLOSE */
    RdaDispatchRead,          /* 0x03 IRP_MJ_READ */
    RdaDispatchWrite,         /* 0x04 IRP_MJ_WRITE */
    RdaDispatchDefault,       /* 0x05 */
    RdaDispatchDefault,       /* 0x06 */
    RdaDispatchDefault,       /* 0x07 */
    RdaDispatchDefault,       /* 0x08 */
    RdaDispatchDefault,       /* 0x09 */
    RdaDispatchDefault,       /* 0x0A */
    RdaDispatchDefault,       /* 0x0B */
    RdaDispatchDefault,       /* 0x0C */
    RdaDispatchDefault,       /* 0x0D */
    RdaDispatchDeviceControl, /* 0x0E IRP_MJ_DEVICE_CONTROL */
    RdaDispatchDefault,       /* 0x0F */
    RdaDispatchDefault,       /* 0x10 */
    RdaDispatchDefault,       /* 0x11 */
    RdaDispatchCleanup,       /* 0x12 IRP_MJ_CLEANUP (release, fix F9) */
    RdaDispatchDefault,       /* 0x13 */
    RdaDispatchDefault,       /* 0x14 */
    RdaDispatchDefault,       /* 0x15 */
    RdaDispatchDefault,       /* 0x16 */
    RdaDispatchDefault,       /* 0x17 */
    RdaDispatchDefault,       /* 0x18 */
    RdaDispatchDefault,       /* 0x19 */
    RdaDispatchDefault,       /* 0x1A */
    RdaDispatchDefault,       /* 0x1B */
};

static NTSTATUS RdaDispatchMaster(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
    UCHAR major;

    if (DeviceObject != g_RdaControlDevice) {
        /* Filter stacks (and any device created after DriverEntry, e.g. by
         * AddDevice) run the filter dispatch - never the control handlers. */
        return RdaDispatchFilter(DeviceObject, Irp);
    }

    major = IoGetCurrentIrpStackLocation(Irp)->MajorFunction;
    if (major > IRP_MJ_MAXIMUM_FUNCTION) {
        return RdaDispatchDefault(DeviceObject, Irp);
    }
    return g_RdaControlMajors[major](DeviceObject, Irp);
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

    /* G11 architecture fix (reference parity - the reference installs ONE
     * master dispatcher on ALL 28 majors, FUN_000120c4, and routes on the
     * device: DeviceType 0x800C -> control protocol, else -> filter path).
     * A single control-side table shared by the whole DriverObject is WRONG
     * for a driver that also owns filter stacks. The master guarantees
     * control handlers only ever see the control device. */
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = RdaDispatchMaster;
    }

    DriverObject->DriverUnload = RdaDriverUnload;

    /* Copy-session engine state (session registry + worker bookkeeping) and
     * the per-disk target cache (session/direct/RRWR resolution). */
    RdaSessionInit();
    RdaDiskCacheInit();

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
