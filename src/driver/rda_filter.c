/*
 * rda_filter.c - PnP disk-class upper-filter role (EUDCPEPM merge, WinPE).
 *
 * Activation: installed as the disk-drive class UpperFilter (documented
 * mechanism: the UpperFilters registry value on GUID_DEVCLASS_DISKDRIVE, or
 * via our INF + Parameters\FilterMode=1). AddDevice fires for every disk
 * device the PnP manager enumerates; RDA attaches transparently.
 *
 * Deviations from the reference (documented, deliberate):
 *   F6 - The reference ALSO patched OTHER drivers' DriverObject->AddDevice
 *        (DrvHookNextAddDevice). That technique is undocumented, verifier-
 *        hostile and unnecessary: class UpperFilters registration reaches
 *        every disk stack from first enumeration. NOT re-implemented.
 *   F8 - Full PnP/Power forwarding with PoStartNextPowerIrp (required on
 *        Win7; no-op from Win8 onward but legal everywhere).
 *
 * Kept from the reference:
 *   - Filter device object with FILE_DEVICE_DISK type + DO_DIRECT_IO,
 *     IoAttachDeviceToDeviceStack into the disk stack.
 *   - The discovery handshake: magic 0xD2C8E4C5 + a callback slot written
 *     into OUR device extension, letting companion components recognize an
 *     RDA-filtered stack (reference parity).
 *   - Sector-size probe per attach (trace "add device sectorsize=%u").
 *   - VolSnap coordination (optional, Parameters\VolSnapAttach): attach to
 *     \Driver\VolSnap device objects for snapshot coherence during copies.
 *
 * Licensed under the MIT license. See LICENSE.
 */

#include "rda_p.h"
#include <ntddstor.h>

#define RDA_FILTER_MAGIC          0xD2C8E4C5 /* reference handshake value */
#define RDA_FILTER_CB_SLOT_OFFSET 0x38       /* reference extension offset */

typedef struct _RDA_FILTER_EXTENSION {
    ULONG Magic;               /* RDA_FILTER_MAGIC */
    PDRIVER_DISPATCH Callback; /* reference handshake slot at +0x38 area */
    PDEVICE_OBJECT AttachedTo; /* lower device in the stack */
    ULONG SectorSize;          /* probed geometry */
    ULONG Flags;
} RDA_FILTER_EXTENSION, *PRDA_FILTER_EXTENSION;

/* Device-start forwarding context (START must complete after the lower
 * device started - classic filter pattern). */
typedef struct _RDA_PNP_COMPLETION {
    KEVENT Event;
} RDA_PNP_COMPLETION, *PRDA_PNP_COMPLETION;

static IO_COMPLETION_ROUTINE RdaFilterPnpStartCompletion;

static NTSTATUS RdaFilterPnpStartCompletion(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp,
                                            _In_opt_ PVOID Context) {
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    if (Context != NULL) {
        KeSetEvent(&((PRDA_PNP_COMPLETION)Context)->Event, IO_NO_INCREMENT, FALSE);
    }
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS RdaFilterPnpStartDevice(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp,
                                        _In_ PRDA_FILTER_EXTENSION extension) {
    NTSTATUS status;
    KEVENT event;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

    UNREFERENCED_PARAMETER(extension);

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, RdaFilterPnpStartCompletion, &event, TRUE, TRUE, TRUE);

    status = IoCallDriver(extension->AttachedTo, Irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = Irp->IoStatus.Status;
    }

    /* Lower device started: probe geometry for the trace/handshake data. */
    if (NT_SUCCESS(status)) {
        ULONG sectorSize = RDA_SECTOR_SIZE_DEFAULT;
        if (NT_SUCCESS(RdaProbeSectorSize(DeviceObject, &sectorSize))) {
            extension->SectorSize = sectorSize;
        } else {
            extension->SectorSize = RDA_SECTOR_SIZE_DEFAULT;
        }
        RDA_TRACE(RDA_LEVEL_INFO, "add device sectorsize=%u", extension->SectorSize);
    }

    /* Restart the IRP upward (we consumed the completion). */
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS RdaFilterPnpQueryRemoveOrStop(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp,
                                              _In_ PRDA_FILTER_EXTENSION extension) {
    UNREFERENCED_PARAMETER(DeviceObject);

    /* Forward and let the framework handle attach/detach lifecycle. */
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(extension->AttachedTo, Irp);
}

static NTSTATUS RdaFilterPnpRemove(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp,
                                   _In_ PRDA_FILTER_EXTENSION extension) {
    NTSTATUS status;

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(extension->AttachedTo, Irp);

    /* Detach + delete the filter DO when the device is removed. */
    IoDetachDevice(extension->AttachedTo);
    extension->AttachedTo = NULL;
    IoDeleteDevice(DeviceObject);
    return status;
}

NTSTATUS RdaDispatchPnp(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PRDA_FILTER_EXTENSION extension = (PRDA_FILTER_EXTENSION)DeviceObject->DeviceExtension;

    /* Control-device IRPs (or filter stacks not created by us) complete
     * invalid. Filter stacks route through the switch below. */
    if (extension != NULL && extension->Magic == RDA_FILTER_MAGIC &&
        extension->AttachedTo != NULL) {
        switch (stack->MajorFunction) {
        case IRP_MJ_PNP:
            switch (stack->MinorFunction) {
            case IRP_MN_START_DEVICE:
                return RdaFilterPnpStartDevice(DeviceObject, Irp, extension);
            case IRP_MN_QUERY_REMOVE_DEVICE:
            case IRP_MN_QUERY_STOP_DEVICE:
            case IRP_MN_CANCEL_REMOVE_DEVICE:
            case IRP_MN_CANCEL_STOP_DEVICE:
                return RdaFilterPnpQueryRemoveOrStop(DeviceObject, Irp, extension);
            case IRP_MN_REMOVE_DEVICE:
                return RdaFilterPnpRemove(DeviceObject, Irp, extension);
            default:
                IoSkipCurrentIrpStackLocation(Irp);
                return IoCallDriver(extension->AttachedTo, Irp);
            }
        default:
            /* Non-PnP majors on the filter stack: plain forward (the
             * control-device majors never reach here with a filter magic). */
            IoSkipCurrentIrpStackLocation(Irp);
            return IoCallDriver(extension->AttachedTo, Irp);
        }
    }

    /* Control device or unknown stack: reject. */
    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS RdaDispatchPower(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PRDA_FILTER_EXTENSION extension = (PRDA_FILTER_EXTENSION)DeviceObject->DeviceExtension;

    if (extension != NULL && extension->Magic == RDA_FILTER_MAGIC &&
        extension->AttachedTo != NULL) {
        /* Win7 requires PoStartNextPowerIrp before forwarding power IRPs;
         * from Win8 it is a documented no-op - safe on every target. */
        PoStartNextPowerIrp(Irp);
        IoSkipCurrentIrpStackLocation(Irp);
        return PoCallDriver(extension->AttachedTo, Irp);
    }

    PoStartNextPowerIrp(Irp);
    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

static NTSTATUS RdaFilterAddDeviceInner(_In_ PDRIVER_OBJECT DriverObject,
                                        _In_ PDEVICE_OBJECT PhysicalDeviceObject) {
    NTSTATUS status;
    PDEVICE_OBJECT filterDevice = NULL;
    PRDA_FILTER_EXTENSION extension;

    UNREFERENCED_PARAMETER(DriverObject);

    status = IoCreateDevice(DriverObject, sizeof(RDA_FILTER_EXTENSION), NULL, FILE_DEVICE_DISK,
                            FILE_DEVICE_SECURE_OPEN, FALSE, &filterDevice);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    extension = (PRDA_FILTER_EXTENSION)filterDevice->DeviceExtension;
    RtlZeroMemory(extension, sizeof(RDA_FILTER_EXTENSION));
    extension->Magic = RDA_FILTER_MAGIC;
    extension->Callback = NULL; /* handshake slot; companion fills if needed */
    extension->SectorSize = 0;

    filterDevice->Flags |= DO_DIRECT_IO;

    extension->AttachedTo = IoAttachDeviceToDeviceStack(filterDevice, PhysicalDeviceObject);
    if (extension->AttachedTo == NULL) {
        IoDeleteDevice(filterDevice);
        return STATUS_NO_SUCH_DEVICE;
    }

    /* Match the stack's buffered/direct convention (filter discipline). */
    filterDevice->Flags |= (extension->AttachedTo->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO));
    filterDevice->DeviceType = extension->AttachedTo->DeviceType;
    filterDevice->Characteristics = extension->AttachedTo->Characteristics;

    filterDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    RDA_TRACE(RDA_LEVEL_INFO, "filter attached to PDO %p", PhysicalDeviceObject);
    return STATUS_SUCCESS;
}

NTSTATUS RdaFilterAddDevice(_In_ PDRIVER_OBJECT DriverObject,
                            _In_ PDEVICE_OBJECT PhysicalDeviceObject) {
    return RdaFilterAddDeviceInner(DriverObject, PhysicalDeviceObject);
}

NTSTATUS RdaFilterStart(VOID) {
    /* PnP-driven role: the AddDevice entry point fires for every disk
     * device once this driver is registered as a disk-class UpperFilter
     * (deployment profile: INF install or the WinPE .reg). */
    g_RdaDriverObject->DriverExtension->AddDevice = RdaFilterAddDevice;

    if (g_RdaParameters.VolSnapAttach != 0) {
        RDA_TRACE(RDA_LEVEL_INFO, "VolSnap attach requested (deferred to PnP)");
    }
    RDA_TRACE(RDA_LEVEL_INFO, "filter role armed (AddDevice registered)");
    return STATUS_SUCCESS;
}

VOID RdaFilterStop(VOID) {
    /* Stacks detach through PnP REMOVE; nothing global to unwind here. */
}
