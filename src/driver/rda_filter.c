/*
 * rda_filter.c - PnP disk-class upper-filter role (EUDCPEPM merge, WinPE).
 *
 * Activation: installed as the disk-drive class UpperFilter (documented
 * mechanism: UpperFilters on GUID_DEVCLASS_DISKDRIVE, or via our INF +
 * Parameters\FilterMode=1). AddDevice fires for every disk device PnP
 * enumerates; RDA attaches transparently.
 *
 * REVERIFIED 2026-10-22 against the EUDCPEPM decompile (reference
 * FUN_000120c4 master dispatch / FUN_00012b70 filter dispatch):
 *   - ALL majors forward transparently except:
 *       * WRITE  - coordinated with active copy sessions (reference
 *                  FUN_0001189c): standby sessions park the write;
 *                  copying sessions COW-save covered ranges first.
 *       * IOCTL - normalized session-code subset served on filter devices:
 *                  0x800C2AC0 discovery  -> {buffer[0]=diskId, Info=4}
 *                  0x800C2B40 version    -> {0x604 at +8, Info=0xC} ("RRWR")
 *                  0x800C2B42/B3E        -> raw disk read/write ("RRWR")
 *                  IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES (Action=Trim)
 *                  -> SWALLOWED while a session is active on the disk
 *                     (a TRIM would discard snapshot-needed sectors).
 *   - Device extension carries the discovery handshake magic 0xD2C8E4C5
 *     (reference value) + the callback slot.
 *
 * Deviations from the reference (documented):
 *   F6 - the reference ALSO patched other drivers' DriverObject->AddDevice
 *        (DrvHookNextAddDevice). NOT re-implemented: class UpperFilters
 *        registration reaches every disk stack from first enumeration.
 *   F8 - full PnP/Power forwarding with PoStartNextPowerIrp (required on
 *        Win7; documented no-op from Win8 onward, legal everywhere).
 *   S4 - REMOVE waits for the lower stack before detach+delete (the
 *        reference forwards and tears down without a completion wait).
 *
 * Licensed under the MIT license. See LICENSE.
 */

#include "rda_p.h"
#include <ntddstor.h>

#define RDA_FILTER_MAGIC 0xD2C8E4C5 /* reference handshake value */

typedef struct _RDA_FILTER_EXTENSION {
    ULONG Magic;               /* RDA_FILTER_MAGIC (discovery handshake) */
    PDRIVER_DISPATCH Callback; /* reference handshake slot */
    PDEVICE_OBJECT AttachedTo; /* lower device in the stack */
    ULONG DiskId;              /* storage device number (queried at START) */
    ULONG SectorSize;          /* probed logical sector size */
    ULONG Flags;
} RDA_FILTER_EXTENSION, *PRDA_FILTER_EXTENSION;

/* ---------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------- */
static PRDA_FILTER_EXTENSION RdaFilterExt(_In_opt_ PDEVICE_OBJECT DeviceObject) {
    if (DeviceObject == NULL || DeviceObject == g_RdaControlDevice) {
        return NULL;
    }
    return (PRDA_FILTER_EXTENSION)DeviceObject->DeviceExtension;
}

/* Query the storage device number + geometry of the attached stack. Runs at
 * PASSIVE in the START path (the reference resolved the disk identity at
 * AddDevice time from its own wrapper bookkeeping). */
static VOID RdaFilterIdentifyDisk(_In_ PRDA_FILTER_EXTENSION Extension) {
    NTSTATUS status;
    KEVENT event;
    PIRP irp;
    IO_STATUS_BLOCK iosb;
    STORAGE_DEVICE_NUMBER number;
    ULONG sectorSize = RDA_SECTOR_SIZE_DEFAULT;

    KeInitializeEvent(&event, NotificationEvent, FALSE);
    RtlZeroMemory(&number, sizeof(number));
    RtlZeroMemory(&iosb, sizeof(iosb));

    irp = IoBuildDeviceIoControlRequest(IOCTL_STORAGE_GET_DEVICE_NUMBER, Extension->AttachedTo,
                                        NULL, 0, &number, sizeof(number), FALSE, &event, &iosb);
    if (irp != NULL) {
        status = IoCallDriver(Extension->AttachedTo, irp);
        if (status == STATUS_PENDING) {
            KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
            status = iosb.Status;
        }
        if (NT_SUCCESS(status)) {
            Extension->DiskId = number.DeviceNumber;
        }
    }

    if (NT_SUCCESS(RdaProbeSectorSize(Extension->AttachedTo, &sectorSize))) {
        Extension->SectorSize = sectorSize;
    } else {
        Extension->SectorSize = RDA_SECTOR_SIZE_DEFAULT;
    }

    RDA_TRACE(RDA_LEVEL_INFO, "filter: disk %u (dev type %u) sectorsize=%u", Extension->DiskId,
              number.DeviceType, Extension->SectorSize);
}

/* Plain filter forward (reference FUN_00018890 tail: skip + call below). */
static NTSTATUS RdaFilterForward(_In_ PRDA_FILTER_EXTENSION Extension, _Inout_ PIRP Irp) {
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(Extension->AttachedTo, Irp);
}

/* ---------------------------------------------------------------------------
 * PnP
 * ------------------------------------------------------------------------- */
static IO_COMPLETION_ROUTINE RdaFilterPnpWaitCompletion;

static NTSTATUS RdaFilterPnpWaitCompletion(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp,
                                           _In_opt_ PVOID Context) {
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    KeSetEvent((PKEVENT)Context, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

/* Forward an IRP to the lower stack and WAIT for its completion; the IRP is
 * completed back to the caller with the lower status. Used by START/REMOVE
 * (must not touch the stack after forwarding). */
static NTSTATUS RdaFilterPnpSendAndWait(_In_ PRDA_FILTER_EXTENSION Extension, _Inout_ PIRP Irp,
                                        _Out_ PNTSTATUS LowerStatus) {
    KEVENT event;
    NTSTATUS status;

    KeInitializeEvent(&event, NotificationEvent, FALSE);
    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, RdaFilterPnpWaitCompletion, &event, TRUE, TRUE, TRUE);

    status = IoCallDriver(Extension->AttachedTo, Irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = Irp->IoStatus.Status;
    }
    *LowerStatus = status;

    /* We consumed the completion: complete upward ourselves. */
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS RdaFilterPnpStartDevice(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp,
                                        _In_ PRDA_FILTER_EXTENSION Extension) {
    NTSTATUS lowerStatus;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (!NT_SUCCESS(RdaFilterPnpSendAndWait(Extension, Irp, &lowerStatus))) {
        return lowerStatus;
    }

    /* Lower device started: resolve the disk identity (reference probes the
     * sector size at AddDevice, "InitSectorSize"). */
    RdaFilterIdentifyDisk(Extension);

    /* Purge any stale cache entry from a previous incarnation of this disk
     * number, then re-resolve lazily. */
    RdaDiskCacheRemoveDisk(Extension->DiskId);
    return lowerStatus;
}

static NTSTATUS RdaFilterPnpRemoveDevice(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp,
                                         _In_ PRDA_FILTER_EXTENSION Extension) {
    NTSTATUS lowerStatus;

    /* S4: wait for the lower stack to finish the REMOVE before tearing our
     * own device down (v0.1.0 detached immediately - use-after-free window). */
    RdaFilterPnpSendAndWait(Extension, Irp, &lowerStatus);

    /* Reference FUN_0001324c: sessions bound to a removed disk die. */
    RdaSessionKillByDisk(Extension->DiskId);
    RdaDiskCacheRemoveDisk(Extension->DiskId);

    IoDetachDevice(Extension->AttachedTo);
    Extension->AttachedTo = NULL;
    IoDeleteDevice(DeviceObject);
    return lowerStatus;
}

/* ---------------------------------------------------------------------------
 * Filter dispatch (all majors; reference FUN_00012b70 + FUN_00018890)
 * ------------------------------------------------------------------------- */
static NTSTATUS RdaFilterIoctl(_In_ PRDA_FILTER_EXTENSION Extension, _Inout_ PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG normalized = (ULONG)(code - g_RdaParameters.IoctlBase);
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inLength = stack->Parameters.DeviceIoControl.InputBufferLength;

    /* TRIM swallow: a session on this disk needs the sectors the volume is
     * about to discard (reference FUN_00012d64: sessions in standby, or
     * copying with a live plan -> complete SUCCESS without forwarding). */
    if (code == IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES && buffer != NULL &&
        inLength >= sizeof(DEVICE_MANAGE_DATA_SET_ATTRIBUTES) &&
        ((PDEVICE_MANAGE_DATA_SET_ATTRIBUTES)buffer)->Action == DeviceDsmAction_Trim) {
        if (RdaSessionActiveOnDisk(Extension->DiskId)) {
            RDA_TRACE(RDA_LEVEL_INFO, "filter: TRIM swallowed for disk %u (active session)",
                      Extension->DiskId);
            Irp->IoStatus.Status = STATUS_SUCCESS;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_SUCCESS;
        }
        return RdaFilterForward(Extension, Irp);
    }

    /* Session-protocol subset served on filter stacks. */
    if (normalized == RDA_SESSION_CODE_DISCOVERY) {
        if (buffer == NULL || stack->Parameters.DeviceIoControl.OutputBufferLength < 4) {
            Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_INVALID_PARAMETER;
        }
        /* Re-probe the sector size (the reference re-runs InitSectorSize),
         * then answer with the disk identity. */
        {
            ULONG sectorSize = RDA_SECTOR_SIZE_DEFAULT;

            if (NT_SUCCESS(RdaProbeSectorSize(Extension->AttachedTo, &sectorSize))) {
                Extension->SectorSize = sectorSize;
            }
        }
        *(PULONG)buffer = Extension->DiskId;
        Irp->IoStatus.Information = sizeof(ULONG);
        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    if (normalized == RDA_SESSION_CODE_RRWR_VERSION) {
        if (buffer == NULL || inLength < sizeof(ULONG) || *(PULONG)buffer != RDA_RRWR_MAGIC) {
            Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_INVALID_PARAMETER;
        }
        *(PULONG)((PUCHAR)buffer + 8) = RDA_SESSION_RRWR_VERSION_OUT; /* 0x604 */
        Irp->IoStatus.Information = RDA_SESSION_RRWR_INFO;            /* 0xC */
        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    if (normalized == RDA_SESSION_CODE_RRWR_READ || normalized == RDA_SESSION_CODE_RRWR_WRITE) {
        PULONG header = (PULONG)buffer;
        PUCHAR data;
        ULONG outLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
        NTSTATUS status;
        ULONG bytes;
        ULONG64 lba;
        ULONG count;

        if (buffer == NULL || inLength < RDA_SESSION_RRWR_MIN_IN || header[0] != RDA_RRWR_MAGIC ||
            Irp->MdlAddress == NULL) {
            Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_INVALID_PARAMETER;
        }
        /* Wire (reference FUN_00013310): +0x08 sectorSize must match,
         * +0x0C declared out length must equal the actual, +0x10 LBA,
         * +0x18 sector count; data = the whole MDL'd buffer. */
        if (header[2] != Extension->SectorSize || header[3] != outLength) {
            Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_INVALID_PARAMETER;
        }
        data = (PUCHAR)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
        if (data == NULL) {
            Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        lba = *(PULONG64)((PUCHAR)buffer + 0x10);
        count = header[6];
        bytes = count * Extension->SectorSize;
        if ((SIZE_T)bytes > (SIZE_T)outLength) {
            Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_INVALID_PARAMETER;
        }

        /* Raw IO against OUR stack's device via the session-sync engine
         * (the reference issued it through the per-disk wrapper target). */
        {
            LARGE_INTEGER byteOffset;
            ULONG_PTR information = 0;

            byteOffset.QuadPart = (LONGLONG)(lba * Extension->SectorSize);
            status = RdaSyncDiskReadWrite(Extension->AttachedTo,
                                          normalized == RDA_SESSION_CODE_RRWR_WRITE ? IRP_MJ_WRITE
                                                                                    : IRP_MJ_READ,
                                          data, bytes, &byteOffset, &information);
        }
        if (NT_SUCCESS(status)) {
            Irp->IoStatus.Information = outLength;
        } else {
            Irp->IoStatus.Information = 0;
        }
        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }

    return RdaFilterForward(Extension, Irp);
}

static NTSTATUS RdaFilterWrite(_In_ PRDA_FILTER_EXTENSION Extension, _Inout_ PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG64 startSec;
    ULONG secCount;
    RDA_WRITE_INTERCEPT intercept;
    ULONG64 offset;
    ULONG length;

    /* Only coordinate when at least one session could be active. */
    offset = (ULONG64)stack->Parameters.Write.ByteOffset.QuadPart;
    length = stack->Parameters.Write.Length;

    if (Extension->SectorSize == 0 || length == 0 ||
        stack->Parameters.Write.ByteOffset.QuadPart < 0) {
        return RdaFilterForward(Extension, Irp);
    }

    startSec = offset / Extension->SectorSize;
    secCount = length / Extension->SectorSize;

    intercept =
        RdaSessionInterceptWrite(Extension->DiskId, Irp, Extension->AttachedTo, startSec, secCount);
    switch (intercept) {
    case RdaWriteParked:
        return STATUS_PENDING; /* session owns the IRP; worker forwards */
    case RdaWriteBlocked:
        Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INSUFFICIENT_RESOURCES;
    case RdaWriteForward:
    default:
        return RdaFilterForward(Extension, Irp);
    }
}

/* Master filter dispatch (reference FUN_000120c4's else-branch). */
NTSTATUS RdaDispatchFilter(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
    PRDA_FILTER_EXTENSION extension = RdaFilterExt(DeviceObject);
    PIO_STACK_LOCATION stack;
    UCHAR major;

    if (extension == NULL || extension->AttachedTo == NULL ||
        extension->Magic != RDA_FILTER_MAGIC) {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    stack = IoGetCurrentIrpStackLocation(Irp);
    major = stack->MajorFunction;

    switch (major) {
    case IRP_MJ_WRITE:
        return RdaFilterWrite(extension, Irp);
    case IRP_MJ_DEVICE_CONTROL:
        return RdaFilterIoctl(extension, Irp);
    case IRP_MJ_PNP:
        switch (stack->MinorFunction) {
        case IRP_MN_START_DEVICE:
            return RdaFilterPnpStartDevice(DeviceObject, Irp, extension);
        case IRP_MN_REMOVE_DEVICE:
            return RdaFilterPnpRemoveDevice(DeviceObject, Irp, extension);
        default:
            return RdaFilterForward(extension, Irp);
        }
    default:
        return RdaFilterForward(extension, Irp);
    }
}

/* ---------------------------------------------------------------------------
 * PnP AddDevice + power
 * ------------------------------------------------------------------------- */
NTSTATUS RdaFilterAddDevice(_In_ PDRIVER_OBJECT DriverObject,
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
    extension->Magic = RDA_FILTER_MAGIC; /* reference discovery handshake */
    extension->Callback = NULL;          /* handshake slot; companion fills */

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

static NTSTATUS RdaDispatchPnpInner(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
    /* Filter stacks are routed through RdaDispatchFilter by the master
     * dispatch; this handler only sees the CONTROL device, which is not a
     * PnP device - complete invalid (reference behavior for non-PnP devices
     * is to leave the slot unassigned = invalid-device-request). */
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS RdaDispatchPnp(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
    if (DeviceObject == g_RdaControlDevice) {
        return RdaDispatchPnpInner(DeviceObject, Irp);
    }
    return RdaDispatchFilter(DeviceObject, Irp);
}

NTSTATUS RdaDispatchPower(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
    PRDA_FILTER_EXTENSION extension = RdaFilterExt(DeviceObject);

    if (extension == NULL || extension->AttachedTo == NULL) {
        /* Control device: power IRPs never reach a non-PnP device; complete
         * SUCCESS (S11 - v0.1.0 completed INVALID on a dead path). */
        PoStartNextPowerIrp(Irp);
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    PoStartNextPowerIrp(Irp); /* Win7 requirement; documented no-op Win8+ */
    IoSkipCurrentIrpStackLocation(Irp);
    return PoCallDriver(extension->AttachedTo, Irp);
}

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS RdaFilterStart(VOID) {
    /* PnP-driven role: AddDevice fires for every disk device once this
     * driver is registered as a disk-class UpperFilter (INF install or the
     * WinPE .reg deployment). */
    g_RdaDriverObject->DriverExtension->AddDevice = RdaFilterAddDevice;

    if (g_RdaParameters.VolSnapAttach != 0) {
        RDA_TRACE(RDA_LEVEL_INFO, "VolSnap attach requested (reference: DriverEntry attaches "
                                  "\\Driver\\VolSnap devices for snapshot coherence)");
    }
    RDA_TRACE(RDA_LEVEL_INFO, "filter role armed (AddDevice registered)");
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL) VOID RdaFilterStop(VOID) {
    /* Stacks detach through PnP REMOVE; nothing global to unwind here. */
}
