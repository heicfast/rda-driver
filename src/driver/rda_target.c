/*
 * rda_target.c - target device resolution chains (reference-exact).
 *
 * Three resolution strategies mirror the merged reference drivers:
 *
 *  RdaResolveVolume (EPMNtDrv volume branch):
 *    "\Device\HarddiskVolume%u" -> IoGetDeviceObjectPointer ->
 *    top-of-stack via IoGetAttachedDeviceReference. Mode fixed 0.
 *
 *  RdaResolveDisk (EPMNtDrv disk branch):
 *    "\Device\Harddisk{d}\Partition0", on failure retry
 *    "\Device\Harddisk{d}\DR{d}" (same number twice - reference-exact),
 *    then walk DOWN from top-of-stack: first layer whose ObQueryNameString
 *    name contains "\Device\Harddisk" becomes the IO target (this skips
 *    storage filter devices - e.g. the copy filter in PE); mode =
 *    (layer's driver name != "Disk"). The partition number in the path is
 *    reference-vestigial (parsed by clients, ignored by the driver).
 *
 *  RdaResolveDiskEpm (EUEDKEPM branch):
 *    "\Device\Harddisk{d}\Partition0" only (no fallback), walk DOWN to the
 *    first layer whose driver is \Driver\Disk; that layer is the IO target.
 *
 * Geometry (fix F1): after resolution every context probes the target's
 * logical sector size (IOCTL_DISK_GET_DRIVE_GEOMETRY on the target; falls
 * back to 512 when the target does not answer geometry queries - e.g. some
 * volume stacks). READ/WRITE offsets stay absolute bytes for callers;
 * internal 4Kn correctness is enforced at the forwarding boundary.
 *
 * Licensed under the MIT license. See LICENSE.
 */

#include "rda_p.h"

/* The name-contains walk of the reference used a 0x200 byte buffer with
 * ObQueryNameString and wcsstr("\Device\Harddisk"). */
static BOOLEAN RdaDeviceNameContainsHarddisk(_In_ PDEVICE_OBJECT Device, _Out_ BOOLEAN *Contains) {
    NTSTATUS status;
    PBYTE buffer;
    ULONG returned = 0;

    *Contains = FALSE;

    buffer = (PBYTE)RdaAlloc(RDA_QUERY_NAME_BUFFER);
    if (buffer == NULL) {
        return FALSE;
    }

    status = ObQueryNameString(Device, (POBJECT_NAME_INFORMATION)buffer, RDA_QUERY_NAME_BUFFER,
                               &returned);
    if (NT_SUCCESS(status)) {
        POBJECT_NAME_INFORMATION info = (POBJECT_NAME_INFORMATION)buffer;
        PCWSTR cursor;
        PCWSTR end;

        /* Bounded substring search for L"\Device\Harddisk" (the reference
         * used wcsstr over the NUL-terminated name string). */
        if (info->Name.Buffer != NULL && info->Name.Length >= sizeof(WCHAR) * 15) {
            end = info->Name.Buffer + (info->Name.Length / sizeof(WCHAR));
            for (cursor = info->Name.Buffer; cursor + 15 <= end; cursor++) {
                if (cursor[0] == L'\\' && cursor[1] == L'D' && cursor[2] == L'e' &&
                    cursor[3] == L'v' && cursor[4] == L'i' && cursor[5] == L'c' &&
                    cursor[6] == L'e' && cursor[7] == L'\\' && cursor[8] == L'H' &&
                    cursor[9] == L'a' && cursor[10] == L'r' && cursor[11] == L'd' &&
                    cursor[12] == L'd' && cursor[13] == L'i' && cursor[14] == L's') {
                    *Contains = TRUE;
                    break;
                }
            }
        }
    }

    RdaFree(buffer);
    return NT_SUCCESS(status) ? TRUE : FALSE;
}

/* TRUE when the device's driver object name equals L"Disk"
 * (RtlCompareUnicodeString case-insensitive, reference-exact). */
static BOOLEAN RdaDriverIsDisk(_In_ PDEVICE_OBJECT Device) {
    UNICODE_STRING diskName;
    PDRIVER_OBJECT driver;

    driver = Device->DriverObject;
    if (driver == NULL || driver->DriverName.Buffer == NULL) {
        return FALSE;
    }
    RtlInitUnicodeString(&diskName, L"Disk");
    return RtlCompareUnicodeString(&driver->DriverName, &diskName, TRUE) == 0;
}

/* Opens a named device and stashes the referenced file object + device
 * object into the context. Caller ensures symmetric release via
 * RdaReleaseContext. */
static NTSTATUS RdaOpenNamedDevice(_In_ PCWSTR Name, _In_ ULONG Number,
                                   _Out_ PRDA_OPEN_CONTEXT Context) {
    NTSTATUS status;
    WCHAR nameBuffer[64];
    UNICODE_STRING name;

    name.Buffer = nameBuffer;
    name.Length = 0;
    name.MaximumLength = sizeof(nameBuffer);
    status = RdaFormatDeviceName(&name, Name, Number);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoGetDeviceObjectPointer(&name, FILE_ANY_ACCESS, &Context->TargetFileObject,
                                      &Context->TargetDevice);
    if (!NT_SUCCESS(status)) {
        RDA_TRACE(RDA_LEVEL_WARN, "[GetVolumeDeviceObejct] %wZ open error 0x%x", &name, status);
    }
    return status;
}

NTSTATUS RdaResolveVolume(_In_ ULONG VolumeNumber, _Out_ PRDA_OPEN_CONTEXT Context) {
    NTSTATUS status;
    PDEVICE_OBJECT top = NULL;

    RDA_ENTER("ResolveVolume");

    status = RdaOpenNamedDevice(L"\\Device\\HarddiskVolume%u", VolumeNumber, Context);
    if (!NT_SUCCESS(status)) {
        RDA_TRACE(RDA_LEVEL_ERROR, "[GetVolumeDeviceObejct] %ws open error 0x%x,that's it!",
                  L"\\Device\\HarddiskVolume", status);
        goto Fail;
    }

    /* Top-of-stack reference (held for the handle lifetime). */
    top = IoGetAttachedDeviceReference(Context->TargetDevice);
    if (top == NULL) {
        status = STATUS_INVALID_PARAMETER;
        goto Fail;
    }
    Context->TargetDevice = top; /* transfer ref (original released in Fail/Release) */
    Context->Mode = 0;           /* reference parity: volume mode = 0 */
    Context->Kind = RdaCtxVolume;

    status = RdaProbeSectorSize(Context->TargetDevice, &Context->SectorSize);
    if (!NT_SUCCESS(status)) {
        Context->SectorSize = RDA_SECTOR_SIZE_DEFAULT;
    }

    RDA_EXIT("ResolveVolume");
    return STATUS_SUCCESS;

Fail:
    if (Context->TargetFileObject != NULL) {
        ObDereferenceObject(Context->TargetFileObject);
        Context->TargetFileObject = NULL;
    }
    RDA_EXIT("ResolveVolume");
    return status;
}

NTSTATUS RdaResolveDisk(_In_ ULONG DiskNumber, _In_ ULONG PartNumber,
                        _Out_ PRDA_OPEN_CONTEXT Context) {
    NTSTATUS status;
    PDEVICE_OBJECT top;
    PDEVICE_OBJECT layer;
    BOOLEAN found;
    BOOLEAN hasHarddiskName = FALSE;

    UNREFERENCED_PARAMETER(PartNumber); /* reference-vestigial */

    RDA_ENTER("ResolveDisk");

    status = RdaOpenNamedDevice(L"\\Device\\Harddisk%u\\Partition0", DiskNumber, Context);
    if (!NT_SUCCESS(status)) {
        /* Reference retry: \Device\Harddisk{d}\DR{d} (same number twice). */
        RDA_TRACE(RDA_LEVEL_WARN, "[GetDiskDeviceObejct] %ws open error 0x%x,retry",
                  L"\\Device\\Harddisk\\Partition0", status);
        status = RdaOpenNamedDevice(L"\\Device\\Harddisk%u\\DR%u", DiskNumber, Context);
        if (!NT_SUCCESS(status)) {
            RDA_TRACE(RDA_LEVEL_ERROR, "[GetDiskDeviceObejct] %ws open error 0x%x,that's it!",
                      L"\\Device\\Harddisk\\DR", status);
            return status;
        }
    }

    top = IoGetAttachedDeviceReference(Context->TargetDevice);
    if (top == NULL) {
        ObDereferenceObject(Context->TargetFileObject);
        Context->TargetFileObject = NULL;
        return STATUS_INVALID_PARAMETER;
    }

    /* Walk down from the top: first layer whose NAME contains
     * \Device\Harddisk becomes the target; mode records whether its driver
     * is \Driver\Disk. Skip filter DOs above (their names differ).
     *
     * Ownership discipline: exactly one reference is held at any time (the
     * first layer comes from IoGetAttachedDeviceReference; each subsequent
     * layer from IoGetLowerDeviceObject); it transfers to the context on a
     * match or is dropped when stepping down. The reference drivers leaked
     * the top-of-stack reference per open (fix F13) - this rewrite does not.
     */
    found = FALSE;
    layer = top;
    while (layer != NULL) {
        PDEVICE_OBJECT next;

        if (RdaDeviceNameContainsHarddisk(layer, &hasHarddiskName) && hasHarddiskName) {
            Context->TargetDevice = layer; /* adopt this layer's reference */
            Context->Mode = RdaDriverIsDisk(layer) ? 0 : 1;
            found = TRUE;
            break;
        }
        next = IoGetLowerDeviceObject(layer);
        ObDereferenceObject(layer);
        layer = next;
    }

    if (!found) {
        RDA_TRACE(RDA_LEVEL_ERROR, "[GetDiskDeviceObejct] no Harddisk layer,that's it!");
        ObDereferenceObject(Context->TargetFileObject);
        Context->TargetFileObject = NULL;
        return STATUS_INVALID_PARAMETER;
    }
    Context->Kind = RdaCtxDisk;

    status = RdaProbeSectorSize(Context->TargetDevice, &Context->SectorSize);
    if (!NT_SUCCESS(status)) {
        Context->SectorSize = RDA_SECTOR_SIZE_DEFAULT;
    }

    RDA_EXIT("ResolveDisk");
    return STATUS_SUCCESS;
}

NTSTATUS RdaResolveDiskEpm(_In_ ULONG DiskNumber, _Out_ PRDA_OPEN_CONTEXT Context) {
    NTSTATUS status;
    PDEVICE_OBJECT top;
    PDEVICE_OBJECT layer;

    RDA_ENTER("ResolveDiskEpm");

    status = RdaOpenNamedDevice(L"\\Device\\Harddisk%u\\Partition0", DiskNumber, Context);
    if (!NT_SUCCESS(status)) {
        RDA_TRACE(RDA_LEVEL_ERROR, "[EUEDKEPM] disk %u open failed 0x%08X", DiskNumber, status);
        return status;
    }

    top = IoGetAttachedDeviceReference(Context->TargetDevice);
    if (top == NULL) {
        ObDereferenceObject(Context->TargetFileObject);
        Context->TargetFileObject = NULL;
        return STATUS_INVALID_PARAMETER;
    }

    /* Walk down to the first layer DRIVEN BY \Driver\Disk; that layer is
     * the target (EUEDKEPM parity: direct disk-class forwarding, no
     * Harddisk-name filter, no DR fallback). Same one-reference ownership
     * discipline as RdaResolveDisk. */
    layer = top;
    while (layer != NULL) {
        PDEVICE_OBJECT next;

        if (RdaDriverIsDisk(layer)) {
            Context->TargetDevice = layer; /* adopt this layer's reference */
            Context->Mode = 0;
            break;
        }
        next = IoGetLowerDeviceObject(layer);
        ObDereferenceObject(layer);
        layer = next;
    }

    if (layer == NULL) {
        ObDereferenceObject(Context->TargetFileObject);
        Context->TargetFileObject = NULL;
        return STATUS_INVALID_PARAMETER;
    }
    Context->Kind = RdaCtxDiskEpm;

    status = RdaProbeSectorSize(Context->TargetDevice, &Context->SectorSize);
    if (!NT_SUCCESS(status)) {
        Context->SectorSize = RDA_SECTOR_SIZE_DEFAULT;
    }

    RDA_EXIT("ResolveDiskEpm");
    return STATUS_SUCCESS;
}

/* Probes the target's logical sector size via IOCTL_DISK_GET_DRIVE_GEOMETRY.
 * The reference main gate never did this (its 512-byte hardcode silently
 * corrupted 4Kn IO - fix F1); the copy engine probed geometry per device. */
NTSTATUS RdaProbeSectorSize(_In_ PDEVICE_OBJECT TargetDevice, _Out_ PULONG SectorSize) {
    NTSTATUS status;
    KEVENT event;
    PIRP irp;
    IO_STATUS_BLOCK iosb;
    DISK_GEOMETRY geometry;
    PDEVICE_OBJECT attached;

    *SectorSize = RDA_SECTOR_SIZE_DEFAULT;

    RtlZeroMemory(&geometry, sizeof(geometry));
    KeInitializeEvent(&event, NotificationEvent, FALSE);
    RtlZeroMemory(&iosb, sizeof(iosb));

    attached = IoGetAttachedDeviceReference(TargetDevice);
    if (attached == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_GET_DRIVE_GEOMETRY, attached, NULL, 0, &geometry,
                                        sizeof(geometry), FALSE, &event, &iosb);
    if (irp == NULL) {
        ObDereferenceObject(attached);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IoCallDriver(attached, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    }
    ObDereferenceObject(attached);

    if (NT_SUCCESS(status)) {
        if (geometry.BytesPerSector == 512 || geometry.BytesPerSector == 4096 ||
            (geometry.BytesPerSector % 512) == 0) {
            *SectorSize = geometry.BytesPerSector;
        } else {
            status = STATUS_UNSUCCESSFUL;
        }
    }
    return status;
}
