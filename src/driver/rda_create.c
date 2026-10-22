/*
 * rda_create.c - IRP_MJ_CREATE / CLEANUP / CLOSE.
 *
 * CREATE contract (reference-exact semantics; see rda_compat.h):
 *  1. FileObject name < 2 wchars -> SUCCESS with no target (global mode:
 *     identity IOCTLs + global-handle read/write modes).
 *  2. Classify via RdaClassifyOpenPath; REJECT -> STATUS_INVALID_PARAMETER.
 *  3. Verify token == RdaComputePidToken(PsGetCurrentProcessId()).
 *  4. Resolve per kind:
 *       VOLUME    -> RdaResolveVolume (top of volume stack, mode 0)
 *       DISK      -> RdaResolveDisk    (Partition0/DR fallback, Harddisk layer)
 *       DISK_EPM  -> RdaResolveDiskEpm (Partition0, \Driver\Disk layer)
 *       disk bound: DISK kind <= MaxDisks-1 (reference 200),
 *                   DISK_EPM kind < 100 (EUEDKEPM parity)
 *     with SDDL admin gating already handled at device-open time, the token
 *     handshake is retained for wire compatibility only.
 *  5. Context into FileObject->FsContext (file object) + FsContext2 (context).
 *
 * CLEANUP releases all per-handle resources (fix F9: the reference released
 * on CLOSE; handles with pending IO at cleanup must have resources tied to
 * CLEANUP, not the final CLOSE drop). CLOSE completes with STATUS_SUCCESS.
 *
 * Licensed under the MIT license. See LICENSE.
 */

#include "rda_p.h"

VOID RdaReleaseContext(_In_opt_ PRDA_OPEN_CONTEXT Context) {
    if (Context == NULL) {
        return;
    }
    if (Context->TargetDevice != NULL) {
        ObDereferenceObject(Context->TargetDevice);
        Context->TargetDevice = NULL;
    }
    if (Context->TargetFileObject != NULL) {
        ObDereferenceObject(Context->TargetFileObject);
        Context->TargetFileObject = NULL;
    }
    RdaFree(Context);
}

static NTSTATUS RdaDispatchCreateInner(_In_ PIO_STACK_LOCATION Stack) {
    NTSTATUS status;
    PFILE_OBJECT fileObject = Stack->FileObject;
    PRDA_OPEN_CONTEXT context;
    RDA_OPEN_INFO openInfo;
    ULONG token;
    PUNICODE_STRING fileName;

    if (fileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    fileName = &fileObject->FileName;

    /* Portability guard: the shared classifier receives (buffer, wchars). */
    RdaClassifyOpenPath(fileName->Buffer, fileName->Length / sizeof(WCHAR), &openInfo);

    if (openInfo.Kind == RDA_OPEN_CLASS_GLOBAL) {
        /* Bare open: succeeds with no context (reference parity). */
        fileObject->FsContext = NULL;
        fileObject->FsContext2 = NULL;
        return STATUS_SUCCESS;
    }

    if (openInfo.Kind == RDA_OPEN_CLASS_REJECT) {
        return STATUS_INVALID_PARAMETER;
    }

    /* PID-token gate (reference parity; retained for wire compatibility -
     * the device DACL is the real boundary). */
    token = RdaComputePidToken((ULONG)(ULONG_PTR)PsGetCurrentProcessId());
    if (token != openInfo.Token) {
        RDA_TRACE(RDA_LEVEL_WARN, "create: token mismatch (got %u want %u)", openInfo.Token, token);
        return STATUS_INVALID_PARAMETER;
    }

    if (openInfo.Kind == RDA_OPEN_CLASS_DISK && openInfo.DiskNumber >= g_RdaParameters.MaxDisks) {
        return STATUS_INVALID_PARAMETER; /* reference: disk# <= 199 */
    }
    if (openInfo.Kind == RDA_OPEN_CLASS_DISK_EPM &&
        openInfo.DiskNumber >= RDA_DISK_LIMIT_EUEDKEPM) {
        return STATUS_INVALID_PARAMETER; /* EUEDKEPM parity: disk# < 100 */
    }

    context = (PRDA_OPEN_CONTEXT)RdaAllocZero(sizeof(RDA_OPEN_CONTEXT));
    if (context == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    switch (openInfo.Kind) {
    case RDA_OPEN_CLASS_VOLUME:
        status = RdaResolveVolume(openInfo.VolumeNumber, context);
        break;
    case RDA_OPEN_CLASS_DISK:
        status = RdaResolveDisk(openInfo.DiskNumber, 0, context);
        break;
    case RDA_OPEN_CLASS_DISK_EPM:
        status = RdaResolveDiskEpm(openInfo.DiskNumber, context);
        break;
    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    if (!NT_SUCCESS(status)) {
        RdaFree(context);
        return status;
    }

    /* Reference parity for the FsContext slots: FsContext holds the target
     * file object (informational; the context owns the reference), FsContext2
     * holds the per-handle context. */
    fileObject->FsContext = context->TargetFileObject;
    fileObject->FsContext2 = context;

    RDA_TRACE(RDA_LEVEL_INFO, "create: kind=%u disk=%u vol=%u ss=%u mode=%ld", openInfo.Kind,
              openInfo.DiskNumber, openInfo.VolumeNumber, context->SectorSize, context->Mode);
    return STATUS_SUCCESS;
}

NTSTATUS RdaDispatchCreate(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
    NTSTATUS status;
    PIO_STACK_LOCATION stack;

    UNREFERENCED_PARAMETER(DeviceObject);

    stack = IoGetCurrentIrpStackLocation(Irp);
    status = RdaDispatchCreateInner(stack);

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* CLEANUP: last reference from user mode is closing the handle; release the
 * target bindings now (fix F9). FsContext/FsContext2 are cleared. */
NTSTATUS RdaDispatchCleanup(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
    PIO_STACK_LOCATION stack;
    PFILE_OBJECT fileObject;
    PRDA_OPEN_CONTEXT context;

    UNREFERENCED_PARAMETER(DeviceObject);

    stack = IoGetCurrentIrpStackLocation(Irp);
    fileObject = (stack != NULL) ? stack->FileObject : NULL;

    if (fileObject != NULL) {
        context = (PRDA_OPEN_CONTEXT)fileObject->FsContext2;
        if (context != NULL) {
            fileObject->FsContext = NULL;
            fileObject->FsContext2 = NULL;
            RdaReleaseContext(context);
        }
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS RdaDispatchClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
    /* CLEANUP performed the release; CLOSE just completes (reference parity:
     * a 0-status complete for every close). */
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
