/*
 * rda_ioctl.c - IRP_MJ_DEVICE_CONTROL.
 *
 * Routing (reference-exact shape, extended):
 *
 *   1. Normalized session code: (code - IoctlBase) in
 *      0x800C2AC8..0x800C2B38  ->  rda_session.c engine (EUDCPEPM merge).
 *      The normalization base is the registry IoctlBase (default 0; the
 *      reference WinPE deployment sets 0x10000).
 *
 *   2. Target-bound handles (FsContext2 with target):
 *        0x60002408 GetDiskContextMode  -> rda_ident.c
 *        everything else               -> pass-through proxy to the
 *                                         target's top-of-stack
 *        (reference: 0x60002400/04 on a bound handle also pass through.)
 *
 *   3. Global handles (no target):
 *        0x60002400 GetProcName    -> rda_ident.c
 *        0x60002404 GetFileObjName -> rda_ident.c
 *        0x60002440 GetInfo        -> extended (RDA)
 *        0x60002444 OpenTarget     -> extended (RDA)
 *        0x60002448 GetVersion     -> extended (RDA)
 *        else                      -> STATUS_INVALID_PARAMETER
 *
 * Pass-through (fix F10): the reference forwarded the METHOD_BUFFERED
 * SystemBuffer as both input and output. RDA honors the transfer method:
 *   - METHOD_BUFFERED:      in = out = SystemBuffer (reference parity)
 *   - METHOD_IN/OUT_DIRECT: in = SystemBuffer, out = Irp->UserBuffer
 *     (IoBuildDeviceIoControlRequest probes/locks at PASSIVE in context)
 *   - METHOD_NEITHER:       STATUS_NOT_SUPPORTED (documented; the reference
 *     passed SystemBuffer which is invalid for NEITHER anyway).
 *
 * Licensed under the MIT license. See LICENSE.
 */

#include "rda_p.h"

static BOOLEAN RdaIsSessionCode(_In_ ULONG Code, _Out_ PULONG CustomCode)
{
    ULONG normalized;

    /* IoctlBase defaults to 0; the reference PE deployment sets 0x10000. */
    normalized = (ULONG)(Code - g_RdaParameters.IoctlBase);
    if (normalized >= RDA_SESSION_CODE_GET_VERSION &&
        normalized <= RDA_SESSION_CODE_CANCEL) {
        *CustomCode = normalized;
        return TRUE;
    }
    return FALSE;
}

/* Extended info output. */
static NTSTATUS RdaIoctlGetInfoInner(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack)
{
    PRDA_DRIVER_INFO info;
    ULONG outLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;

    if (outLength < sizeof(RDA_DRIVER_INFO) || Irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    info = (PRDA_DRIVER_INFO)Irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(info, sizeof(RDA_DRIVER_INFO));
    info->StructSize = sizeof(RDA_DRIVER_INFO);
    info->MajorVersion = RDA_VERSION_MAJOR;
    info->MinorVersion = RDA_VERSION_MINOR;
    info->Flags = 0;
    if (g_RdaParameters.FilterMode != 0) {
        info->Flags |= RDA_INFO_FLAG_FILTER_MODE;
    }
    if (g_RdaParameters.SessionsEnabled != 0) {
        info->Flags |= RDA_INFO_FLAG_SESSIONS;
    }
    info->MaxDisks = g_RdaParameters.MaxDisks;
    info->IoctlBase = g_RdaParameters.IoctlBase;
    Irp->IoStatus.Information = sizeof(RDA_DRIVER_INFO);
    return STATUS_SUCCESS;
}

static NTSTATUS RdaIoctlGetVersionInner(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack)
{
    ULONG outLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;

    if (outLength < sizeof(ULONG64) || Irp->AssociatedIrp.SystemBuffer == NULL) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    *(PULONG64)Irp->AssociatedIrp.SystemBuffer =
        ((ULONG64)RDA_VERSION_MAJOR << 32) | RDA_VERSION_MINOR;
    Irp->IoStatus.Information = sizeof(ULONG64);
    return STATUS_SUCCESS;
}

/* Extended explicit open: IOCTL_RDA_OPEN_TARGET binds a target without the
 * path-string grammar. Requires the PID-token to be absent by design: the
 * device DACL is the security boundary. */
static NTSTATUS RdaIoctlOpenTargetInner(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack,
                                        _In_opt_ PRDA_OPEN_CONTEXT CurrentContext)
{
    PRDA_OPEN_TARGET_IN input;
    PRDA_OPEN_CONTEXT context;
    NTSTATUS status;
    ULONG inLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    PFILE_OBJECT fileObject = Stack->FileObject;

    if (inLength < sizeof(RDA_OPEN_TARGET_IN) || outLength != 0 ||
        Irp->AssociatedIrp.SystemBuffer == NULL || fileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    input = (PRDA_OPEN_TARGET_IN)Irp->AssociatedIrp.SystemBuffer;
    if (input->StructSize < sizeof(RDA_OPEN_TARGET_IN)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (fileObject->FsContext2 != NULL) {
        return STATUS_INVALID_DEVICE_STATE; /* already bound; close first */
    }

    switch (input->Kind) {
    case RDA_TARGET_KIND_VOLUME:
        if (CurrentContext != NULL) {
            return STATUS_INVALID_DEVICE_STATE;
        }
        break;
    case RDA_TARGET_KIND_DISK:
        if (input->DiskNumber >= RDA_DISK_LIMIT_EUEDKEPM) {
            return STATUS_INVALID_PARAMETER;
        }
        break;
    case RDA_TARGET_KIND_DISK_PART:
        if (input->DiskNumber >= g_RdaParameters.MaxDisks) {
            return STATUS_INVALID_PARAMETER;
        }
        break;
    default:
        return STATUS_INVALID_PARAMETER;
    }

    context = (PRDA_OPEN_CONTEXT)RdaAllocZero(sizeof(RDA_OPEN_CONTEXT));
    if (context == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    switch (input->Kind) {
    case RDA_TARGET_KIND_VOLUME:
        status = RdaResolveVolume(input->VolumeNumber, context);
        break;
    case RDA_TARGET_KIND_DISK:
        status = RdaResolveDiskEpm(input->DiskNumber, context);
        break;
    case RDA_TARGET_KIND_DISK_PART:
    default:
        status = RdaResolveDisk(input->DiskNumber, input->PartNumber, context);
        break;
    }

    if (!NT_SUCCESS(status)) {
        RdaFree(context);
        return status;
    }

    fileObject->FsContext = context->TargetFileObject;
    fileObject->FsContext2 = context;
    RDA_TRACE(RDA_LEVEL_INFO, "explicit open: kind=%u disk=%u vol=%u", input->Kind,
              input->DiskNumber, input->VolumeNumber);
    return STATUS_SUCCESS;
}

NTSTATUS RdaPassThroughIoctl(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack,
                             _In_ PRDA_OPEN_CONTEXT Context)
{
    NTSTATUS status;
    KEVENT event;
    PIRP forward;
    IO_STATUS_BLOCK iosb;
    PDEVICE_OBJECT top;
    ULONG code = Stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG method = code & 3;
    PVOID outBuffer;

    top = IoGetAttachedDeviceReference(Context->TargetDevice);
    if (top == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    switch (method) {
    case METHOD_BUFFERED:
        outBuffer = Irp->AssociatedIrp.SystemBuffer;
        if (outBuffer == NULL && (inLength != 0 || outLength != 0)) {
            ObDereferenceObject(top);
            return STATUS_INVALID_PARAMETER;
        }
        break;
    case METHOD_IN_DIRECT:
    case METHOD_OUT_DIRECT:
        outBuffer = Irp->UserBuffer;
        if (outBuffer == NULL && outLength != 0) {
            ObDereferenceObject(top);
            return STATUS_INVALID_PARAMETER;
        }
        break;
    default: /* METHOD_NEITHER */
        RDA_TRACE(RDA_LEVEL_WARN, "pass-through: METHOD_NEITHER code 0x%08X rejected", code);
        ObDereferenceObject(top);
        return STATUS_NOT_SUPPORTED;
    }

    KeInitializeEvent(&event, NotificationEvent, FALSE);
    RtlZeroMemory(&iosb, sizeof(iosb));

    forward = IoBuildDeviceIoControlRequest(code, top, Irp->AssociatedIrp.SystemBuffer,
                                            inLength, outBuffer, outLength, FALSE, &event,
                                            &iosb);
    if (forward == NULL) {
        ObDereferenceObject(top);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IoCallDriver(top, forward);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    }

    Irp->IoStatus.Information = iosb.Information;
    ObDereferenceObject(top);
    return status;
}

static NTSTATUS RdaDispatchDeviceControlInner(_In_ PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PRDA_OPEN_CONTEXT context = NULL;
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG customCode;
    NTSTATUS status;

    if (stack->FileObject != NULL) {
        context = (PRDA_OPEN_CONTEXT)stack->FileObject->FsContext2;
    }

    /* 1. Session protocol (served on any handle when enabled). */
    if (g_RdaParameters.SessionsEnabled != 0 && RdaIsSessionCode(code, &customCode)) {
        return RdaSessionDispatch(customCode, Irp, stack, context);
    }

    /* 2. Bound handles: GetDiskContextMode or pass-through. */
    if (context != NULL && context->TargetDevice != NULL) {
        if (code == IOCTL_RDA_GET_DISK_CONTEXT_MODE) {
            return RdaIoctlGetDiskContextMode(Irp, context);
        }
        return RdaPassThroughIoctl(Irp, stack, context);
    }

    /* 3. Global handles: identity + extended interfaces. */
    switch (code) {
    case IOCTL_RDA_GET_PROC_NAME:
        return RdaIoctlGetProcName(Irp, stack);
    case IOCTL_RDA_GET_FILE_OBJ_NAME:
        return RdaIoctlGetFileObjName(Irp, stack);
    case IOCTL_RDA_GET_INFO:
        return RdaIoctlGetInfoInner(Irp, stack);
    case IOCTL_RDA_GET_VERSION:
        return RdaIoctlGetVersionInner(Irp, stack);
    case IOCTL_RDA_OPEN_TARGET:
        return RdaIoctlOpenTargetInner(Irp, stack, context);
    default:
        RDA_TRACE(RDA_LEVEL_WARN, "global ioctl 0x%08X rejected", code);
        return STATUS_INVALID_PARAMETER;
    }
}

NTSTATUS RdaDispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(DeviceObject);

    status = RdaDispatchDeviceControlInner(Irp);

    if (status == STATUS_PENDING) {
        /* Async paths (GETNEXTBLOCK pump) marked the IRP pending and own
         * its completion; touching IoStatus here would race the worker. */
        return STATUS_PENDING;
    }

    if (!NT_SUCCESS(status)) {
        Irp->IoStatus.Information = 0;
    }
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
