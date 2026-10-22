/*
 * rda_ident.c - process/file identity services (IOCTLs 0x60002400/0x60002404).
 *
 * Reference parity notes:
 *  - GetProcName resolved a caller-supplied PID via NtOpenProcess(0x20000) +
 *    ZwQueryInformationProcess(ProcessImageFileName). RDA uses the
 *    documented kernel APIs PsLookupProcessByProcessId + SeLocateProcessImageName
 *    (ntifs.h) - same observable result (image path of any PID), no process
 *    handle juggling, no undocumented NtOpenProcess import.
 *  - GetFileObjName resolves a caller-supplied HANDLE via
 *    ObReferenceObjectByHandle(..., *IoFileObjectType, KernelMode) then
 *    ObQueryNameString(FileObject->DeviceObject) + FileName append - the
 *    reference chain, implemented with bounded buffers.
 *  - Both write into the METHOD_BUFFERED SystemBuffer; Information = byte
 *    length including the terminating NUL (reference: len + 2).
 *
 * These services are privileged information disclosure primitives; they are
 * reachable only through the control device, whose DACL defaults to
 * administrators + SYSTEM (fix F3).
 *
 * Licensed under the MIT license. See LICENSE.
 */

#include "rda_p.h"
#include <ntifs.h>

/* Copy a UNICODE_STRING into a BYTE-strided kernel buffer with NUL
 * termination. Returns byte length written (including NUL) via Information. */
static NTSTATUS RdaCopyUnicodeToBuffer(_In_ PUNICODE_STRING Source,
                                       _Out_writes_bytes_(BufferBytes) PVOID Buffer,
                                       _In_ ULONG BufferBytes, _Out_ PULONG_PTR Information)
{
    ULONG bytes;
    ULONG i;

    if (Source->Length > BufferBytes - sizeof(WCHAR)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    bytes = Source->Length; /* even: WCHAR-aligned */
    for (i = 0; i < bytes / sizeof(WCHAR); i++) {
        ((PWCHAR)Buffer)[i] = Source->Buffer[i];
    }
    ((PWCHAR)Buffer)[bytes / sizeof(WCHAR)] = UNICODE_NULL;
    *Information = bytes + sizeof(WCHAR);
    return STATUS_SUCCESS;
}

NTSTATUS RdaIoctlGetProcName(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack)
{
    NTSTATUS status;
    ULONG inLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID systemBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG pid;
    PEPROCESS process = NULL;
    PUNICODE_STRING imageName = NULL;

    if (inLength != RDA_IDENT_IN_LEN || outLength < RDA_IDENT_MIN_OUT_LEN ||
        systemBuffer == NULL) {
        RDA_TRACE(RDA_LEVEL_WARN, "[GetProcName] para error %u,%u!", inLength, outLength);
        return STATUS_INVALID_PARAMETER;
    }

    pid = *(PULONG)systemBuffer;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
    if (!NT_SUCCESS(status)) {
        RDA_TRACE(RDA_LEVEL_WARN, "[GetProcName] lookup error 0x%x!", status);
        return status;
    }

    status = SeLocateProcessImageName(process, &imageName);
    if (NT_SUCCESS(status)) {
        status = RdaCopyUnicodeToBuffer(imageName, systemBuffer, outLength,
                                        &Irp->IoStatus.Information);
        if (imageName->Buffer != NULL) {
            ExFreePool(imageName->Buffer);
        }
        ExFreePool(imageName);
    } else {
        RDA_TRACE(RDA_LEVEL_WARN, "[GetProcName] image name error 0x%x!", status);
    }

    ObDereferenceObject(process);
    return status;
}

NTSTATUS RdaIoctlGetFileObjNameCore(_In_ HANDLE FileHandle,
                                    _Out_writes_bytes_(BufferBytes) PVOID Buffer,
                                    _In_ ULONG BufferBytes, _Out_ PULONG_PTR Information)
{
    NTSTATUS status;
    PFILE_OBJECT fileObject = NULL;
    PBYTE nameBuffer = NULL;
    PUNICODE_STRING deviceName;
    UNICODE_STRING combined;
    ULONG returned = 0;
    USHORT fileNameBytes;

    *Information = 0;

    status = ObReferenceObjectByHandle(FileHandle, 0, *IoFileObjectType, KernelMode,
                                        (PVOID *)&fileObject, NULL);
    if (!NT_SUCCESS(status)) {
        RDA_TRACE(RDA_LEVEL_WARN, "[GetFileObjName] ObReferenceObjectByHandle error 0x%x!",
                  status);
        return status;
    }

    if (fileObject->DeviceObject == NULL) {
        ObDereferenceObject(fileObject);
        return STATUS_INVALID_HANDLE;
    }

    nameBuffer = (PBYTE)RdaAlloc(RDA_QUERY_NAME_BUFFER);
    if (nameBuffer == NULL) {
        ObDereferenceObject(fileObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ObQueryNameString(fileObject->DeviceObject, (POBJECT_NAME_INFORMATION)nameBuffer,
                               RDA_QUERY_NAME_BUFFER, &returned);
    if (!NT_SUCCESS(status)) {
        goto Done;
    }

    deviceName = &((POBJECT_NAME_INFORMATION)nameBuffer)->Name;

    /* Compose: device name + file name (reference parity: ObQueryNameString on
     * the DeviceObject, then RtlAppendUnicodeStringToString of FileName). */
    fileNameBytes = fileObject->FileName.Length;
    combined.Buffer = (PWCHAR)RdaAllocZero((SIZE_T)deviceName->Length + fileNameBytes +
                                           sizeof(WCHAR));
    if (combined.Buffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
    }
    combined.MaximumLength = deviceName->Length + fileNameBytes + sizeof(WCHAR);
    combined.Length = 0;

    status = RtlAppendUnicodeStringToString(&combined, deviceName);
    if (NT_SUCCESS(status)) {
        status = RtlAppendUnicodeStringToString(&combined, &fileObject->FileName);
    }
    if (NT_SUCCESS(status)) {
        status = RdaCopyUnicodeToBuffer(&combined, Buffer, BufferBytes, Information);
    }
    RdaFree(combined.Buffer);

Done:
    RdaFree(nameBuffer);
    ObDereferenceObject(fileObject);
    return status;
}

NTSTATUS RdaIoctlGetFileObjName(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack)
{
    ULONG inLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID systemBuffer = Irp->AssociatedIrp.SystemBuffer;

    if (inLength != RDA_IDENT_IN_LEN || outLength < RDA_IDENT_MIN_OUT_LEN ||
        systemBuffer == NULL) {
        RDA_TRACE(RDA_LEVEL_WARN, "[GetFileObjName] para error %u,%u!", inLength, outLength);
        return STATUS_INVALID_PARAMETER;
    }
    return RdaIoctlGetFileObjNameCore((HANDLE)(ULONG_PTR)(*(PULONG)systemBuffer), systemBuffer,
                                      outLength, &Irp->IoStatus.Information);
}

NTSTATUS RdaIoctlGetDiskContextMode(_In_ PIRP Irp, _In_ PRDA_OPEN_CONTEXT Context)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG outLength = stack->Parameters.DeviceIoControl.OutputBufferLength;

    if (outLength != sizeof(ULONG) || Irp->AssociatedIrp.SystemBuffer == NULL) {
        RDA_TRACE(RDA_LEVEL_WARN, "[GetDiskContextMode] para error %u!", outLength);
        return STATUS_INVALID_PARAMETER;
    }
    *(PLONG)Irp->AssociatedIrp.SystemBuffer = Context->Mode;
    Irp->IoStatus.Information = sizeof(ULONG);
    return STATUS_SUCCESS;
}
