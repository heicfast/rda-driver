/*
 * rda_control.c - control device: naming, security, lifecycle.
 *
 * Naming (reference-exact, verified from the eprdtdrv DriverEntry decompile):
 *   base = last path component of the DriverEntry RegistryPath, UPPERCASED
 *   device = "\Device\"  + base    (fallback "EPMNTDRV")
 *   dos    = "\DosDevices\" + base (fallback "EPMNTDRV")
 * Consequence: install the same rda.sys under any service name and it
 * serves that name's device identity - drop-in for eprdtdrv/ebrntdrv/
 * epmdkdrv, and %s%d hot-upgrade variants coexist without conflicts.
 *
 * Security (deviation F2, documented): the reference called IoCreateDevice
 * (default security, no explicit DACL). RDA uses IoCreateDeviceSecure with
 * an admin/SYSTEM-only SDDL default, overridable via Parameters\Sddl.
 *
 * Device type: FILE_DEVICE_UNKNOWN (0x22, reference parity) with
 * DO_DIRECT_IO (0x10) so the IO manager builds MDLs for READ/WRITE.
 *
 * Licensed under the MIT license. See LICENSE.
 */

#include "rda_p.h"

/* Extracts the UPPERCASED last component of the registry path (the service
 * name) into BaseName. Returns FALSE when the path is unusable (the
 * reference then fell back to "EPMNTDRV"). */
static BOOLEAN RdaDeriveBaseName(_In_opt_ PUNICODE_STRING RegistryPath,
                                 _Out_ PUNICODE_STRING BaseName,
                                 _Out_writes_(BufferChars) PWCHAR Buffer, _In_ ULONG BufferChars) {
    PCWSTR source;
    ULONG lengthChars;
    ULONG lastSep;
    ULONG i;
    ULONG outChars;

    if (RegistryPath == NULL || RegistryPath->Buffer == NULL ||
        RegistryPath->Length < 2 * sizeof(WCHAR)) {
        return FALSE;
    }

    source = RegistryPath->Buffer;
    lengthChars = RegistryPath->Length / sizeof(WCHAR);

    /* Reference parity: scan backward for the last '\'. */
    lastSep = lengthChars;
    for (i = lengthChars; i > 0; i--) {
        if (source[i - 1] == L'\\') {
            lastSep = i - 1;
            break;
        }
    }
    if (lastSep == lengthChars) {
        return FALSE; /* no separator at all */
    }

    outChars = lengthChars - lastSep - 1;
    if (outChars == 0 || outChars >= BufferChars) {
        return FALSE;
    }
    for (i = 0; i < outChars; i++) {
        WCHAR c = source[lastSep + 1 + i];
        if (c == L'\\') {
            return FALSE; /* pathological separator run */
        }
        Buffer[i] = RtlUpcaseUnicodeChar(c);
    }
    Buffer[outChars] = UNICODE_NULL;

    RtlInitUnicodeString(BaseName, Buffer);
    return TRUE;
}

NTSTATUS RdaCreateControlDevice(_In_ PDRIVER_OBJECT DriverObject,
                                _In_opt_ PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    PWCHAR deviceBuffer = NULL;
    PWCHAR dosBuffer = NULL;
    const ULONG nameBufferBytes = 2 * RDA_NAME_BUFFER_CHARS * sizeof(WCHAR);
    UNICODE_STRING sddl;
    PCUNICODE_STRING sddlToUse;
    PWCHAR baseBuffer;
    UNICODE_STRING baseName;

    RDA_ENTER("CreateControlDevice");

    /* Resolve the base name: Parameters\DeviceName override (EUEDKEPM
     * parity), else service-name derivation, else the reference fallback.
     * The derived-name scratch is heap so both composition buffers can be
     * heap-owned globals that outlive this function. */
    baseBuffer = (PWCHAR)RdaAllocZero(RDA_NAME_BUFFER_CHARS * sizeof(WCHAR));
    if (baseBuffer == NULL) {
        RDA_EXIT("CreateControlDevice");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (g_RdaParameters.UseDeviceName) {
        RtlInitUnicodeString(&baseName, g_RdaParameters.DeviceName);
    } else if (!RdaDeriveBaseName(RegistryPath, &baseName, baseBuffer, RDA_NAME_BUFFER_CHARS)) {
        RtlInitUnicodeString(&baseName, RDA_FALLBACK_BASE_NAME);
        RDA_TRACE(RDA_LEVEL_WARN, "naming fell back to %ws", RDA_FALLBACK_BASE_NAME);
    }

    deviceBuffer = (PWCHAR)RdaAllocZero(nameBufferBytes);
    dosBuffer = (PWCHAR)RdaAllocZero(nameBufferBytes);
    if (deviceBuffer == NULL || dosBuffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Fail;
    }

    /* Compose \Device\<base> and \DosDevices\<base> (reference kept both
     * names in sync; both buffers are driver-owned). */
    {
        UNICODE_STRING prefix;
        RtlInitUnicodeString(&g_RdaDeviceName, deviceBuffer);
        g_RdaDeviceName.MaximumLength = nameBufferBytes;
        RtlInitUnicodeString(&prefix, RDA_DEV_PREFIX);
        status = RtlAppendUnicodeStringToString(&g_RdaDeviceName, &prefix);
        if (NT_SUCCESS(status)) {
            status = RtlAppendUnicodeStringToString(&g_RdaDeviceName, &baseName);
        }
        if (!NT_SUCCESS(status)) {
            RDA_TRACE(RDA_LEVEL_ERROR, "device name compose failed 0x%08X", status);
            goto Fail;
        }

        RtlInitUnicodeString(&g_RdaDosName, dosBuffer);
        g_RdaDosName.MaximumLength = nameBufferBytes;
        RtlInitUnicodeString(&prefix, RDA_DOS_PREFIX);
        status = RtlAppendUnicodeStringToString(&g_RdaDosName, &prefix);
        if (NT_SUCCESS(status)) {
            status = RtlAppendUnicodeStringToString(&g_RdaDosName, &baseName);
        }
        if (!NT_SUCCESS(status)) {
            goto Fail;
        }
    }

    RdaFree(baseBuffer);
    baseBuffer = NULL;

    if (g_RdaParameters.Sddl[0] != UNICODE_NULL) {
        RtlInitUnicodeString(&sddl, g_RdaParameters.Sddl);
        sddlToUse = &sddl;
    } else {
        RtlInitUnicodeString(&sddl, RDA_DEFAULT_SDDL);
        sddlToUse = &sddl;
    }

    /* IoCreateDeviceSecure (wdmsec): named device with an explicit DACL and
     * a class GUID admins can override. The reference used plain
     * IoCreateDevice with default security (fix F2). */
    status = IoCreateDeviceSecure(DriverObject, 0, &g_RdaDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE,
                                  sddlToUse, &RDA_DEVICE_CLASS_GUID, &g_RdaControlDevice);
    if (!NT_SUCCESS(status)) {
        RDA_TRACE(RDA_LEVEL_ERROR, "[RDA]IoCreateDevice ret,0x%x,%wZ", status, &g_RdaDeviceName);
        goto Fail;
    }

    /* Reference parity: DO_DIRECT_IO for the READ/WRITE MDL path. */
    g_RdaControlDevice->Flags |= DO_DIRECT_IO;

    status = IoCreateSymbolicLink(&g_RdaDosName, &g_RdaDeviceName);
    if (!NT_SUCCESS(status)) {
        RDA_TRACE(RDA_LEVEL_ERROR, "[RDA]IoCreateSymbolicLink ret,0x%x,%wZ", status, &g_RdaDosName);
        IoDeleteDevice(g_RdaControlDevice);
        g_RdaControlDevice = NULL;
        goto Fail;
    }

    RDA_TRACE(RDA_LEVEL_INFO, "control device %wZ (%wZ) created", &g_RdaDeviceName, &g_RdaDosName);
    RDA_EXIT("CreateControlDevice");
    return STATUS_SUCCESS;

Fail:
    if (baseBuffer != NULL) {
        RdaFree(baseBuffer);
    }
    if (g_RdaDeviceName.Buffer != NULL) {
        RdaFree(g_RdaDeviceName.Buffer);
        RtlInitUnicodeString(&g_RdaDeviceName, NULL);
    }
    if (g_RdaDosName.Buffer != NULL) {
        RdaFree(g_RdaDosName.Buffer);
        RtlInitUnicodeString(&g_RdaDosName, NULL);
    }
    RDA_EXIT("CreateControlDevice");
    return status;
}

VOID RdaDeleteControlDevice(VOID) {
    if (g_RdaDosName.Buffer != NULL) {
        IoDeleteSymbolicLink(&g_RdaDosName);
        RdaFree(g_RdaDosName.Buffer);
        RtlInitUnicodeString(&g_RdaDosName, NULL);
    }
    if (g_RdaDeviceName.Buffer != NULL) {
        RdaFree(g_RdaDeviceName.Buffer);
        RtlInitUnicodeString(&g_RdaDeviceName, NULL);
    }
    if (g_RdaControlDevice != NULL) {
        IoDeleteDevice(g_RdaControlDevice);
        g_RdaControlDevice = NULL;
    }
    RtlInitUnicodeString(&g_RdaDeviceName, NULL);
}
