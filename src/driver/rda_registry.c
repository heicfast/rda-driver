/*
 * rda_registry.c - service Parameters reading.
 *
 * Reference drivers read service-key values at DriverEntry (EUDCPEPM read
 * DisplayName/DeviceName/IoctlBase; the naming comes from the service key
 * path). RDA consolidates all knobs under Parameters\:
 *
 *   IoctlBase       DWORD  session-protocol code base (default 0; WinPE
 *                          reference deployments set 0x10000)
 *   MaxDisks        DWORD  open-grammar disk bound (default 200 = reference)
 *   DebugLevel      DWORD  0..5 trace verbosity (default 1)
 *   FilterMode      DWORD  1 = PnP disk-class filter role (WinPE profile)
 *   VolSnapAttach   DWORD  1 = also attach VolSnap devices (PE parity)
 *   SessionsEnabled DWORD  1 = serve the 15-command copy protocol (default)
 *   DeviceName      REG_SZ  override the \Device base name (EUEDKEPM parity)
 *   Sddl            REG_SZ  control-device DACL override
 *
 * Missing values keep defaults; malformed values keep defaults (the
 * reference ignored unreadable values). Registry access happens once at
 * PASSIVE_LEVEL in DriverEntry.
 *
 * Licensed under the MIT license. See LICENSE.
 */

#include "rda_p.h"

typedef struct _RDA_KEY_LOOKUP {
    PCWSTR Name;
    ULONG Type;      /* REG_* expected */
    BOOLEAN IsValue; /* TRUE: Parameters\Value; FALSE: Parameters subkeyless */
} RDA_KEY_LOOKUP;

/* Reads a DWORD from the Parameters subkey. Returns FALSE if absent/malformed. */
static BOOLEAN RdaReadDword(_In_ HANDLE KeyHandle, _In_ PCWSTR ValueName,
                            _Out_ PULONG Value)
{
    NTSTATUS status;
    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    ULONG length = 0;
    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
    UNICODE_STRING name;

    RtlInitUnicodeString(&name, ValueName);
    status = ZwQueryValueKey(KeyHandle, &name, KeyValuePartialInformation, info,
                             sizeof(buffer), &length);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }
    if (info->Type != REG_DWORD || info->DataLength != sizeof(ULONG)) {
        return FALSE;
    }
    *Value = *((ULONG UNALIGNED *)&info->Data[0]);
    return TRUE;
}

/* Reads a REG_SZ into a fixed WCHAR buffer (always NUL-terminated). */
static BOOLEAN RdaReadString(_In_ HANDLE KeyHandle, _In_ PCWSTR ValueName,
                             _Out_ PWSTR Buffer, _In_ ULONG BufferChars)
{
    NTSTATUS status;
    UCHAR buffer[512];
    ULONG length = 0;
    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
    UNICODE_STRING name;

    RtlInitUnicodeString(&name, ValueName);
    status = ZwQueryValueKey(KeyHandle, &name, KeyValuePartialInformation, info,
                             sizeof(buffer), &length);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }
    if (info->Type != REG_SZ || info->DataLength < sizeof(WCHAR)) {
        return FALSE;
    }

    /* Copy up to BufferChars-1 chars, NUL-terminate. Data may not be
     * NUL-terminated in the registry; length-bounded copy handles it. */
    {
        ULONG srcChars = info->DataLength / sizeof(WCHAR);
        ULONG i;

        if (srcChars > BufferChars - 1) {
            srcChars = BufferChars - 1;
        }
        for (i = 0; i < srcChars; i++) {
            Buffer[i] = ((const WCHAR *)info->Data)[i];
        }
        Buffer[srcChars] = UNICODE_NULL;
    }
    return TRUE;
}

NTSTATUS RdaReadParameters(_In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES attributes;
    HANDLE keyHandle = NULL;
    HANDLE paramKey = NULL;
    UNICODE_STRING parametersName;
    ULONG value = 0;

    RDA_ENTER("ReadParameters");

    if (RegistryPath == NULL || RegistryPath->Buffer == NULL || RegistryPath->Length < sizeof(WCHAR)) {
        RDA_EXIT("ReadParameters");
        return STATUS_INVALID_PARAMETER;
    }

    InitializeObjectAttributes(&attributes, RegistryPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL, NULL);
    status = ZwOpenKey(&keyHandle, KEY_READ, &attributes);
    if (!NT_SUCCESS(status)) {
        RDA_TRACE(RDA_LEVEL_WARN, "service key open failed 0x%08X", status);
        RDA_EXIT("ReadParameters");
        return status;
    }

    RtlInitUnicodeString(&parametersName, L"Parameters");
    InitializeObjectAttributes(&attributes, &parametersName,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, keyHandle, NULL);
    status = ZwOpenKey(&paramKey, KEY_READ, &attributes);
    if (NT_SUCCESS(status)) {
        if (RdaReadDword(paramKey, L"IoctlBase", &value)) {
            g_RdaParameters.IoctlBase = value;
        }
        if (RdaReadDword(paramKey, L"MaxDisks", &value)) {
            /* Clamp to a sane range; reference hard-fixed 200/100. */
            if (value >= 2 && value <= 1024) {
                g_RdaParameters.MaxDisks = value;
            }
        }
        if (RdaReadDword(paramKey, L"DebugLevel", &value)) {
            if (value <= RDA_LEVEL_VERBOSE) {
                g_RdaParameters.DebugLevel = value;
                g_RdaDebugLevel = value;
            }
        }
        if (RdaReadDword(paramKey, L"FilterMode", &value)) {
            g_RdaParameters.FilterMode = (value != 0) ? 1 : 0;
        }
        if (RdaReadDword(paramKey, L"VolSnapAttach", &value)) {
            g_RdaParameters.VolSnapAttach = (value != 0) ? 1 : 0;
        }
        if (RdaReadDword(paramKey, L"SessionsEnabled", &value)) {
            g_RdaParameters.SessionsEnabled = (value != 0) ? 1 : 0;
        }
        if (RdaReadString(paramKey, L"DeviceName", g_RdaParameters.DeviceName,
                          RDA_NAME_BUFFER_CHARS) &&
            g_RdaParameters.DeviceName[0] != UNICODE_NULL) {
            g_RdaParameters.UseDeviceName = TRUE;
        }
        if (RdaReadString(paramKey, L"Sddl", g_RdaParameters.Sddl,
                          RTL_NUMBER_OF(g_RdaParameters.Sddl)) &&
            g_RdaParameters.Sddl[0] != UNICODE_NULL) {
            RDA_TRACE(RDA_LEVEL_INFO, "SDDL override configured");
        }
        ZwClose(paramKey);
    } else {
        RDA_TRACE(RDA_LEVEL_WARN, "Parameters subkey absent (defaults in effect) 0x%08X",
                  status);
    }

    ZwClose(keyHandle);

    RDA_TRACE(RDA_LEVEL_INFO,
              "parameters: IoctlBase=0x%X MaxDisks=%u DebugLevel=%u Filter=%u VolSnap=%u "
              "Sessions=%u DeviceNameOverride=%d",
              g_RdaParameters.IoctlBase, g_RdaParameters.MaxDisks, g_RdaParameters.DebugLevel,
              g_RdaParameters.FilterMode, g_RdaParameters.VolSnapAttach,
              g_RdaParameters.SessionsEnabled, (int)g_RdaParameters.UseDeviceName);

    RDA_EXIT("ReadParameters");
    return STATUS_SUCCESS;
}
