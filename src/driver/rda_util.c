/*
 * rda_util.c - pool and string helpers.
 *
 * Pool policy:
 *  - All driver allocations use ExAllocatePoolWithTag with the 'rda1' tag
 *    (the reference family used 'esdr' / 'ECLU'; RDA uses its own tag).
 *    ExAllocatePoolWithTag remains the correct API for Win7 SP1 targets;
 *    the newer ExAllocatePool2 is Win10 2004+ only and must NOT be imported.
 *    The WDK deprecation warning for ExAllocatePoolWithTag is suppressed in
 *    exactly one place (here) with the rationale; everything else stays
 *    clean at /W4 /WX.
 *  - RdaAllocZero guarantees zero-initialization (the reference relied on
 *    explicit field init; zero-by-default removes a whole defect class).
 *  - Freeing is tag-checked to catch cross-pool frees in verifier runs.
 *
 * Strings: bounded composition only; RtlAppendUnicodeStringToString used
 * with pre-sized buffers (no RtlStringCbPrintfW dependency in hot paths;
 * device-name formatting uses the Rtl* string builder, reference parity).
 *
 * Licensed under the MIT license. See LICENSE.
 */

#include "rda_p.h"

/* ExAllocatePoolWithTag is deprecated in newer WDK headers (in favor of
 * ExAllocatePool2) but ExAllocatePool2 requires Windows 10 2004+; this
 * driver supports Windows 7 SP1 and therefore must stay on the old API.
 * C4996 is confined to this TU by design. */
#pragma warning(disable : 4996)

_IRQL_requires_max_(DISPATCH_LEVEL) PVOID RdaAlloc(_In_ SIZE_T Bytes) {
    return ExAllocatePoolWithTag(NonPagedPool, Bytes, RDA_POOL_TAG);
}

_IRQL_requires_max_(PASSIVE_LEVEL) PVOID RdaAllocZero(_In_ SIZE_T Bytes) {
    PVOID memory = RdaAlloc(Bytes);
    if (memory != NULL) {
        RtlZeroMemory(memory, Bytes);
    }
    return memory;
}

_IRQL_requires_max_(DISPATCH_LEVEL) VOID RdaFree(_In_opt_ PVOID Memory) {
    if (Memory != NULL) {
        ExFreePoolWithTag(Memory, RDA_POOL_TAG);
    }
}

/* Formats "\Device\Harddisk%u\Partition0"-style names into a caller-owned
 * stack buffer + UNICODE_STRING (bounded, no printf). Handles ULONG numbers
 * only, which is all the reference ever formatted. */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    RdaFormatDeviceName(_Out_ PUNICODE_STRING Name, _In_z_ PCWSTR Format, _In_ ULONG Number) {
    return RdaFormatDeviceName2(Name, Format, Number, Number);
}

/* Two-number form. Used by the DR fallback: the reference formatted
 * "\Device\Harddisk%u\DR%u" with a SINGLE vararg (the second %u consumed
 * uninitialized stack - decompile-verified FUN_000110b0, G4). The retry
 * could therefore essentially never resolve. RDA formats the disk number
 * deterministically into both slots (documented divergence from garbage). */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    RdaFormatDeviceName2(_Out_ PUNICODE_STRING Name, _In_z_ PCWSTR Format, _In_ ULONG Number,
                         _In_ ULONG Number2) {
    NTSTATUS status;
    UNICODE_STRING numberString;
    WCHAR numberBuffer[12];
    UNICODE_STRING number2String;
    WCHAR number2Buffer[12];
    UNICODE_STRING prefix;
    PCWSTR cursor;
    const WCHAR *suffix;
    PCWSTR cursor2;

    RtlInitUnicodeString(&numberString, NULL);
    numberString.Buffer = numberBuffer;
    numberString.MaximumLength = sizeof(numberBuffer);
    status = RtlIntegerToUnicodeString(Number, 10, &numberString);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&number2String, NULL);
    number2String.Buffer = number2Buffer;
    number2String.MaximumLength = sizeof(number2Buffer);
    status = RtlIntegerToUnicodeString(Number2, 10, &number2String);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Split the format at the first %u. */
    cursor = Format;
    while (*cursor != UNICODE_NULL && *cursor != L'%') {
        cursor++;
    }
    if (*cursor != L'%') {
        return STATUS_INVALID_PARAMETER;
    }
    suffix = cursor + 2; /* skip %u */

    RtlInitUnicodeString(&prefix, NULL);
    prefix.Buffer = (PWCH)Format;
    prefix.Length = (USHORT)((cursor - Format) * sizeof(WCHAR));
    prefix.MaximumLength = prefix.Length;

    status = RtlAppendUnicodeStringToString(Name, &prefix);
    if (NT_SUCCESS(status)) {
        status = RtlAppendUnicodeStringToString(Name, &numberString);
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Optional second %u in the suffix. */
    cursor2 = suffix;
    while (*cursor2 != UNICODE_NULL && *cursor2 != L'%') {
        cursor2++;
    }
    if (*cursor2 == L'%') {
        UNICODE_STRING mid;
        UNICODE_STRING tail;

        RtlInitUnicodeString(&mid, NULL);
        mid.Buffer = (PWCH)suffix;
        mid.Length = (USHORT)((cursor2 - suffix) * sizeof(WCHAR));
        mid.MaximumLength = mid.Length;
        status = RtlAppendUnicodeStringToString(Name, &mid);
        if (NT_SUCCESS(status)) {
            status = RtlAppendUnicodeStringToString(Name, &number2String);
        }
        if (NT_SUCCESS(status)) {
            RtlInitUnicodeString(&tail, cursor2 + 2);
            status = RtlAppendUnicodeStringToString(Name, &tail);
        }
        return status;
    }

    {
        UNICODE_STRING suffixString;
        RtlInitUnicodeString(&suffixString, suffix);
        return RtlAppendUnicodeStringToString(Name, &suffixString);
    }
}
