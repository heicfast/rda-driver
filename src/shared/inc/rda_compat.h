/*
 * rda_compat.h - Shared, portable wire-grammar logic for the RDA driver.
 *
 * This header contains ONLY pure functions operating on (pointer, length)
 * ranges: no kernel APIs, no CRT dependencies beyond integer types. It is
 * compiled into:
 *   - the kernel driver (IRP_MJ_CREATE path classification)
 *   - the user-mode client/test tools
 *   - the portable unit tests (Linux + Windows)
 *
 * Grammar implemented (reference-exact; see docs/ground-truth-contracts.md):
 *
 *   \<PID-TOKEN>\Volume\<N>       volume branch (EPMNtDrv)
 *   \<PID-TOKEN>\<disk>\<part>    disk branch (EPMNtDrv) - the reference
 *                                 driver parses ONLY the first number and
 *                                 ignores everything after it; the third
 *                                 segment selects EPMNtDrv resolution
 *                                 semantics (limit 200, DR fallback,
 *                                 walk-to-Harddisk-layer + mode flag).
 *   \<PID-TOKEN>\<disk>           EUEDKEPM variant (limit 100, walk-to-
 *                                 \Driver\Disk target, no fallback)
 *
 * All comparisons are over NON-NUL-TERMINATED ranges: the reference drivers
 * parsed the FILE_OBJECT name buffer with explicit lengths and the same
 * discipline is preserved here.
 *
 * Licensed under the MIT license. See LICENSE.
 */

#ifndef _RDA_COMPAT_H_
#define _RDA_COMPAT_H_

#include "rda_ioctl.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * RdaComputePidToken - the reference PID-token transform, implemented as a
 * function (not a macro) so byte-sum shifts happen in ULONG arithmetic.
 * A macro version would promote unsigned char sums (up to 0x1FE) to int and
 * shifting those by 24 overflows a 32-bit int - undefined behavior that both
 * MSVC /W4 and gcc -Werror reject.
 *
 *   b0..b3 = little-endian bytes of the 32-bit process id
 *   token  = b0 | (b0+b1)<<8 | (b1+b2)<<16 | (b2+b3)<<24   (8-bit wraps)
 */
static __inline ULONG RdaComputePidToken(ULONG Pid) {
    unsigned char b0 = (unsigned char)(Pid & 0xff);
    unsigned char b1 = (unsigned char)((Pid >> 8) & 0xff);
    unsigned char b2 = (unsigned char)((Pid >> 16) & 0xff);
    unsigned char b3 = (unsigned char)((Pid >> 24) & 0xff);

    return (ULONG)b0 | ((ULONG)(unsigned char)(b0 + b1) << 8) |
           ((ULONG)(unsigned char)(b1 + b2) << 16) | ((ULONG)(unsigned char)(b2 + b3) << 24);
}

/* Result kinds for RdaClassifyOpenPath. */
#define RDA_OPEN_CLASS_REJECT 0 /* malformed token/target - STATUS_INVALID_PARAMETER */
#define RDA_OPEN_CLASS_GLOBAL                                                                      \
    1                             /* name < 2 wchars: no-target handle (EPMNtDrv                   \
                                   * completes these SUCCESSFULLY - global-handle /                \
                                   * identity-IOCTL mode. EUEDKEPM rejected them;                  \
                                   * the merged driver follows EPMNtDrv.) */
#define RDA_OPEN_CLASS_VOLUME   2 /* \<token>\Volume\<N> */
#define RDA_OPEN_CLASS_DISK     3 /* \<token>\<disk>\<anything>: EPMNtDrv semantics */
#define RDA_OPEN_CLASS_DISK_EPM 4 /* \<token>\<disk>: EUEDKEPM semantics */

typedef struct _RDA_OPEN_INFO {
    UINT32 Kind;         /* RDA_OPEN_CLASS_* */
    UINT32 Token;        /* parsed first-segment value (pre-verification) */
    UINT32 DiskNumber;   /* Kinds 3,4 */
    UINT32 VolumeNumber; /* Kind 2 */
} RDA_OPEN_INFO, *PRDA_OPEN_INFO;

/*
 * RdaParseUnsigned - RtlUnicodeStringToInteger-compatible decimal parser
 * over an explicit (possibly non-NUL-terminated) wchar range.
 *
 * Accepts: optional leading whitespace, optional '+', then one or more
 * decimal digits. Stops at the first non-digit. Returns 0 on success with
 * *Value set; returns -1 if no digits were present or the value would
 * overflow 32 bits (the reference rejected such paths via
 * RtlUnicodeStringToInteger's STATUS_INVALID_PARAMETER).
 *
 * Note on whitespace: the reference's RtlUnicodeStringToInteger skips
 * leading whitespace; we mirror it for exactness even though no legitimate
 * client produces whitespace.
 */
static __inline int RdaParseUnsigned(PCWSTR Buffer, UINT32 Chars, UINT32 *Value) {
    UINT32 i;
    UINT64 acc = 0;
    int haveDigits = 0;

    if (Buffer == (PCWSTR)0 || Chars == 0 || Value == (UINT32 *)0) {
        return -1;
    }

    for (i = 0; i < Chars; i++) {
        WCHAR c = Buffer[i];
        if (c == L' ' || c == L'\t' || c == L'\r' || c == L'\n') {
            continue;
        }
        if (c == L'+') {
            i++;
            break;
        }
        break;
    }

    for (; i < Chars; i++) {
        WCHAR c = Buffer[i];
        if (c < L'0' || c > L'9') {
            break;
        }
        acc = acc * 10 + (UINT64)(c - L'0');
        if (acc > 0xFFFFFFFFULL) {
            return -1; /* overflow - reference rejects */
        }
        haveDigits = 1;
    }

    if (!haveDigits) {
        return -1;
    }

    *Value = (UINT32)acc;
    return 0;
}

/*
 * RdaClassifyOpenPath - classify a FILE_OBJECT open path (name relative to
 * the control device). Buffer may not be NUL-terminated; Chars is the
 * length in wchars. Mirrors the reference CREATE handlers:
 *
 *  - Chars == 0 (FileName.Length < 2 BYTES - EPMNtDrv FUN_000110b0 gate)
 *                                                 -> GLOBAL (completes with
 *                                                    STATUS_SUCCESS, no target)
 *  - exactly 1 char goes to the scan loop below, finds no separator from
 *    index 1 and ends REJECT (reference-parity: a 1-wchar name is INVALID)
 *  - first '\' found scanning from index 1; token is chars[1..idx-1];
 *    token must parse as decimal                   (else REJECT)
 *  - no '\' after index 0                          -> REJECT
 *  - remainder counted SEPARATOR-INCLUSIVE (from the '\' at sepIdx)
 *    longer than 8 wchars and equal to L"\Volume" at that position
 *                                                   -> VOLUME, number parsed
 *      from sepIdx+8 (reference gate: Chars - sepIdx > 8); a NUMBER-PARSE
 *      FAILURE FALLS BACK TO VOLUME 0 (reference sets local_108[0]=0 and
 *      still opens \Device\HarddiskVolume0 - verified FUN_000110b0)
 *  - otherwise, if another path separator exists after the first number,
 *    the path is the 3-segment EPMNtDrv form      -> DISK (rest ignored,
 *      exactly like the reference: it parsed only the first number)
 *  - otherwise (single trailing number)            -> DISK_EPM (EUEDKEPM
 *      2-segment variant)
 *
 * Note: a path with no leading '\' at index 0 is treated identically: the
 * reference scanned for the separator from index 1 and used chars[1..idx-1]
 * as the token, so a leading '\' is implicit in the reference's grammar.
 */
static __inline void RdaClassifyOpenPath(PCWSTR Buffer, UINT32 Chars, PRDA_OPEN_INFO Info) {
    UINT32 sepIdx;
    UINT32 i;
    UINT32 value;
    UINT32 remStart;
    UINT32 remChars;
    int ok;

    if (Info == (PRDA_OPEN_INFO)0) {
        return;
    }
    Info->Kind = RDA_OPEN_CLASS_REJECT;
    Info->Token = 0;
    Info->DiskNumber = 0;
    Info->VolumeNumber = 0;

    if (Buffer == (PCWSTR)0) {
        return; /* null buffer -> REJECT */
    }
    if (Chars == 0) {
        /* Reference-exact (EPMNtDrv FUN_000110b0): the global-mode gate is
         * FileName.Length < 2 BYTES - i.e. only the EMPTY name completes
         * CREATE with STATUS_SUCCESS and no target context ("global" mode
         * behind bare device opens). A 1-wchar name falls through to the
         * separator scan below and ends REJECT, matching the reference scan
         * gate `if (1 < totalChars)`. EUEDKEPM rejected short names too. */
        Info->Kind = RDA_OPEN_CLASS_GLOBAL;
        return;
    }

    /* Find the first '\' at index >= 1. */
    sepIdx = 0;
    for (i = 1; i < Chars; i++) {
        if (Buffer[i] == L'\\') {
            sepIdx = i;
            break;
        }
    }
    if (sepIdx == 0) {
        return; /* no separator -> REJECT */
    }

    /* Token = chars[1..sepIdx-1]. */
    if (sepIdx == 1) {
        return; /* empty token -> REJECT (reference: parse of empty fails) */
    }
    if (RdaParseUnsigned(Buffer + 1, sepIdx - 1, &value) != 0) {
        return; /* token not decimal -> REJECT */
    }
    Info->Token = value;

    remStart = sepIdx + 1;
    remChars = Chars - remStart;

    if (remChars == 0) {
        return; /* token only, no target -> REJECT (reference requires a target) */
    }

    /* Volume branch (reference-exact, verified against the eprdtdrv CREATE
     * decompile): the reference counts the remainder SEPARATOR-INCLUSIVE
     * (remTotal = Chars - sepIdx, including the '\' at sepIdx) and requires
     * remTotal > 8; the literal L"\Volume" (7 wchars) is compared starting
     * AT the separator; the volume number is parsed from sepIdx+8 for
     * (remTotal - 8) wchars. */
    {
        UINT32 remTotal = Chars - sepIdx;

        if (remTotal > 8 && Buffer[sepIdx] == L'\\' && Buffer[sepIdx + 1] == L'V' &&
            Buffer[sepIdx + 2] == L'o' && Buffer[sepIdx + 3] == L'l' &&
            Buffer[sepIdx + 4] == L'u' && Buffer[sepIdx + 5] == L'm' &&
            Buffer[sepIdx + 6] == L'e') {
            if (RdaParseUnsigned(Buffer + sepIdx + 8, remTotal - 8, &value) == 0) {
                Info->Kind = RDA_OPEN_CLASS_VOLUME;
                Info->VolumeNumber = value;
            } else {
                /* Reference-verified (FUN_000110b0): when the volume number
                 * fails to parse the reference sets volume 0 and STILL
                 * opens \Device\HarddiskVolume0 (that open then fails with
                 * the IoGetDeviceObjectPointer status when volume 0 does not
                 * exist). Mirror exactly. */
                Info->Kind = RDA_OPEN_CLASS_VOLUME;
                Info->VolumeNumber = 0;
            }
            return;
        }
    }

    /* Disk branch: first number of the remainder. */
    ok = RdaParseUnsigned(Buffer + remStart, remChars, &value);
    if (ok != 0) {
        return; /* not a number -> REJECT */
    }
    Info->DiskNumber = value;

    /* Count wchars consumed by the disk number to decide 2 vs 3 segment. */
    {
        UINT32 digits = 1;
        UINT32 v = value;
        while (v >= 10) {
            v /= 10;
            digits++;
        }
        /* Skip any whitespace/sign the parser tolerated. */
        i = 0;
        while (i < remChars && (Buffer[remStart + i] == L' ' || Buffer[remStart + i] == L'\t')) {
            i++;
        }
        if (Buffer[remStart + i] == L'+') {
            i++;
        }
        i += digits;

        if (i < remChars && Buffer[remStart + i] == L'\\') {
            Info->Kind = RDA_OPEN_CLASS_DISK; /* 3+ segment form: EPMNtDrv */
        } else {
            Info->Kind = RDA_OPEN_CLASS_DISK_EPM; /* 2-segment: EUEDKEPM */
        }
    }
}

#ifdef __cplusplus
}
#endif

#endif /* _RDA_COMPAT_H_ */
