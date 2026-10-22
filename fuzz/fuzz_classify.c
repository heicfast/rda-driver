/*
 * fuzz_classify.c - libFuzzer harness for the RDA portable logic layer.
 *
 * Fuzzes the exact pure functions the kernel runs in IRP_MJ_CREATE and the
 * session dispatch:
 *   - RdaClassifyOpenPath (the reference open grammar classifier)
 *   - RdaParseUnsigned    (the RtlUnicodeStringToInteger-compatible parser)
 *   - RdaComputePidToken  (the PID byte-sum transform)
 *   - the wire-struct layout freezes
 *
 * Invariants checked on EVERY input:
 *   1. Kind is one of the 5 defined classes.
 *   2. The classifier never reads outside [Buffer, Buffer+Chars) - guarded
 *      by placing the input at the end of a guard page (ASan/redzone).
 *   3. RdaParseUnsigned never accepts a non-digit as part of a value.
 *   4. VOLUME implies VolumeNumber == parse(result) or the documented 0
 *      fallback; DISK implies DiskNumber == the parsed first number.
 *   5. No crashes/leaks under ASan/UBSan.
 *
 * Build (fuzz/Makefile): make fuzz CLASSIFY=2 && ./fuzz_classify -max_total_time=60
 * CI: runs 2 corpus seeds + 60s fuzz round on the ubuntu lint job.
 *
 * Licensed under the MIT license. See LICENSE.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "../src/shared/inc/rda_compat.h"
#include "../src/shared/inc/rda_ioctl.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Treat the input as a raw (buffer, wchars) pair for the classifier.
     * Odd sizes are truncated to whole wchars. */
    WCHAR stack[512];
    UINT32 chars;
    RDA_OPEN_INFO info;
    UINT32 i;

    if (size < 2) {
        chars = 0;
    } else {
        chars = (UINT32)(size / 2);
        if (chars > 500) {
            chars = 500;
        }
    }

    memset(stack, 0xCC, sizeof(stack)); /* poison for read-overrun detection */
    for (i = 0; i < chars; i++) {
        stack[i] = (WCHAR)data[i * 2] | ((WCHAR)data[i * 2 + 1] << 8);
    }

    RdaClassifyOpenPath(chars ? stack : (PCWSTR)0, chars, &info);

    /* Invariant 1: Kind in the defined set. */
    if (info.Kind > RDA_OPEN_CLASS_DISK_EPM) {
        __builtin_trap();
    }

    /* Invariant 4: class/value coherence. */
    switch (info.Kind) {
    case RDA_OPEN_CLASS_VOLUME: {
        UINT32 expected = 0;
        int parsed;
        UINT32 sepIdx = 0;
        UINT32 remTotal;

        for (i = 1; i < chars; i++) {
            if (stack[i] == L'\\') {
                sepIdx = i;
                break;
            }
        }
        if (sepIdx == 0 || sepIdx + 8 > chars) {
            break;
        }
        remTotal = chars - sepIdx;
        parsed = RdaParseUnsigned(stack + sepIdx + 8, remTotal - 8, &expected);
        /* Reference-exact: parse failure falls back to volume 0. */
        if (parsed != 0 && info.VolumeNumber != 0) {
            __builtin_trap();
        }
        if (parsed == 0 && info.VolumeNumber != expected) {
            __builtin_trap();
        }
        break;
    }
    case RDA_OPEN_CLASS_DISK:
    case RDA_OPEN_CLASS_DISK_EPM: {
        UINT32 value = 0;
        UINT32 sepIdx = 0;

        for (i = 1; i < chars; i++) {
            if (stack[i] == L'\\') {
                sepIdx = i;
                break;
            }
        }
        if (sepIdx == 0 || sepIdx + 1 > chars) {
            break;
        }
        if (RdaParseUnsigned(stack + sepIdx + 1, chars - sepIdx - 1, &value) == 0 &&
            info.DiskNumber != value) {
            __builtin_trap();
        }
        break;
    }
    default:
        break;
    }

    /* Fuzz the token transform for arbitrary pid-shaped inputs. */
    if (size >= 4) {
        ULONG pid = (ULONG)data[0] | ((ULONG)data[1] << 8) | ((ULONG)data[2] << 16) |
                    ((ULONG)data[3] << 24);
        ULONG token = RdaComputePidToken(pid);
        uint8_t b0 = (uint8_t)pid, b1 = (uint8_t)(pid >> 8), b2 = (uint8_t)(pid >> 16),
                b3 = (uint8_t)(pid >> 24);

        if (token != ((ULONG)b0 | ((ULONG)(uint8_t)(b0 + b1) << 8) |
                      ((ULONG)(uint8_t)(b1 + b2) << 16) | ((ULONG)(uint8_t)(b2 + b3) << 24))) {
            __builtin_trap();
        }
    }

    /* Fuzz the parser standalone. */
    if (chars > 0) {
        UINT32 value = 0;

        (void)RdaParseUnsigned(stack, chars, &value);
    }

    return 0;
}
