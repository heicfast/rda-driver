/*
 * rda_trace.h - Leveled tracing for the RDA driver.
 *
 * Design notes:
 *  - DbgPrintEx with a private component ID + per-level masks. Gated at runtime
 *    by g_DebugLevel (registry Parameters\DebugLevel, 0..5, default 1).
 *  - Zero cost when disabled (level check is a plain comparison against a
 *    global; strings still occupy the image - acceptable for a driver of
 *    this size; the reference drivers shipped full DbgPrint traces too).
 *  - Reference trace strings preserved where they carry wire-contract
 *    meaning ("[GetVolumeDeviceObejct] ... that's it!" etc.) so field
 *    tooling and documentation stay aligned.
 *  - No WPP: keeps the build toolchain-free, works on every target OS,
 *    and avoids .tmh generation coupling. ETW can be layered later without
 *    contract impact.
 *
 * Licensed under the MIT license. See LICENSE.
 */

#ifndef _RDA_TRACE_H_
#define _RDA_TRACE_H_

/* No system includes here on purpose: this header is always included after
 * the base headers (ntifs.h chain via rda_p.h). Including wdm.h from here
 * would (a) fight the load-bearing include order and (b) neuter ntddk.h
 * (wdm.h defines _NTDDK_ when included first). */

/* Private component: 'r' 'd' 'a' 0x01 - first 4 hex digits are the component
 * group (user-defined < 0x8000 for third parties), next 4 the component. */
#define RDA_DP_COMPONENT 'r' | ('d' << 8) | ('a' << 16)

/* Verbose levels (registry Parameters\DebugLevel). */
#define RDA_LEVEL_OFF     0
#define RDA_LEVEL_ERROR   1
#define RDA_LEVEL_WARN    2
#define RDA_LEVEL_INFO    3
#define RDA_LEVEL_TRACE   4
#define RDA_LEVEL_VERBOSE 5

extern ULONG g_RdaDebugLevel;

#define RDA_IS_LEVEL_ENABLED(_lvl) ((g_RdaDebugLevel) >= (_lvl))

#define RDA_TRACE_RAW(_fmt)                                                                        \
    do {                                                                                           \
        if (RDA_IS_LEVEL_ENABLED(RDA_LEVEL_TRACE)) {                                               \
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[RDA] " _fmt "\n");                  \
        }                                                                                          \
    } while (0)

/* General leveled trace with printf-style formatting. DbgPrintEx takes
 * DPFLTR_ masks; we pass the level as the component-relative mask so
 * `ed nt!Kd_DEFAULT_Mask`-style filtering stays intuitive. */
#define RDA_TRACE(_lvl, _fmt, ...)                                                                 \
    do {                                                                                           \
        if (RDA_IS_LEVEL_ENABLED(_lvl)) {                                                          \
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, (_lvl) + 3, "[RDA] " _fmt "\n", __VA_ARGS__);          \
        }                                                                                          \
    } while (0)

/* Trace with an implicit location tag. */
#define RDA_ENTER(_name) RDA_TRACE(RDA_LEVEL_VERBOSE, "%s+", _name)
#define RDA_EXIT(_name)  RDA_TRACE(RDA_LEVEL_VERBOSE, "%s-", _name)

#endif /* _RDA_TRACE_H_ */
