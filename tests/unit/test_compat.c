/*
 * test_compat.c - Portable unit tests for the shared RDA wire-grammar logic.
 *
 * Compiled and run on: Ubuntu CI (gcc) and Windows CI (MSVC) via CTest.
 * The tests encode the byte-verified reference behavior from
 * docs/ground-truth-contracts.md, including the two corrections to prior
 * research artifacts (global-open semantics; 3-segment grammar ignoring
 * the trailing component).
 *
 * Licensed under the MIT license. See LICENSE.
 */

#include "rda_compat.h"

#include <stdio.h>
#include <string.h>

/*
 * Wide-string portability: MSVC in C mode has no u"" literals and L"" is
 * 2-byte wchar_t (matches our WCHAR); gcc/clang on Linux have 4-byte
 * wchar_t but support C11 u"" literals (char16_t = 2 bytes, matches).
 */
#if defined(_MSC_VER)
#define WSTR(s) L##s
typedef WCHAR TWCHAR;
#else
#include <uchar.h>
#define WSTR(s) u##s
typedef char16_t TWCHAR;
#endif

static int g_failures;

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                                 \
            g_failures++;                                                                          \
        }                                                                                          \
    } while (0)

static UINT32 WsLen(const TWCHAR *s) {
    UINT32 n = 0;
    while (s[n] != 0) {
        n++;
    }
    return n;
}

/* Copy a WSTR literal into a WCHAR buffer WITHOUT relying on termination. */
static void MakePath(const TWCHAR *src, UINT32 chars, WCHAR *out, UINT32 outChars) {
    UINT32 i;
    for (i = 0; i < outChars; i++) {
        out[i] = (i < chars) ? (WCHAR)src[i] : (WCHAR)0;
    }
}

#define CASE_LEN 128

static void TestPidToken(void) {
    /* Reference transform: b0 | (b0+b1)<<8 | (b1+b2)<<16 | (b2+b3)<<24
     * with 8-bit wrapping adds. */
    CHECK(RdaComputePidToken(0x00000000UL) == 0x00000000UL);
    { /* pid = 1: b0=1 -> token = 1 | (1+0)<<8 = 0x00000101. */
        ULONG pid = 0x00000001UL;
        CHECK(RdaComputePidToken(pid) == ((ULONG)0x1 | ((ULONG)(0x1 + 0x0)) << 8));
    }
    { /* pid = 0x11223344: b0=0x44 b1=0x33 b2=0x22 b3=0x11
       * token = 0x44 | 0x77<<8 | 0x55<<16 | 0x33<<24 = 0x33557744. */
        ULONG pid = 0x11223344UL;
        ULONG expect = (ULONG)0x44 | ((ULONG)(0x44 + 0x33)) << 8 | ((ULONG)(0x33 + 0x22)) << 16 |
                       ((ULONG)(0x22 + 0x11)) << 24;
        CHECK(RdaComputePidToken(pid) == expect);
        CHECK(RdaComputePidToken(pid) == 0x33557744UL);
    }
    { /* 8-bit wrap: pid = 0x0001FF00: b0=0x00 b1=0xFF b2=0x01 b3=0x00
       * token = 0x00 | 0xFF<<8 | (0xFF+0x01)&0xFF = 0x00<<16 | 0x01<<24
       *       = 0x0100FF00 (the 0x100 byte-sum wraps to 0x00). */
        ULONG pid = 0x0001FF00UL;
        ULONG expect = (ULONG)0x00 | ((ULONG)0xFF) << 8 | ((ULONG)((0xFF + 0x01) & 0xFF)) << 16 |
                       ((ULONG)0x01) << 24;
        CHECK(RdaComputePidToken(pid) == expect);
        CHECK(RdaComputePidToken(pid) == 0x0100FF00UL);
    }
    { /* Cross-check against an independent byte-wise computation. */
        ULONG pid = 0xD8A2E3C3UL;
        unsigned char b[4];
        ULONG expect;
        b[0] = (unsigned char)(pid & 0xff);
        b[1] = (unsigned char)((pid >> 8) & 0xff);
        b[2] = (unsigned char)((pid >> 16) & 0xff);
        b[3] = (unsigned char)((pid >> 24) & 0xff);
        expect = (ULONG)b[0] | (((ULONG)(b[0] + b[1]) & 0xFF) << 8) |
                 (((ULONG)(b[1] + b[2]) & 0xFF) << 16) | (((ULONG)(b[2] + b[3]) & 0xFF) << 24);
        CHECK(RdaComputePidToken(pid) == expect);
    }
}

static void TestParser(void) {
    UINT32 v = 0;

    CHECK(RdaParseUnsigned(WSTR("123"), 3, &v) == 0 && v == 123);
    CHECK(RdaParseUnsigned(WSTR("0"), 1, &v) == 0 && v == 0);
    CHECK(RdaParseUnsigned(WSTR("12x"), 3, &v) == 0 && v == 12); /* stops at non-digit */
    CHECK(RdaParseUnsigned(WSTR("+7"), 2, &v) == 0 && v == 7);
    CHECK(RdaParseUnsigned(WSTR(" 42"), 3, &v) == 0 && v == 42); /* leading ws */
    CHECK(RdaParseUnsigned(WSTR("4294967295"), 10, &v) == 0 && v == 4294967295UL);
    CHECK(RdaParseUnsigned(WSTR("4294967296"), 10, &v) != 0); /* overflow */
    CHECK(RdaParseUnsigned(WSTR(""), 0, &v) != 0);            /* empty */
    CHECK(RdaParseUnsigned(WSTR("abc"), 3, &v) != 0);         /* no digits */
    CHECK(RdaParseUnsigned((PCWSTR)0, 3, &v) != 0);           /* null */
}

static void Expect(const TWCHAR *path, UINT32 kind, UINT32 token, UINT32 diskOrVol) {
    RDA_OPEN_INFO info;
    WCHAR buf[CASE_LEN];
    UINT32 n = WsLen(path);

    MakePath(path, n, buf, CASE_LEN);
    RdaClassifyOpenPath(buf, n, &info);
    if (info.Kind != kind ||
        (kind != RDA_OPEN_CLASS_GLOBAL && kind != RDA_OPEN_CLASS_REJECT && info.Token != token)) {
        printf("FAIL path: kind=%u want=%u token=%u want=%u\n", info.Kind, kind, info.Token, token);
        g_failures++;
        return;
    }
    if (kind == RDA_OPEN_CLASS_VOLUME && info.VolumeNumber != diskOrVol) {
        printf("FAIL volume: got=%u want=%u\n", info.VolumeNumber, diskOrVol);
        g_failures++;
        return;
    }
    if ((kind == RDA_OPEN_CLASS_DISK || kind == RDA_OPEN_CLASS_DISK_EPM) &&
        info.DiskNumber != diskOrVol) {
        printf("FAIL disk: got=%u want=%u\n", info.DiskNumber, diskOrVol);
        g_failures++;
        return;
    }
}

static void TestClassifier(void) {
    /* G2 (reference-exact, FUN_000110b0): the global-mode gate is
     * FileName.Length < 2 BYTES - ONLY the EMPTY name. A single backslash
     * (1 wchar) is REJECTED (the scan needs 1 < totalChars). */
    Expect(WSTR(""), RDA_OPEN_CLASS_GLOBAL, 0, 0);
    Expect(WSTR("\\"), RDA_OPEN_CLASS_REJECT, 0, 0);

    /* Volume grammar. */
    Expect(WSTR("\\123456\\Volume\\3"), RDA_OPEN_CLASS_VOLUME, 123456, 3);
    Expect(WSTR("\\999\\Volume\\0"), RDA_OPEN_CLASS_VOLUME, 999, 0);
    Expect(WSTR("\\999\\Volume\\77"), RDA_OPEN_CLASS_VOLUME, 999, 77);

    /* 3-segment disk grammar: the trailing component is IGNORED
     * (reference-exact: the reference driver parsed only the first number
     * and its DR-fallback used the disk number twice). */
    Expect(WSTR("\\123\\0\\2"), RDA_OPEN_CLASS_DISK, 123, 0);
    Expect(WSTR("\\123\\17\\99"), RDA_OPEN_CLASS_DISK, 123, 17);
    Expect(WSTR("\\0\\199\\0"), RDA_OPEN_CLASS_DISK, 0, 199);

    /* 2-segment disk grammar (EUEDKEPM variant). */
    Expect(WSTR("\\55\\7"), RDA_OPEN_CLASS_DISK_EPM, 55, 7);
    Expect(WSTR("\\55\\0"), RDA_OPEN_CLASS_DISK_EPM, 55, 0);

    /* Rejections. */
    Expect(WSTR("\\abc\\0\\2"), RDA_OPEN_CLASS_REJECT, 0, 0); /* non-numeric token */
    Expect(WSTR("\\\\0\\2"), RDA_OPEN_CLASS_REJECT, 0, 0);    /* empty token */
    Expect(WSTR("\\12"), RDA_OPEN_CLASS_REJECT, 0, 0);        /* token, no separator */
    Expect(WSTR("\\12\\"), RDA_OPEN_CLASS_REJECT, 0, 0);      /* separator, no target */
    Expect(WSTR("\\12\\Volume"), RDA_OPEN_CLASS_REJECT, 0, 0);
    Expect(WSTR("\\12\\Volume\\"), RDA_OPEN_CLASS_REJECT, 0, 0);
    Expect(WSTR("\\12\\x9"), RDA_OPEN_CLASS_REJECT, 0, 0); /* non-digit target */

    /* G3 (reference-exact): a volume branch whose NUMBER fails to parse
     * falls back to volume 0 (the reference opens HarddiskVolume0). */
    Expect(WSTR("\\12\\Volume\\xy"), RDA_OPEN_CLASS_VOLUME, 12, 0);
}

static void TestVolumeGateBoundary(void) {
    RDA_OPEN_INFO info;
    WCHAR buf[CASE_LEN];

    /* "\12\Volume\3": separator-inclusive remainder = 9 wchars (> 8)
     * -> volume branch, number parsed from sepIdx+8. */
    MakePath(WSTR("\\12\\Volume\\3"), 12, buf, CASE_LEN);
    RdaClassifyOpenPath(buf, 12, &info);
    CHECK(info.Kind == RDA_OPEN_CLASS_VOLUME && info.VolumeNumber == 3);

    /* "\12\Volume": separator-inclusive remainder = 7 wchars -> does NOT
     * enter the volume branch under the reference (remTotal > 8) gate; falls
     * to the disk parser which fails on "Volume" -> reject. */
    MakePath(WSTR("\\12\\Volume"), 10, buf, CASE_LEN);
    RdaClassifyOpenPath(buf, 10, &info);
    CHECK(info.Kind == RDA_OPEN_CLASS_REJECT);

    /* "\12\Volume\" : separator-inclusive remainder = 8 wchars, not > 8
     * -> the reference gate fails; disk parse of "Volume\" fails -> reject. */
    MakePath(WSTR("\\12\\Volume\\"), 11, buf, CASE_LEN);
    RdaClassifyOpenPath(buf, 11, &info);
    CHECK(info.Kind == RDA_OPEN_CLASS_REJECT);
}

static void TestIoctlTable(void) {
    /* Reference-exact codes must not drift. */
    CHECK(IOCTL_RDA_GET_PROC_NAME == 0x60002400UL);
    CHECK(IOCTL_RDA_GET_FILE_OBJ_NAME == 0x60002404UL);
    CHECK(IOCTL_RDA_GET_DISK_CONTEXT_MODE == 0x60002408UL);
    CHECK(RDA_SESSION_CODE_GET_VERSION == 0x800C2AC8UL);
    CHECK(RDA_SESSION_CODE_OPEN_SESSION == 0x800C2AD0UL);
    CHECK(RDA_SESSION_CODE_GETNEXTBLOCK == 0x800C2AE8UL);
    /* G28: the full 18-command set incl. discovery + RRWR families. */
    CHECK(RDA_SESSION_CODE_DISCOVERY == 0x800C2AC0UL);
    CHECK(RDA_SESSION_CODE_SESSION_STATUS == 0x800C2AF0UL);
    CHECK(RDA_SESSION_CODE_GET_PROGRESS == 0x800C2AF8UL);
    CHECK(RDA_SESSION_CODE_CLOSE_SESSION == 0x800C2B00UL);
    CHECK(RDA_SESSION_CODE_DIRECT_READ == 0x800C2B0AUL);
    CHECK(RDA_SESSION_CODE_DIRECT_WRITE == 0x800C2B12UL);
    CHECK(RDA_SESSION_CODE_MODE4 == 0x800C2B18UL);
    CHECK(RDA_SESSION_CODE_MODE3 == 0x800C2B20UL);
    CHECK(RDA_SESSION_CODE_SIZED_XFER == 0x800C2B2AUL);
    CHECK(RDA_SESSION_CODE_SIZED_XFER2 == 0x800C2B2EUL);
    CHECK(RDA_SESSION_CODE_CANCEL == 0x800C2B38UL);
    CHECK(RDA_SESSION_CODE_RRWR_WRITE == 0x800C2B3EUL);
    CHECK(RDA_SESSION_CODE_RRWR_VERSION == 0x800C2B40UL);
    CHECK(RDA_SESSION_CODE_RRWR_READ == 0x800C2B42UL);
    CHECK(RDA_RRWR_MAGIC == 0x52455752UL);
    /* Wire layout freezes (session 2): */
    CHECK(sizeof(RDA_GETNEXTBLOCK) == 0x1E);
    CHECK(sizeof(RDA_STARTBACKUP_IN) == 0x28);
    CHECK(sizeof(RDA_FILEIO_IN) == 0x1C);
    CHECK(RDA_SESSION_CODE_GET_PROGRESS == 0x800C2AF8UL);
    CHECK(RDA_SESSION_CODE_CLOSE_SESSION == 0x800C2B00UL);
    CHECK(RDA_SESSION_CODE_CANCEL == 0x800C2B38UL);
    CHECK(sizeof(RDA_OPEN_SESSION) == RDA_SESSION_STRUCT_SIZE);
}

int main(void) {
    TestPidToken();
    TestParser();
    TestClassifier();
    TestVolumeGateBoundary();
    TestIoctlTable();

    if (g_failures != 0) {
        printf("rda-compat: %d test(s) FAILED\n", g_failures);
        return 1;
    }
    printf("rda-compat: all tests passed\n");
    return 0;
}
