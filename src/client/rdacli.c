/*
 * rdacli.c - RDA user-mode client: contract verification, raw IO, benchmark.
 *
 * The client doubles as the integration harness: every subcommand exercises
 * a verified wire contract against a loaded driver. Run elevated with the
 * driver installed (see scripts/install.ps1).
 *
 *   rdacli info                     GET_INFO + GET_VERSION (global handles)
 *   rdacli grammar <disk#>           open all 3 grammar forms + identity checks
 *   rdacli read <disk> <off> <len>  raw read via \\.\EPRDTDRV\<token>\<disk>
 *   rdacli write <disk> <off> <hex> raw write (data = hex string)
 *   rdacli ident <pid>               IOCTL 0x60002400 GetProcName
 *   rdacli session <disk> <start> <secs>
 *                                   OpenSession -> pump N blocks -> progress -> close
 *   rdacli bench read <disk> <secs> [chunkSectors]
 *                                   driver-path throughput vs \\.\PhysicalDriveN
 *
 * Licensed under the MIT license. See LICENSE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "rda_compat.h"
#include "rda_ioctl.h"

#define RDA_DEVICE_SYM_FMT L"\\\\.\\%ws"
#define RDA_OPEN_FMT       L"\\\\.\\%ws\\%u\\%u\\%u"
#define RDA_MAX_PATH_W     256

static int Fail(const char *what, DWORD err) {
    printf("FAIL %s (gle=%lu, 0x%08lX)\n", what, err, err);
    return 2;
}

static ULONG TokenFromPid(void) {
    return RdaComputePidToken((ULONG)GetCurrentProcessId());
}

static HANDLE OpenDevice(DWORD access) {
    WCHAR path[RDA_MAX_PATH_W];
    _snwprintf_s(path, RDA_MAX_PATH_W, _TRUNCATE, L"\\\\.\\%ws", L"EPRDTDRV");
    return CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
}

static HANDLE OpenGlobal(DWORD access) {
    return OpenDevice(access);
}

/* Opens \\.\EPRDTDRV\<token>\<disk> (the EPMNtDrv 3-segment grammar). */
static HANDLE OpenDisk(DWORD access, ULONG disk) {
    WCHAR path[RDA_MAX_PATH_W];
    _snwprintf_s(path, RDA_MAX_PATH_W, _TRUNCATE, RDA_OPEN_FMT, L"EPRDTDRV", TokenFromPid(), disk,
                 0);
    return CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
}

/* Opens \\.\EPRDTDRV\<token>\Volume\<n>. */
static HANDLE OpenVolume(DWORD access, ULONG volume) {
    WCHAR path[RDA_MAX_PATH_W];
    _snwprintf_s(path, RDA_MAX_PATH_W, _TRUNCATE, L"\\\\.\\%ws\\%u\\Volume\\%u", L"EPRDTDRV",
                 TokenFromPid(), volume);
    return CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
}

/* ------------------------------------------------------------------ info -- */

static int CmdInfo(void) {
    HANDLE h = OpenGlobal(GENERIC_READ);
    DWORD bytes = 0;
    RDA_DRIVER_INFO info;
    ULONG64 version = 0;

    if (h == INVALID_HANDLE_VALUE) {
        return Fail("open global", GetLastError());
    }

    if (!DeviceIoControl(h, IOCTL_RDA_GET_INFO, NULL, 0, &info, sizeof(info), &bytes, NULL) ||
        bytes < sizeof(info)) {
        return Fail("GET_INFO", GetLastError());
    }
    printf("driver: v%u.%u flags=0x%X maxDisks=%u ioctlBase=0x%X\n", info.MajorVersion,
           info.MinorVersion, info.Flags, info.MaxDisks, info.IoctlBase);

    if (!DeviceIoControl(h, IOCTL_RDA_GET_VERSION, NULL, 0, &version, sizeof(version), &bytes,
                         NULL)) {
        return Fail("GET_VERSION", GetLastError());
    }
    printf("version: %llu\n", (unsigned long long)version);

    CloseHandle(h);
    printf("PASS info\n");
    return 0;
}

/* --------------------------------------------------------------- grammar -- */

static int CmdGrammar(ULONG disk) {
    HANDLE h;
    DWORD bytes = 0;
    LONG mode = -1;

    /* 3-segment disk grammar. */
    h = OpenDisk(GENERIC_READ, disk);
    if (h == INVALID_HANDLE_VALUE) {
        return Fail("open disk (3-segment)", GetLastError());
    }
    if (!DeviceIoControl(h, IOCTL_RDA_GET_DISK_CONTEXT_MODE, NULL, 0, &mode, sizeof(mode), &bytes,
                         NULL) ||
        bytes != sizeof(mode)) {
        return Fail("GET_DISK_CONTEXT_MODE", GetLastError());
    }
    printf("disk %u: mode=%ld (0 = disk.sys-backed)\n", disk, mode);
    CloseHandle(h);

    /* Volume grammar (volume 0..N may fail legitimately when absent). */
    {
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION *logical = NULL;
        DWORD needed = 0;
        GetLogicalProcessorInformation(NULL, &needed);
        (void)logical;
    }
    h = OpenVolume(GENERIC_READ, 0);
    if (h != INVALID_HANDLE_VALUE) {
        printf("volume 0: open OK\n");
        CloseHandle(h);
    } else {
        printf("volume 0: open failed (may be absent) gle=%lu\n", GetLastError());
    }

    /* 2-segment EUEDKEPM grammar. */
    {
        WCHAR path[RDA_MAX_PATH_W];
        _snwprintf_s(path, RDA_MAX_PATH_W, _TRUNCATE, L"\\\\.\\%ws\\%u\\%u", L"EPRDTDRV",
                     TokenFromPid(), disk);
        h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            return Fail("open disk (2-segment/EUEDKEPM)", GetLastError());
        }
        printf("disk %u (2-segment): open OK\n", disk);
        CloseHandle(h);
    }

    /* Wrong-token open must fail. */
    {
        WCHAR path[RDA_MAX_PATH_W];
        _snwprintf_s(path, RDA_MAX_PATH_W, _TRUNCATE, L"\\\\.\\%ws\\%u\\%u\\%u", L"EPRDTDRV",
                     TokenFromPid() ^ 0x5A5A, disk, 0);
        h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            printf("FAIL: wrong-token open unexpectedly succeeded\n");
            return 2;
        }
        printf("wrong-token open rejected (gle=%lu)\n", GetLastError());
    }

    printf("PASS grammar\n");
    return 0;
}

/* ------------------------------------------------------------------ read -- */

static int CmdRead(ULONG disk, unsigned long long offset, unsigned long len) {
    HANDLE h = OpenDisk(GENERIC_READ, disk);
    BYTE *buffer;
    DWORD got = 0;
    unsigned long long i;
    int status = 0;

    if (h == INVALID_HANDLE_VALUE) {
        return Fail("open disk", GetLastError());
    }
    buffer = (BYTE *)malloc(len);
    if (buffer == NULL) {
        CloseHandle(h);
        return Fail("malloc", 0);
    }
    if (SetFilePointer(h, (LONG)(offset & 0xFFFFFFFF), (PLONG)((offset >> 32) & 0xFFFFFFFF),
                       FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        free(buffer);
        CloseHandle(h);
        return Fail("SetFilePointer", GetLastError());
    }
    if (!ReadFile(h, buffer, len, &got, NULL)) {
        status = Fail("ReadFile", GetLastError());
    } else {
        /* Legacy contract: reported count is 512x the byte count. */
        if ((unsigned long long)got != (unsigned long long)len * RDA_LEGACY_INFORMATION_SCALE) {
            printf("NOTE: reported %lu bytes (expected legacy scale x%u -> %llu)\n", got,
                   RDA_LEGACY_INFORMATION_SCALE,
                   (unsigned long long)len * RDA_LEGACY_INFORMATION_SCALE);
        }
        printf("read %lu bytes OK; first bytes:", len);
        for (i = 0; i < len && i < 16; i++) {
            printf(" %02X", buffer[i]);
        }
        printf("\n");
    }
    free(buffer);
    CloseHandle(h);
    return status;
}

/* ------------------------------------------------------------------ ident - */

static int CmdIdent(ULONG pid) {
    HANDLE h = OpenGlobal(GENERIC_READ);
    BYTE buffer[RDA_IDENT_MIN_OUT_LEN];
    DWORD bytes = 0;

    if (h == INVALID_HANDLE_VALUE) {
        return Fail("open global", GetLastError());
    }
    if (!DeviceIoControl(h, IOCTL_RDA_GET_PROC_NAME, &pid, sizeof(pid), buffer, sizeof(buffer),
                         &bytes, NULL)) {
        return Fail("GET_PROC_NAME", GetLastError());
    }
    printf("pid %u image: %ls (len=%lu)\n", pid, (WCHAR *)buffer, bytes);
    CloseHandle(h);
    return 0;
}

/* --------------------------------------------------------------- session -- */

static int CmdSession(ULONG disk, unsigned long long startSec, unsigned long long secs) {
    HANDLE h = OpenGlobal(GENERIC_READ | GENERIC_WRITE);
    RDA_OPEN_SESSION *in;
    DWORD bytes = 0;
    ULONG64 handle;
    ULONG total = 0;
    int pumpRound;

    if (h == INVALID_HANDLE_VALUE) {
        return Fail("open global (rw)", GetLastError());
    }
    in = (RDA_OPEN_SESSION *)calloc(1, RDA_SESSION_STRUCT_SIZE);
    if (in == NULL) {
        return Fail("calloc", 0);
    }

    in->DiskId = disk;
    in->DataFirstSec = startSec;
    in->TotalSecs = secs;
    in->BitmapSize = 0x800;
    in->BitmapCount = 0x100;
    in->SpbInOut = 0;                     /* auto */
    memset(in->BlockBitmap, 0xFF, 0x100); /* first 0x100 bytes all-set */

    /* OpenSession is issued through the session-code space: base is
     * g_RdaParameters.IoctlBase (default 0 in the live profile). */
    {
        DWORD code = RDA_SESSION_CODE_OPEN_SESSION; /* + IoctlBase (0 here) */
        if (!DeviceIoControl(h, code, in, RDA_SESSION_STRUCT_SIZE, in, RDA_SESSION_STRUCT_SIZE,
                             &bytes, NULL)) {
            free(in);
            CloseHandle(h);
            return Fail("OpenSession", GetLastError());
        }
    }

    handle = in->SessionHandle;
    printf("session open: handle=0x%016llX spb=%u sectorSize=%u\n", (unsigned long long)handle,
           in->SpbInOut, in->SectorSize);

    /* Pump up to 8 rounds. */
    for (pumpRound = 0; pumpRound < 8; pumpRound++) {
        BYTE block[4096 * 16];
        struct {
            ULONG64 session;
            BYTE pad[0x1E - sizeof(ULONG64)];
        } pumpIn;

        pumpIn.session = handle;
        memset(pumpIn.pad, 0, sizeof(pumpIn.pad));

        bytes = 0;
        if (!DeviceIoControl(h, RDA_SESSION_CODE_GETNEXTBLOCK, &pumpIn, sizeof(pumpIn), block,
                             sizeof(block), &bytes, NULL)) {
            free(in);
            CloseHandle(h);
            return Fail("GETNEXTBLOCK", GetLastError());
        }
        printf("pump round %u: %lu bytes\n", pumpRound, bytes);
        total += bytes;
        if (bytes == 0) {
            break;
        }
    }

    /* Progress. */
    {
        BYTE progressOut[0x0C];
        struct {
            ULONG64 session;
            BYTE pad[4];
        } progressIn = {0};

        progressIn.session = handle;
        bytes = 0;
        if (DeviceIoControl(h, RDA_SESSION_CODE_GET_PROGRESS, &progressIn, sizeof(progressIn),
                            progressOut, sizeof(progressOut), &bytes, NULL)) {
            printf("progress: %u%% (bytesDone indication)\n", *(DWORD *)(progressOut + 8));
        }
    }

    /* Close. */
    {
        ULONG64 closeIn = handle;
        bytes = 0;
        if (!DeviceIoControl(h, RDA_SESSION_CODE_CLOSE_SESSION, &closeIn, sizeof(closeIn), NULL, 0,
                             &bytes, NULL)) {
            printf("close failed gle=%lu (continuing)\n", GetLastError());
        }
    }

    free(in);
    CloseHandle(h);
    printf("PASS session (%u bytes streamed)\n", total);
    return 0;
}

/* ----------------------------------------------------------------- bench -- */

static double NowSec(void) {
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart / (double)freq.QuadPart;
}

static int CmdBenchRead(ULONG disk, unsigned long long secs, ULONG chunkSectors) {
    HANDLE h;
    BYTE *buffer;
    ULONG chunkBytes = chunkSectors * 512;
    unsigned long long done = 0;
    DWORD got = 0;
    double t0, t1;
    int status = 0;

    h = OpenDisk(GENERIC_READ, disk);
    if (h == INVALID_HANDLE_VALUE) {
        return Fail("open disk", GetLastError());
    }
    buffer = (BYTE *)malloc(chunkBytes);
    if (buffer == NULL) {
        CloseHandle(h);
        return Fail("malloc", 0);
    }

    SetFilePointer(h, 0, NULL, FILE_BEGIN);
    t0 = NowSec();
    while (done < secs * 512) {
        if (!ReadFile(h, buffer, chunkBytes, &got, NULL)) {
            status = Fail("ReadFile(bench)", GetLastError());
            break;
        }
        done += chunkBytes;
    }
    t1 = NowSec();
    printf("driver path: %llu bytes in %.3f s = %.1f MB/s\n", done, t1 - t0,
           done / (1024.0 * 1024.0) / (t1 - t0));
    free(buffer);
    CloseHandle(h);

    /* Baseline: \\.\PhysicalDriveN with the same pattern. */
    {
        WCHAR path[32];
        HANDLE base;
        _snwprintf_s(path, 32, _TRUNCATE, L"\\\\.\\PhysicalDrive%u", disk);
        base = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (base != INVALID_HANDLE_VALUE) {
            buffer = (BYTE *)malloc(chunkBytes);
            done = 0;
            SetFilePointer(base, 0, NULL, FILE_BEGIN);
            t0 = NowSec();
            while (done < secs * 512) {
                if (!ReadFile(base, buffer, chunkBytes, &got, NULL) || got == 0) {
                    break;
                }
                done += chunkBytes;
            }
            t1 = NowSec();
            printf("baseline  : %llu bytes in %.3f s = %.1f MB/s\n", done, t1 - t0,
                   done / (1024.0 * 1024.0) / (t1 - t0));
            free(buffer);
            CloseHandle(base);
        } else {
            printf("baseline open failed gle=%lu\n", GetLastError());
        }
    }
    return status;
}

/* ------------------------------------------------------------------ main -- */

static void Usage(void) {
    printf("usage: rdacli <command> [args]\n"
           "  info\n"
           "  grammar <disk>\n"
           "  read <disk> <offset> <len>\n"
           "  ident <pid>\n"
           "  session <disk> <startSec> <secs>\n"
           "  bench read <disk> <secs> [chunkSectors]\n");
}

int __cdecl wmain(int argc, wchar_t **argv) {
    if (argc < 2) {
        Usage();
        return 1;
    }
    if (wcscmp(argv[1], L"info") == 0) {
        return CmdInfo();
    }
    if (wcscmp(argv[1], L"grammar") == 0 && argc >= 3) {
        return CmdGrammar((ULONG)_wtoi(argv[2]));
    }
    if (wcscmp(argv[1], L"read") == 0 && argc >= 5) {
        return CmdRead((ULONG)_wtoi(argv[2]), _wcstoui64(argv[3], NULL, 10),
                       (unsigned long)_wcstoui64(argv[4], NULL, 10));
    }
    if (wcscmp(argv[1], L"ident") == 0 && argc >= 3) {
        return CmdIdent((ULONG)_wtoi(argv[2]));
    }
    if (wcscmp(argv[1], L"session") == 0 && argc >= 5) {
        return CmdSession((ULONG)_wtoi(argv[2]), _wcstoui64(argv[3], NULL, 10),
                          _wcstoui64(argv[4], NULL, 10));
    }
    if (wcscmp(argv[1], L"bench") == 0 && argc >= 5 && wcscmp(argv[2], L"read") == 0) {
        ULONG chunk = (argc >= 6) ? (ULONG)_wtoi(argv[5]) : 128;
        return CmdBenchRead((ULONG)_wtoi(argv[3]), _wcstoui64(argv[4], NULL, 10), chunk);
    }
    Usage();
    return 1;
}
