/*
 * rdabench.c - performance + correctness benchmark client for the RDA
 * driver, structured for side-by-side comparison with the reference
 * eprdtdrv/EUEDKEPM drivers (all speak the same wire grammar, so one
 * binary drives any of them through its device name).
 *
 * Modes:
 *   open       - cold-open latency (device open with token grammar) x N
 *   seq        - sequential raw reads across a sector span (throughput)
 *   rand       - random-offset reads of a fixed block size (IOPS + latency)
 *   info       - contract probes: geometry pass-through, identity IOCTLs,
 *                information scaling (Length<<9), close/reopen churn
 *   fuzz       - hostile-input hammer: random paths/IOCTLs/lengths; the
 *                driver must answer with NTSTATUS failures, never hang
 *   verify     - correctness: SHA-256 over sampled ranges for cross-driver
 *                byte-equality reports (emits a hash line per range)
 *
 * All results emit machine-readable JSON (one object per --run label) so
 * the CI workflow can diff drivers objectively.
 *
 *   rdabench --device EPRDTDRV --disk 1 --part 0 --mode seq --mb 512
 *
 * Licensed under the MIT license. See LICENSE.
 */

#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bcrypt.h>

#include "../../src/shared/inc/rda_compat.h"
#include "../../src/shared/inc/rda_ioctl.h"

#pragma comment(lib, "bcrypt.lib")

#define MAX_BUFFER_BYTES (16 * 1024 * 1024)
#define HASH_HEXDIGEST   64

typedef struct _BENCH_CONFIG {
    char Device[64]; /* \\.\ symbolic link base name (no prefix) */
    ULONG Disk;      /* grammar disk number */
    ULONG Part;      /* grammar partition component (vestigial) */
    char Mode[16];
    ULONG Mb;      /* span to read (sequential/verify) */
    ULONG BlockKb; /* block size (random/seq) */
    ULONG Iterations;
    ULONG Seed;
    char Run[64]; /* JSON "run" label */
} BENCH_CONFIG;

static BENCH_CONFIG g_Config;

/* Token for the CURRENT process (the driver re-derives it from its own
 * PsGetCurrentProcessId and compares). */
static ULONG CurrentPidToken(void) {
    return RdaComputePidToken((ULONG)GetCurrentProcessId());
}

static HANDLE OpenTarget(ULONG disk, ULONG part, DWORD *lastError) {
    char path[128];
    HANDLE h;

    sprintf_s(path, sizeof(path), "\\\\.\\%s\\%u\\%u\\%u", g_Config.Device, CurrentPidToken(), disk,
              part);
    h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING, NULL);
    *lastError = GetLastError();
    return h;
}

/* Legacy Information contract (reference-exact, verified in both drivers):
 * on success the driver reports Information = Length * 512, so ReadFile's
 * lpNumberOfBytesRead comes back SCALED. Reference clients divide by 512 to
 * recover the true byte count; so do we. */
static DWORD UnscaleInformation(DWORD scaled) {
    return scaled / RDA_LEGACY_INFORMATION_SCALE;
}

static double NowSec(void) {
    LARGE_INTEGER freq, counter;

    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart / (double)freq.QuadPart;
}

static void HexFromHash(const BYTE *hash, DWORD hashLen, char *out, size_t outBytes) {
    static const char *digits = "0123456789abcdef";
    DWORD i;

    for (i = 0; i < hashLen && (i * 2 + 2) < outBytes; i++) {
        out[i * 2] = digits[hash[i] >> 4];
        out[i * 2 + 1] = digits[hash[i] & 0xF];
    }
    out[hashLen * 2 < outBytes ? hashLen * 2 : outBytes - 1] = '\0';
}

static void EmitResult(const char *metric, const char *unit, double value) {
    printf("{\"run\":\"%s\",\"driver\":\"%s\",\"mode\":\"%s\",\"metric\":\"%s\","
           "\"unit\":\"%s\",\"value\":%.6f}\n",
           g_Config.Run, g_Config.Device, g_Config.Mode, metric, unit, value);
}

static void EmitString(const char *metric, const char *value) {
    printf("{\"run\":\"%s\",\"driver\":\"%s\",\"mode\":\"%s\",\"metric\":\"%s\","
           "\"value\":\"%s\"}\n",
           g_Config.Run, g_Config.Device, g_Config.Mode, metric, value);
}

/* ------------------------------------------------------------------------ */
static int BenchOpen(void) {
    DWORD lastError = 0;
    double t0, t1;
    ULONG i;
    HANDLE h;

    t0 = NowSec();
    for (i = 0; i < g_Config.Iterations; i++) {
        h = OpenTarget(g_Config.Disk, g_Config.Part, &lastError);
        if (h == INVALID_HANDLE_VALUE) {
            EmitString("error", "open failed");
            return 1;
        }
        CloseHandle(h);
    }
    t1 = NowSec();
    EmitResult("open_ns_mean", "ns", (t1 - t0) * 1e9 / g_Config.Iterations);
    EmitResult("open_ops", "ops/s", (double)g_Config.Iterations / (t1 - t0));
    return 0;
}

static int BenchSeq(void) {
    HANDLE h;
    DWORD lastError = 0;
    BYTE *buffer;
    ULONG blockBytes = g_Config.BlockKb * 1024;
    ULONG64 spanBytes = (ULONG64)g_Config.Mb * 1024 * 1024;
    LARGE_INTEGER offset;
    double t0, t1;
    ULONG64 total = 0;
    DWORD read;

    if (blockBytes > MAX_BUFFER_BYTES) {
        blockBytes = MAX_BUFFER_BYTES;
    }
    buffer = (BYTE *)_aligned_malloc(blockBytes, 4096);
    if (buffer == NULL) {
        EmitString("error", "oom");
        return 1;
    }

    h = OpenTarget(g_Config.Disk, g_Config.Part, &lastError);
    if (h == INVALID_HANDLE_VALUE) {
        _aligned_free(buffer);
        EmitString("error", "open failed");
        return 1;
    }

    t0 = NowSec();
    for (offset.QuadPart = 0; (ULONG64)offset.QuadPart < spanBytes; offset.QuadPart += blockBytes) {
        DWORD scaled = 0;

        if (!SetFilePointerEx(h, offset, NULL, FILE_BEGIN)) {
            _aligned_free(buffer);
            CloseHandle(h);
            EmitString("error", "seek failed");
            return 1;
        }
        if (!ReadFile(h, buffer, blockBytes, &scaled, NULL) ||
            UnscaleInformation(scaled) != blockBytes) {
            if (total == 0) {
                _aligned_free(buffer);
                CloseHandle(h);
                EmitString("error", "first read failed");
                return 1;
            }
            break;
        }
        read = UnscaleInformation(scaled);
        total += read;
    }
    t1 = NowSec();
    _aligned_free(buffer);
    CloseHandle(h);

    EmitResult("throughput", "MiB/s", (double)total / (1024.0 * 1024.0) / (t1 - t0));
    EmitResult("elapsed", "s", t1 - t0);
    EmitResult("bytes", "bytes", (double)total);
    return 0;
}

static int BenchRand(void) {
    HANDLE h;
    DWORD lastError = 0;
    BYTE *buffer;
    ULONG blockBytes = g_Config.BlockKb * 1024;
    ULONG64 spanBytes = (ULONG64)g_Config.Mb * 1024 * 1024;
    ULONG64 blockCount = spanBytes / blockBytes;
    LARGE_INTEGER offset;
    double t0, t1;
    DWORD read;
    ULONG i;
    unsigned long long rng = g_Config.Seed ? g_Config.Seed : 1;

    if (blockBytes > MAX_BUFFER_BYTES) {
        blockBytes = MAX_BUFFER_BYTES;
    }
    if (blockCount == 0) {
        blockCount = 1;
    }
    buffer = (BYTE *)_aligned_malloc(blockBytes, 4096);
    h = OpenTarget(g_Config.Disk, g_Config.Part, &lastError);
    if (h == INVALID_HANDLE_VALUE) {
        _aligned_free(buffer);
        EmitString("error", "open failed");
        return 1;
    }

    rng = rng * 6364136223846793005ULL + 1442695040888963407ULL; /* warm up */

    t0 = NowSec();
    for (i = 0; i < g_Config.Iterations; i++) {
        DWORD scaled = 0;

        rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
        offset.QuadPart = (ULONG64)((rng >> 11) % blockCount) * blockBytes;
        if (!SetFilePointerEx(h, offset, NULL, FILE_BEGIN) ||
            !ReadFile(h, buffer, blockBytes, &scaled, NULL) ||
            UnscaleInformation(scaled) != blockBytes) {
            EmitString("error", "random read failed");
            _aligned_free(buffer);
            CloseHandle(h);
            return 1;
        }
        read = UnscaleInformation(scaled);
    }
    t1 = NowSec();
    _aligned_free(buffer);
    CloseHandle(h);

    EmitResult("iops", "ops/s", (double)g_Config.Iterations / (t1 - t0));
    EmitResult("latency_us_mean", "us", (t1 - t0) * 1e6 / g_Config.Iterations);
    EmitResult("throughput", "MiB/s",
               (double)g_Config.Iterations * blockBytes / (1024.0 * 1024.0) / (t1 - t0));
    return 0;
}

static int BenchInfo(void) {
    HANDLE h;
    DWORD lastError = 0;
    BYTE buffer[0x400];
    DWORD returned = 0;
    ULONG pid;
    double t0, t1;
    BOOL ok;

    h = OpenTarget(g_Config.Disk, g_Config.Part, &lastError);
    if (h == INVALID_HANDLE_VALUE) {
        EmitString("error", "open failed");
        return 1;
    }

    /* Geometry pass-through (should reach the disk stack). */
    ZeroMemory(buffer, sizeof(buffer));
    ok = DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, buffer,
                         (DWORD)(sizeof(DISK_GEOMETRY_EX)), &returned, NULL);
    EmitResult("geometry_passthrough", "bool", ok ? 1.0 : 0.0);

    /* Identity IOCTL needs the GLOBAL (bare) handle. */
    {
        HANDLE global;
        char path[64];

        sprintf_s(path, sizeof(path), "\\\\.\\%s", g_Config.Device);
        global = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL, NULL);
        if (global != INVALID_HANDLE_VALUE) {
            pid = GetCurrentProcessId();
            ZeroMemory(buffer, sizeof(buffer));
            ok = DeviceIoControl(global, IOCTL_RDA_GET_PROC_NAME, &pid, sizeof(pid), buffer,
                                 sizeof(buffer), &returned, NULL);
            EmitResult("getprocname", "bool", ok ? 1.0 : 0.0);
            CloseHandle(global);
        } else {
            EmitResult("getprocname", "bool", 0.0);
        }
    }

    /* ReadFile Information scaling contract: Length<<9. */
    {
        BYTE small[512];
        LARGE_INTEGER offset;
        DWORD got = 0;

        offset.QuadPart = 0;
        if (SetFilePointerEx(h, offset, NULL, FILE_BEGIN) &&
            ReadFile(h, small, sizeof(small), &got, NULL) &&
            got == sizeof(small) * RDA_LEGACY_INFORMATION_SCALE) {
            /* got == 512 * 512 proves the reference Information scaling. */
            EmitResult("read_information_scale", "sectors", (double)RDA_LEGACY_INFORMATION_SCALE);
        } else {
            EmitResult("read_information_scale", "sectors", 0.0);
        }
    }

    /* Close/reopen churn (cold-start proxy for the driver entry path). */
    CloseHandle(h);
    t0 = NowSec();
    for (int i = 0; i < 100; i++) {
        HANDLE x = OpenTarget(g_Config.Disk, g_Config.Part, &lastError);

        if (x == INVALID_HANDLE_VALUE) {
            EmitString("error", "churn open failed");
            return 1;
        }
        CloseHandle(x);
    }
    t1 = NowSec();
    EmitResult("churn_open_ns_mean", "ns", (t1 - t0) * 1e9 / 100);
    return 0;
}

static int BenchVerify(void) {
    HANDLE h;
    DWORD lastError = 0;
    BYTE *buffer;
    ULONG blockBytes = 1024 * 1024;
    ULONG64 spanBytes = (ULONG64)g_Config.Mb * 1024 * 1024;
    ULONG64 blockCount = spanBytes / blockBytes;
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    BYTE digest[32];
    char hex[HASH_HEXDIGEST + 1];
    LARGE_INTEGER offset;
    DWORD read;

    buffer = (BYTE *)_aligned_malloc(blockBytes, 4096);
    h = OpenTarget(g_Config.Disk, g_Config.Part, &lastError);
    if (h == INVALID_HANDLE_VALUE) {
        _aligned_free(buffer);
        EmitString("error", "open failed");
        return 1;
    }
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) {
        _aligned_free(buffer);
        CloseHandle(h);
        EmitString("error", "bcrypt");
        return 1;
    }

    for (ULONG64 i = 0; i < blockCount; i++) {
        DWORD scaled = 0;

        offset.QuadPart = (LONGLONG)(i * blockBytes);
        if (!SetFilePointerEx(h, offset, NULL, FILE_BEGIN) ||
            !ReadFile(h, buffer, blockBytes, &scaled, NULL) ||
            UnscaleInformation(scaled) != blockBytes) {
            break;
        }
        read = UnscaleInformation(scaled);
        if (BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0) != 0) {
            break;
        }
        BCryptHashData(hash, buffer, read, 0);
        BCryptFinishHash(hash, digest, sizeof(digest), 0);
        BCryptDestroyHash(hash);
        hash = NULL;
        HexFromHash(digest, sizeof(digest), hex, sizeof(hex));
        printf("{\"run\":\"%s\",\"driver\":\"%s\",\"mode\":\"verify\",\"block\":%llu,"
               "\"sha256\":\"%s\"}\n",
               g_Config.Run, g_Config.Device, (unsigned long long)(i * blockBytes), hex);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    _aligned_free(buffer);
    CloseHandle(h);
    return 0;
}

static int BenchFuzz(void) {
    HANDLE h;
    DWORD lastError = 0;
    BYTE buffer[0x900];
    DWORD returned = 0;
    unsigned long long rng = g_Config.Seed ? g_Config.Seed : 0xC0FFEEULL;
    ULONG survived = 0;
    double t0, t1;
    static const ULONG codes[] = {
        0x60002400, 0x60002404, 0x60002408, 0x60002440, 0x60002444, 0x60002448,
        0x800C2AC8, 0x800C2AD0, 0x800C2AE8, 0x800C2B00, 0x800C2B38, 0x800C2B3E,
        0x800C2B40, 0x800C2B42, 0x12345678, 0x00000000, 0xFFFFFFFF,
    };

    h = OpenTarget(g_Config.Disk, g_Config.Part, &lastError);
    if (h == INVALID_HANDLE_VALUE) {
        EmitString("error", "open failed");
        return 1;
    }

    t0 = NowSec();
    for (ULONG i = 0; i < g_Config.Iterations; i++) {
        ULONG code, inLen, outLen;

        rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
        code = codes[(rng >> 33) % (sizeof(codes) / sizeof(codes[0]))];
        inLen = (ULONG)((rng >> 40) % 0x120);
        outLen = (ULONG)((rng >> 20) % 0x900);
        ZeroMemory(buffer, sizeof(buffer));
        /* The driver must always return (graceful NTSTATUS), never hang. */
        DeviceIoControl(h, code, buffer, inLen, buffer, outLen, &returned, NULL);
        survived++;
    }
    t1 = NowSec();
    CloseHandle(h);
    EmitResult("fuzz_survived", "iters", (double)survived);
    EmitResult("fuzz_rate", "iters/s", (double)g_Config.Iterations / (t1 - t0));
    return 0;
}

int main(int argc, char **argv) {
    int i;

    ZeroMemory(&g_Config, sizeof(g_Config));
    strcpy_s(g_Config.Device, sizeof(g_Config.Device), "EPRDTDRV");
    strcpy_s(g_Config.Mode, sizeof(g_Config.Mode), "seq");
    g_Config.Disk = 1;
    g_Config.Part = 0;
    g_Config.Mb = 256;
    g_Config.BlockKb = 1024;
    g_Config.Iterations = 1000;
    strcpy_s(g_Config.Run, sizeof(g_Config.Run), "default");

    for (i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "--device") == 0 && i + 1 < argc) {
            strncpy_s(g_Config.Device, sizeof(g_Config.Device), argv[++i], _TRUNCATE);
        } else if (_stricmp(argv[i], "--disk") == 0 && i + 1 < argc) {
            g_Config.Disk = (ULONG)strtoul(argv[++i], NULL, 0);
        } else if (_stricmp(argv[i], "--part") == 0 && i + 1 < argc) {
            g_Config.Part = (ULONG)strtoul(argv[++i], NULL, 0);
        } else if (_stricmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            strncpy_s(g_Config.Mode, sizeof(g_Config.Mode), argv[++i], _TRUNCATE);
        } else if (_stricmp(argv[i], "--mb") == 0 && i + 1 < argc) {
            g_Config.Mb = (ULONG)strtoul(argv[++i], NULL, 0);
        } else if (_stricmp(argv[i], "--block-kb") == 0 && i + 1 < argc) {
            g_Config.BlockKb = (ULONG)strtoul(argv[++i], NULL, 0);
        } else if (_stricmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
            g_Config.Iterations = (ULONG)strtoul(argv[++i], NULL, 0);
        } else if (_stricmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            g_Config.Seed = (ULONG)strtoul(argv[++i], NULL, 0);
        } else if (_stricmp(argv[i], "--run") == 0 && i + 1 < argc) {
            strncpy_s(g_Config.Run, sizeof(g_Config.Run), argv[++i], _TRUNCATE);
        } else {
            fprintf(stderr, "usage: rdabench --device EPRDTDRV --disk 1 --mode seq|rand|open|info|"
                            "verify|fuzz [--mb N] [--block-kb N] [--iterations N] [--seed N] "
                            "[--run label]\n");
            return 2;
        }
    }

    if (_stricmp(g_Config.Mode, "open") == 0) {
        return BenchOpen();
    }
    if (_stricmp(g_Config.Mode, "seq") == 0) {
        return BenchSeq();
    }
    if (_stricmp(g_Config.Mode, "rand") == 0) {
        return BenchRand();
    }
    if (_stricmp(g_Config.Mode, "info") == 0) {
        return BenchInfo();
    }
    if (_stricmp(g_Config.Mode, "verify") == 0) {
        return BenchVerify();
    }
    if (_stricmp(g_Config.Mode, "fuzz") == 0) {
        return BenchFuzz();
    }
    fprintf(stderr, "unknown mode\n");
    return 2;
}
