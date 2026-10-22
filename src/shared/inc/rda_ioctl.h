/*
 * rda_ioctl.h - Public wire contract for the RDA (Raw Disk Access) driver.
 *
 * Shared by: kernel driver, user-mode client/test tools, documentation.
 *
 * This header preserves, byte-for-byte, the wire contracts of the three reference
 * drivers this project merges (see docs/ground-truth-contracts.md):
 *   - EPMNtDrv  (eprdtdrv.sys):  open grammar, PID-token gate, 3 custom IOCTLs,
 *                                sector IO semantics, IOCTL pass-through.
 *   - EUEDKEPM  (EuDskAcs.sys):  2-segment open grammar variant.
 *   - EUDCPEPM  (EuBackup.sys):  IoctlBase-normalized 15-command copy-session
 *                                protocol on the control device.
 *
 * Licensed under the MIT license. See LICENSE.
 */

#ifndef _RDA_IOCTL_H_
#define _RDA_IOCTL_H_

#include <stddef.h> /* offsetof - needed by the wire-offset asserts below */
#ifndef C_ASSERT
#define C_ASSERT(e) typedef char __C_ASSERT__[(e) ? 1 : -1]
#endif

/* Minimal integer types for standalone consumers (tests, docs tooling).
 * Kernel builds (ntddk.h) and windows.h consumers define these already.
 * C11-compatible duplicate typedefs are fine, but the guard keeps old MSVC
 * C-mode consumers happy. */
#if !defined(_NTDEF_) && !defined(_WINDOWS_) && !defined(_WDMDEF_)
typedef unsigned long ULONG, *PULONG;
typedef unsigned long long ULONG64, *PULONG64;
typedef long long LONGLONG, *PLONGLONG;
typedef void *HANDLE, *PVOID, *LPVOID;
typedef const void *LPCVOID;
typedef unsigned short WCHAR, *PWCHAR;
typedef const WCHAR *PCWSTR;
typedef int LONG, *PLONG;
typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef unsigned int UINT32;
typedef unsigned long long UINT64;
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * Device type for RDA custom IOCTLs (reference value: 0x600).
 * ------------------------------------------------------------------------- */
#define RDA_DEVICE_TYPE 0x600

/* ---------------------------------------------------------------------------
 * Reference identity IOCTLs (EPMNtDrv contract - exact codes).
 *
 * CTL_CODE(0x600, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS) = 0x60002400
 * CTL_CODE(0x600, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS) = 0x60002404
 * CTL_CODE(0x600, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS) = 0x60002408
 * ------------------------------------------------------------------------- */
#define IOCTL_RDA_GET_PROC_NAME         0x60002400UL
#define IOCTL_RDA_GET_FILE_OBJ_NAME     0x60002404UL
#define IOCTL_RDA_GET_DISK_CONTEXT_MODE 0x60002408UL

/* Input/output length gates for the identity IOCTLs (reference-exact). */
#define RDA_IDENT_IN_LEN      4UL     /* u32 PID or HANDLE */
#define RDA_IDENT_MIN_OUT_LEN 0x208UL /* >= 520 bytes (260 WCHARs, MAX_PATH) */

/* ---------------------------------------------------------------------------
 * RDA extended IOCTLs (new, clean interfaces - do not collide with reference
 * function codes 0x900..0x902).
 * ------------------------------------------------------------------------- */
#define CTL_CODE_RDA(Func) ((RDA_DEVICE_TYPE << 16) | ((Func) << 2) | 0 /* METHOD_BUFFERED */)

#define IOCTL_RDA_GET_INFO    CTL_CODE_RDA(0x910) /* 0x60002440 */
#define IOCTL_RDA_OPEN_TARGET CTL_CODE_RDA(0x911) /* 0x60002444 */
#define IOCTL_RDA_GET_VERSION CTL_CODE_RDA(0x912) /* 0x60002448 */

/* IOCTL_RDA_GET_INFO output. */
typedef struct _RDA_DRIVER_INFO {
    UINT32 StructSize;   /* sizeof(RDA_DRIVER_INFO), for versioning */
    UINT32 MajorVersion; /* RDA major */
    UINT32 MinorVersion; /* RDA minor */
    UINT32 Flags;        /* RDA_INFO_FLAG_* */
    UINT32 MaxDisks;     /* configured disk-number bound (reference: 200) */
    UINT32 IoctlBase;    /* session-protocol code base in effect */
} RDA_DRIVER_INFO, *PRDA_DRIVER_INFO;

#define RDA_INFO_FLAG_FILTER_MODE 0x00000001UL /* PnP filter role active */
#define RDA_INFO_FLAG_SESSIONS    0x00000002UL /* copy-session engine active */

/* IOCTL_RDA_OPEN_TARGET input (explicit open - no kernel string parsing). */
typedef struct _RDA_OPEN_TARGET_IN {
    UINT32 StructSize;   /* sizeof(RDA_OPEN_TARGET_IN) */
    UINT32 Kind;         /* RDA_TARGET_KIND_* */
    UINT32 DiskNumber;   /* Kinds: DISK, DISK_PART */
    UINT32 PartNumber;   /* Kind: DISK_PART (DR-fallback selector, reference parity) */
    UINT32 VolumeNumber; /* Kind: VOLUME */
    UINT32 Reserved;
} RDA_OPEN_TARGET_IN, *PRDA_OPEN_TARGET_IN;

#define RDA_TARGET_KIND_VOLUME    1 /* \\.\SYM\Volume\{N} equivalent */
#define RDA_TARGET_KIND_DISK      2 /* EUEDKEPM 2-segment variant: whole disk, walk-to-Disk */
#define RDA_TARGET_KIND_DISK_PART 3 /* EPMNtDrv 3-segment variant */

/* Version reported by IOCTL_RDA_GET_VERSION / session GET_VERSION. */
#define RDA_VERSION_MAJOR 1UL
#define RDA_VERSION_MINOR 0UL

/* ---------------------------------------------------------------------------
 * PID-token handshake (EPMNtDrv + EUEDKEPM + Device.mo client - exact transform).
 *
 *   b0..b3 = little-endian bytes of the 32-bit process id
 *   token  = b0 | (b0+b1)<<8 | (b1+b2)<<16 | (b2+b3)<<24   (8-bit wrapping adds)
 *
 * The token is computed over the CALLING process's own PID and embedded as the
 * first path component when opening sub-devices. The driver re-derives it at
 * IRP_MJ_CREATE time from PsGetCurrentProcessId(); any mismatch fails the open
 * with STATUS_INVALID_PARAMETER. This is a client-binding handshake inherited
 * from the reference drivers; it is NOT a security boundary (device SDDL is).
 * ------------------------------------------------------------------------- */
/*
 * RdaComputePidToken is implemented as a portable inline function in
 * rda_compat.h (pure logic shared with user mode and tests). A macro with
 * byte-sum shifts overflows 32-bit int promotion and is undefined behavior;
 * the function performs the arithmetic in ULONG.
 */

/* ---------------------------------------------------------------------------
 * READ/WRITE contract (reference-exact semantics - see
 * docs/ground-truth-contracts.md section 3, verified on both sides):
 *
 *   - Buffer and Parameters.Read/Write.Length are in BYTES (the IO manager
 *     probes and locks exactly that many bytes; the forwarded disk IO
 *     transfers exactly that many bytes into the locked buffer).
 *   - Parameters.Read/Write.ByteOffset is the absolute BYTE offset on the
 *     target (clients pass SetFilePointer(sector * sectorSize)).
 *   - On success the driver reports Information = Length * 512 (the legacy
 *     scaled-transfer convention). Legacy reference clients divide by 512 to
 *     recover the true byte count. New clients should use the
 *     IOCTL_RDA_GET_INFO-era contract or divide likewise.
 *   - Negative offsets fail with STATUS_INVALID_PARAMETER.
 * ------------------------------------------------------------------------- */
#define RDA_LEGACY_INFORMATION_SCALE 512UL

/* ---------------------------------------------------------------------------
 * Copy-session protocol (EUDCPEPM contract - exact normalized codes).
 *
 * The wire code seen by the driver is  custom_code + IoctlBase  where
 * IoctlBase is the service-key DWORD "IoctlBase" (default 0; the WinPE
 * reference deployment sets 0x10000). Session-reverification 2026-10-22
 * decoded the FULL command set (18 codes) - the prior research artifacts
 * missed the discovery + RRWR families:
 *
 *   code        in-gate  out-gate  semantics (verified in decompile)
 *   ----------  -------   --------  ----------------------------------
 *   0x800C2AC0     4+         -      discovery: returns bound diskId, Info=4
 *   0x800C2AC8   >=0x84       -      GET_VERSION: 0x00010100 + 0x2E string, Info=0
 *   0x800C2AD0   >=0x840      -      OPEN_SESSION (0x840 wire struct)
 *   0x800C2AD8     >=8        -      flush protected file's volume (state 1/3)
 *   0x800C2AE0   >=0x28       -      StartBackup (dest pump buffer + regions)
 *   0x800C2AE8     >=8       >=0x1E   GETNEXTBLOCK (async copy pump, Info=0x1E)
 *   0x800C2AF0     >=8        -      status: block-map status AS the NTSTATUS
 *   0x800C2AF8   >=0x0C       -      finalize ("GET_PROGRESS"): percent @+8
 *   0x800C2B00     >=8        -      CLOSE_SESSION
 *   0x800C2B0A     -         >0x10   DIRECT_READ  (METHOD_OUT_DIRECT, LBA)
 *   0x800C2B12     -         >0x10   DIRECT_WRITE (METHOD_OUT_DIRECT, LBA)
 *   0x800C2B18   >=0x1C     >=4      MODE4 = raw paging WRITE by file handle
 *   0x800C2B20   >=0x1C     >=4      MODE3 = raw paging READ by file handle
 *   0x800C2B2A     -         >0x10   SIZED read (per-disk sector-size cache)
 *   0x800C2B2E     -         >0x10   SIZED write
 *   0x800C2B38     >=8        -      CANCEL (state := 3)
 *   0x800C2B3E   >=0x1C     -      RRWR raw disk WRITE ("RRWR" magic)
 *   0x800C2B40     >=4       -      RRWR version probe: 0x604 @+8, Info=0xC
 *   0x800C2B42   >=0x1C     -      RRWR raw disk READ
 *
 * Direct/sized/RRWR codes are METHOD_OUT_DIRECT: header + data travel in the
 * MDL'd output buffer. All direct-family offsets are LBA sector numbers
 * multiplied by the disk's probed sector size at execution time.
 * ------------------------------------------------------------------------- */
#define RDA_SESSION_CODE_DISCOVERY      0x800C2AC0UL
#define RDA_SESSION_CODE_GET_VERSION    0x800C2AC8UL
#define RDA_SESSION_CODE_OPEN_SESSION   0x800C2AD0UL
#define RDA_SESSION_CODE_SESSION_OP     0x800C2AD8UL
#define RDA_SESSION_CODE_SESSION_OP2    0x800C2AE0UL
#define RDA_SESSION_CODE_GETNEXTBLOCK   0x800C2AE8UL
#define RDA_SESSION_CODE_SESSION_STATUS 0x800C2AF0UL
#define RDA_SESSION_CODE_GET_PROGRESS   0x800C2AF8UL
#define RDA_SESSION_CODE_CLOSE_SESSION  0x800C2B00UL
#define RDA_SESSION_CODE_DIRECT_READ    0x800C2B0AUL
#define RDA_SESSION_CODE_DIRECT_WRITE   0x800C2B12UL
#define RDA_SESSION_CODE_MODE4          0x800C2B18UL
#define RDA_SESSION_CODE_MODE3          0x800C2B20UL
#define RDA_SESSION_CODE_SIZED_XFER     0x800C2B2AUL
#define RDA_SESSION_CODE_SIZED_XFER2    0x800C2B2EUL
#define RDA_SESSION_CODE_CANCEL         0x800C2B38UL
#define RDA_SESSION_CODE_RRWR_WRITE     0x800C2B3EUL
#define RDA_SESSION_CODE_RRWR_VERSION   0x800C2B40UL
#define RDA_SESSION_CODE_RRWR_READ      0x800C2B42UL

/* Session buffer gates (reference-exact, per-command in/out lengths). */
#define RDA_SESSION_INPUT_MIN_LEN        8UL /* codes that take a session handle */
#define RDA_SESSION_GET_VERSION_MIN_IN   0x84UL
#define RDA_SESSION_STRUCT_SIZE          0x840UL /* OpenSession in/out buffer */
#define RDA_SESSION_GETNEXTBLOCK_MIN_IN  0x1EUL
#define RDA_SESSION_GETNEXTBLOCK_MIN_OUT 0x1EUL
#define RDA_SESSION_GETNEXTBLOCK_INFO    0x1EUL /* Information after completion */
#define RDA_SESSION_STARTBACKUP_MIN_IN   0x28UL
#define RDA_SESSION_PROGRESS_MIN_IN      0x0CUL
#define RDA_SESSION_FILEIO_MIN_IN        0x1CUL /* MODE3/MODE4 raw file R/W */
#define RDA_SESSION_DIRECT_MIN_OUT       0x11UL /* direct/sized: out > 0x10 */
#define RDA_SESSION_RRWR_MIN_IN          0x1CUL
#define RDA_SESSION_RRWR_VERSION_OUT     0x604UL
#define RDA_SESSION_RRWR_INFO            0x0CUL

/* Session state machine (verified: state field @+0x38, spinlock-guarded).
 * 0 created -> 1 flush-in-progress -> 3 standby/cancel -> 4 copying -> 5 done.
 * CANCEL forces 3 from any state; StartBackup requires 3. */
#define RDA_SESSION_STATE_CREATED  0
#define RDA_SESSION_STATE_FLUSHING 1
#define RDA_SESSION_STATE_STANDBY  3
#define RDA_SESSION_STATE_COPYING  4
#define RDA_SESSION_STATE_DONE     5

/* RRWR companion magic (read raw / write raw handshake). */
#define RDA_RRWR_MAGIC 0x52455752UL /* "RRWR" */

/* GetNextBlock wire record (in == out == 0x1E, overlaid). Input:
 *   +0x00 session handle, +0x08 cursor sector (LBA), +0x10 max sector count.
 * Output: +0x14 source diskId, +0x18 copy progress percent (u32),
 * +0x1C block-map build percent (byte), +0x1D block-map ok flag (byte).
 * The copied data itself lands in the pump buffer registered at StartBackup
 * (the reference locks a caller user-mode buffer with an MDL), NOT in the
 * IRP buffer. Information is always 0x1E on completion. */
#pragma pack(push, 1)
typedef struct _RDA_GETNEXTBLOCK {
    UINT64 Handle;     /* +0x00 in */
    UINT64 CursorSec;  /* +0x08 in */
    UINT32 MaxSec;     /* +0x10 in */
    UINT32 DiskId;     /* +0x14 out */
    UINT32 Progress;   /* +0x18 out */
    UINT8 MapProgress; /* +0x1C out */
    UINT8 MapOk;       /* +0x1D out */
} RDA_GETNEXTBLOCK, *PRDA_GETNEXTBLOCK;
#pragma pack(pop)
C_ASSERT(sizeof(RDA_GETNEXTBLOCK) == 0x1EUL);
C_ASSERT(offsetof(RDA_GETNEXTBLOCK, CursorSec) == 0x08);
C_ASSERT(offsetof(RDA_GETNEXTBLOCK, MaxSec) == 0x10);
C_ASSERT(offsetof(RDA_GETNEXTBLOCK, DiskId) == 0x14);
C_ASSERT(offsetof(RDA_GETNEXTBLOCK, Progress) == 0x18);
C_ASSERT(offsetof(RDA_GETNEXTBLOCK, MapProgress) == 0x1C);
C_ASSERT(offsetof(RDA_GETNEXTBLOCK, MapOk) == 0x1D);

/* StartBackup wire input (0x28 bytes total; the reference reads the fields
 * at the offsets below directly from the SystemBuffer, including the
 * 4-mod-8 UNALIGNED 64-bit user-bitmap pointer at +0x14 - hence pack(4)):
 *   +0x00 session handle, +0x08 pump buffer USER pointer (locked via MDL),
 *   +0x10 pump buffer byte size (must be spb*sectorSize aligned),
 *   +0x14 optional user exclusion-bitmap pointer (bit count at +0x20),
 *   +0x1C start sector (u32), +0x20 block count (u32), +0x24 spb (u32,
 *   must equal the session's spb when a user bitmap is supplied). */
#pragma pack(push, 4)
typedef struct _RDA_STARTBACKUP_IN {
    UINT64 Handle;     /* +0x00 */
    PVOID PumpBuffer;  /* +0x08 */
    UINT32 PumpBytes;  /* +0x10 */
    PVOID UserBitmap;  /* +0x14 (unaligned-8 on the wire; pack(4) matches) */
    UINT32 StartSec;   /* +0x1C */
    UINT32 BlockCount; /* +0x20 */
    UINT32 Spb;        /* +0x24 */
} RDA_STARTBACKUP_IN, *PRDA_STARTBACKUP_IN;
#pragma pack(pop)
C_ASSERT(sizeof(RDA_STARTBACKUP_IN) == 0x28UL);
C_ASSERT(offsetof(RDA_STARTBACKUP_IN, PumpBuffer) == 0x08);
C_ASSERT(offsetof(RDA_STARTBACKUP_IN, PumpBytes) == 0x10);
C_ASSERT(offsetof(RDA_STARTBACKUP_IN, UserBitmap) == 0x14);
C_ASSERT(offsetof(RDA_STARTBACKUP_IN, StartSec) == 0x1C);
C_ASSERT(offsetof(RDA_STARTBACKUP_IN, BlockCount) == 0x20);
C_ASSERT(offsetof(RDA_STARTBACKUP_IN, Spb) == 0x24);

/* MODE3/MODE4 raw file IO wire input (0x1C bytes):
 *   +0x00 file handle, +0x08 user buffer pointer, +0x10 byte offset,
 *   +0x18 byte length. MODE3 = IRP_MJ_READ, MODE4 = IRP_MJ_WRITE, issued as
 *   paging IO against the file's volume stack with the caller's file object. */
#pragma pack(push, 4)
typedef struct _RDA_FILEIO_IN {
    HANDLE FileHandle; /* +0x00 */
    PVOID Buffer;      /* +0x08 */
    UINT64 ByteOffset; /* +0x10 */
    UINT32 Length;     /* +0x18 */
} RDA_FILEIO_IN, *PRDA_FILEIO_IN;
#pragma pack(pop)
C_ASSERT(sizeof(RDA_FILEIO_IN) == 0x1CUL);
C_ASSERT(offsetof(RDA_FILEIO_IN, Buffer) == 0x08);
C_ASSERT(offsetof(RDA_FILEIO_IN, ByteOffset) == 0x10);
C_ASSERT(offsetof(RDA_FILEIO_IN, Length) == 0x18);

/*
 * RDA_OPEN_SESSION layout (overlaid in/out buffer of RDA_SESSION_STRUCT_SIZE
 * bytes) - reference-exact offsets (verified from the EUDCPEPM decompile).
 * Packed to 4: the reference wire format places 64-bit fields at 4-mod-8
 * offsets (e.g. DataFirstSec at +0x004), so natural alignment must be off.
 */
#include <stddef.h> /* offsetof */

#ifndef C_ASSERT
#define C_ASSERT(e) typedef char __C_ASSERT__[(e) ? 1 : -1]
#endif

#pragma pack(push, 4)
typedef struct _RDA_OPEN_SESSION {
    /* 0x000 */ UINT32 DiskId;
    /* 0x004 */ UINT64 DataFirstSec;      /* copy range start sector */
    /* 0x00C */ UINT64 TotalSecs;         /* must be nonzero */
    /* 0x014 */ UINT64 ExtentParam1;      /* block-map builder parameter */
    /* 0x01C */ UINT64 ExtentParam2;      /* block-map builder parameter */
    /* 0x024 */ UINT64 BitmapSize;        /* must be nonzero */
    /* 0x02C */ UINT32 BitmapCount;       /* must be nonzero */
    /* 0x030 */ UINT32 SpbInOut;          /* IN: 0 => driver picks (<0x20 ? 1 : 0x10);
                                           * OUT: overwritten with the effective
                                           * spb (reference-verified: the ctor
                                           * writes the effective spb back at
                                           * this same offset; +0x838 is unused
                                           * padding in the reference wire format). */
    /* 0x034 */ UINT8 BlockBitmap[0x800]; /* bit per copy block, NUL pad @0x7FE */
                                          /* OUT: */
    /* 0x834 */ UINT64 SessionHandle;     /* opaque 64-bit handle (RDA: ID, not pointer) */
    /* 0x83C */ UINT32 SectorSize;
} RDA_OPEN_SESSION, *PRDA_OPEN_SESSION;
#pragma pack(pop)

/* Wire-offset verification (compilers reject the build if these drift). */
C_ASSERT(offsetof(RDA_OPEN_SESSION, DataFirstSec) == 0x004);
C_ASSERT(offsetof(RDA_OPEN_SESSION, TotalSecs) == 0x00C);
C_ASSERT(offsetof(RDA_OPEN_SESSION, ExtentParam1) == 0x014);
C_ASSERT(offsetof(RDA_OPEN_SESSION, ExtentParam2) == 0x01C);
C_ASSERT(offsetof(RDA_OPEN_SESSION, BitmapSize) == 0x024);
C_ASSERT(offsetof(RDA_OPEN_SESSION, BitmapCount) == 0x02C);
C_ASSERT(offsetof(RDA_OPEN_SESSION, SpbInOut) == 0x030);
C_ASSERT(offsetof(RDA_OPEN_SESSION, BlockBitmap) == 0x034);
C_ASSERT(offsetof(RDA_OPEN_SESSION, SessionHandle) == 0x834);
C_ASSERT(offsetof(RDA_OPEN_SESSION, SectorSize) == 0x83C);
C_ASSERT(sizeof(RDA_OPEN_SESSION) == RDA_SESSION_STRUCT_SIZE);

/* Reference session identity answered by RDA_SESSION_CODE_GET_VERSION.
 * The reference wrote 0x00010100 then a 0x2E-byte product string. RDA answers
 * the same version dword and its own equal-or-shorter product string. */
#define RDA_SESSION_PROTO_VERSION      0x00010100UL
#define RDA_SESSION_PRODUCT_STRING     "RDA Disk Copy Driver (c) RDA contributors"
#define RDA_SESSION_PRODUCT_STRING_MAX 0x2EUL

/* Overlap guard: opening a session whose sector range overlaps an active
 * session on the same disk fails with STATUS_SHARING_VIOLATION
 * (reference-verified behavior). */
#ifndef STATUS_SHARING_VIOLATION
#define STATUS_SHARING_VIOLATION ((LONG)0xC0000043L)
#endif

/* ---------------------------------------------------------------------------
 * Legacy "global handle" modes on bare opens (reference-exact):
 *   WRITE with Parameters.Write.Length == 4 and no resolved target:
 *       stores the caller's u32 handle value into the driver global slot.
 *   READ with no resolved target and out length >= 0x208 (when the slot is
 *       nonzero): resolves the stored handle's object name into the buffer.
 * RDA keeps the read-name half and gates the store half to admin callers.
 * ------------------------------------------------------------------------- */

#ifdef __cplusplus
}
#endif

#endif /* _RDA_IOCTL_H_ */
