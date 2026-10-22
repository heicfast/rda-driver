/*
 * rda_p.h - Private definitions for the RDA kernel driver.
 *
 * Structure map (see docs/architecture.md):
 *   rda_driver.c    entry/unload, dispatch table, globals
 *   rda_registry.c service Parameters reading
 *   rda_control.c   control device (service-name-derived naming, SDDL)
 *   rda_target.c    volume/disk device resolution (reference-exact chains)
 *   rda_create.c    IRP_MJ_CREATE (grammar, token gate, context setup)
 *   rda_readwrite.c IRP_MJ_READ/WRITE (cancellable sector forwarding)
 *   rda_ioctl.c    custom IOCTLs + pass-through + session protocol routing
 *   rda_ident.c    GetProcName / GetFileObjName identity services
 *   rda_session.c  copy-session engine (15-command protocol)
 *   rda_filter.c   PnP disk-class upper-filter role (WinPE deployment)
 *   rda_util.c     pool/string helpers
 *
 * Licensed under the MIT license. See LICENSE.
 */

#ifndef _RDA_P_H_
#define _RDA_P_H_

#include "../../shared/inc/rda_compat.h"
#include "../../shared/inc/rda_ioctl.h"
/* Base headers - ORDER IS LOAD-BEARING (kernel C):
 * ntifs.h must come first: it includes ntddk.h -> wdm.h in that exact
 * order. Including wdm.h first (e.g. via another header) defines _NTDDK_
 * inside wdm.h and silently neuters the later ntddk.h include, wiping out
 * all DDK-level declarations. ntifs.h also provides ObQueryNameString,
 * IoGetLowerDeviceObject, PsLookupProcessByProcessId and
 * SeLocateProcessImageName used by this driver. */
#include <ntifs.h>
#include <wdmsec.h>
#include <ntdddisk.h> /* IOCTL_DISK_GET_DRIVE_GEOMETRY + DISK_GEOMETRY (SDK shared) */

#include "rda_trace.h"

#pragma warning(push)
/* RDA sources compile at /W4 /WX. System/WDK headers are silenced globally
 * via /external:W0 in the project settings. */

/* ---------------------------------------------------------------------------
 * Identity
 * ------------------------------------------------------------------------- */
#define RDA_POOL_TAG   ((ULONG)'rda1')
#define RDA_DOS_PREFIX L"\\DosDevices\\"
#define RDA_DEV_PREFIX L"\\Device\\"
#define RDA_FALLBACK_BASE_NAME                                                                     \
    L"EPMNTDRV" /* reference default when the                                                      \
                 * service name is unusable */
#define RDA_NAME_BUFFER_CHARS   64
#define RDA_SECTOR_SIZE_DEFAULT 512

/* Reference bounds (documented, parameter-configurable where noted). */
#define RDA_DISK_LIMIT_EPMNTDRV 200   /* reference: disk# <= 199 */
#define RDA_DISK_LIMIT_EUEDKEPM 100   /* reference: disk# < 100 */
#define RDA_QUERY_NAME_BUFFER   0x200 /* reference ObQueryNameString buffer */

/* Default device SDDL: Administrators and SYSTEM full access only.
 * This closes the reference drivers' "any process that can open the device
 * can issue identity IOCTLs" gap (fix F2). Overridable via Parameters\Sddl. */
#define RDA_DEFAULT_SDDL L"D:P(A;;GA;;;BA)(A;;GA;;;SY)"

/* Class GUID for the RDA control device class (allows admins to tighten
 * device security through the class key, per wdmsec.h guidance).
 * Generated once, fixed forever: {22503FD1-90D4-4322-B62D-9C8FFE186E33}. */
static const GUID RDA_DEVICE_CLASS_GUID = {
    0x22503FD1, 0x90D4, 0x4322, {0xB6, 0x2D, 0x9C, 0x8F, 0xFE, 0x18, 0x6E, 0x33}};

/* ---------------------------------------------------------------------------
 * Per-handle open context (stored in FileObject->FsContext2; the reference
 * kept {target, mode} in 0x10 bytes - we extend with geometry + kind).
 * ------------------------------------------------------------------------- */
typedef enum _RDA_CONTEXT_KIND {
    RdaCtxGlobal = 0, /* bare open: identity IOCTLs + global-handle modes */
    RdaCtxVolume = 1, /* \Volume\{N}: top-of-volume-stack target, mode 0 */
    RdaCtxDisk = 2,   /* {disk}\{part}: walk-to-Harddisk-layer target + mode */
    RdaCtxDiskEpm = 3 /* {disk}: walk-to-\Driver\Disk target (EUEDKEPM) */
} RDA_CONTEXT_KIND;

typedef struct _RDA_OPEN_CONTEXT {
    /* Referenced FILE_OBJECT returned by IoGetDeviceObjectPointer at open
     * time (the reference kept it in FileObject->FsContext). */
    PFILE_OBJECT TargetFileObject;
    /* Referenced target device object for all forwarding (FsContext2 slot). */
    PDEVICE_OBJECT TargetDevice;
    /* Reference parity: 0 when the chosen layer's driver is \Driver\Disk,
     * 1 otherwise (exposed via IOCTL_RDA_GET_DISK_CONTEXT_MODE). */
    LONG Mode;
    RDA_CONTEXT_KIND Kind;
    /* Logical sector size of the target in bytes (probed at open; F1 fix).
     * 512/4096 typical. Callers see absolute-byte offsets; 4Kn devices are
     * supported without the reference's silent corruption. */
    ULONG SectorSize;
} RDA_OPEN_CONTEXT, *PRDA_OPEN_CONTEXT;

/* ---------------------------------------------------------------------------
 * Driver parameters (Parameters subkey of the service key; see
 * docs/architecture.md). Populated at DriverEntry.
 * ------------------------------------------------------------------------- */
typedef struct _RDA_PARAMETERS {
    ULONG IoctlBase;                         /* session code base (default 0; PE sets 0x10000) */
    ULONG MaxDisks;                          /* open-grammar disk bound (default 200) */
    ULONG DebugLevel;                        /* 0..5 (default 1 = errors only) */
    ULONG FilterMode;                        /* 1 = PnP filter attach role active */
    ULONG VolSnapAttach;                     /* 1 = also attach VolSnap devices (PE parity) */
    ULONG SessionsEnabled;                   /* 1 = copy-session engine served (default 1) */
    BOOLEAN UseDeviceName;                   /* Parameters\DeviceName overrides naming scheme */
    WCHAR DeviceName[RDA_NAME_BUFFER_CHARS]; /* \Device base name when
                                                UseDeviceName */
    WCHAR Sddl[128];                         /* device DACL override; empty -> RDA_DEFAULT_SDDL */
} RDA_PARAMETERS, *PRDA_PARAMETERS;

/* ---------------------------------------------------------------------------
 * Globals (rda_driver.c)
 * ------------------------------------------------------------------------- */
extern PDRIVER_OBJECT g_RdaDriverObject;
extern PDEVICE_OBJECT g_RdaControlDevice;
extern UNICODE_STRING g_RdaDeviceName; /* \Device\... (owned buffer) */
extern UNICODE_STRING g_RdaDosName;    /* \DosDevices\... (owned buffer) */
extern RDA_PARAMETERS g_RdaParameters;
extern ULONG g_RdaDebugLevel;
extern volatile LONG64 g_RdaGlobalHandle; /* reference "DAT_00015170" slot */

/* ---------------------------------------------------------------------------
 * rda_util.c
 * ------------------------------------------------------------------------- */
_IRQL_requires_max_(PASSIVE_LEVEL) PVOID RdaAllocZero(_In_ SIZE_T Bytes);
_IRQL_requires_max_(PASSIVE_LEVEL) PVOID RdaAlloc(_In_ SIZE_T Bytes);
_IRQL_requires_max_(DISPATCH_LEVEL) VOID RdaFree(_In_opt_ PVOID Memory);
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    RdaFormatDeviceName(_Out_ PUNICODE_STRING Name, _In_z_ PCWSTR Format, _In_ ULONG Number);

/* ---------------------------------------------------------------------------
 * rda_registry.c
 * ------------------------------------------------------------------------- */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS RdaReadParameters(_In_ PUNICODE_STRING RegistryPath);

/* ---------------------------------------------------------------------------
 * rda_control.c
 * ------------------------------------------------------------------------- */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    RdaCreateControlDevice(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
_IRQL_requires_max_(PASSIVE_LEVEL) VOID RdaDeleteControlDevice(VOID);

/* ---------------------------------------------------------------------------
 * rda_target.c - reference-exact resolution chains
 * ------------------------------------------------------------------------- */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    RdaResolveVolume(_In_ ULONG VolumeNumber, _Out_ PRDA_OPEN_CONTEXT Context);

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    RdaResolveDisk(_In_ ULONG DiskNumber, _In_ ULONG PartNumber, _Out_ PRDA_OPEN_CONTEXT Context);

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    RdaResolveDiskEpm(_In_ ULONG DiskNumber, _Out_ PRDA_OPEN_CONTEXT Context);

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    RdaProbeSectorSize(_In_ PDEVICE_OBJECT TargetDevice, _Out_ PULONG SectorSize);

/* ---------------------------------------------------------------------------
 * rda_create.c / cleanup
 * ------------------------------------------------------------------------- */
DRIVER_DISPATCH RdaDispatchCreate;
DRIVER_DISPATCH RdaDispatchCleanup;
DRIVER_DISPATCH RdaDispatchClose;

_IRQL_requires_max_(PASSIVE_LEVEL) VOID RdaReleaseContext(_In_opt_ PRDA_OPEN_CONTEXT Context);

/* ---------------------------------------------------------------------------
 * rda_readwrite.c
 * ------------------------------------------------------------------------- */
DRIVER_DISPATCH RdaDispatchRead;
DRIVER_DISPATCH RdaDispatchWrite;

/* Internal synchronous sector IO (no caller IRP; used by the session engine). */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    RdaSyncDiskReadWrite(_In_ PDEVICE_OBJECT TargetDevice, _In_ UCHAR MajorFunction,
                         _In_ PVOID SystemAddress, _In_ ULONG Length,
                         _In_ PLARGE_INTEGER ByteOffset, _Out_ PULONG_PTR Information);

/* ---------------------------------------------------------------------------
 * rda_ioctl.c / rda_ident.c
 * ------------------------------------------------------------------------- */
DRIVER_DISPATCH RdaDispatchDeviceControl;

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    RdaIoctlGetProcName(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack);
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    RdaIoctlGetFileObjName(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack);

/* Shared core: resolve a file HANDLE to its fully-qualified NT name into the
 * caller's kernel buffer (used by IOCTL 0x60002404 and the global-handle
 * READ mode). Information receives byte length including the NUL. */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    RdaIoctlGetFileObjNameCore(_In_ HANDLE FileHandle, _Out_writes_bytes_(BufferBytes) PVOID Buffer,
                               _In_ ULONG BufferBytes, _Out_ PULONG_PTR Information);
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    RdaIoctlGetDiskContextMode(_In_ PIRP Irp, _In_ PRDA_OPEN_CONTEXT Context);
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    RdaIoctlGetInfo(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack);
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    RdaIoctlGetVersion(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack);
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    RdaIoctlOpenTarget(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack);

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    RdaPassThroughIoctl(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack,
                        _In_ PRDA_OPEN_CONTEXT Context);

/* ---------------------------------------------------------------------------
 * rda_session.c - copy-session engine (EUDCPEPM protocol merge)
 * ------------------------------------------------------------------------- */
_IRQL_requires_max_(PASSIVE_LEVEL) VOID RdaSessionInit(VOID);
_IRQL_requires_max_(PASSIVE_LEVEL) VOID RdaSessionShutdown(VOID);
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    RdaSessionDispatch(_In_ ULONG CustomCode, _In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack,
                       _In_opt_ PRDA_OPEN_CONTEXT Context);

/* Destroy every session owned by the given process (control-device
 * CLEANUP/CLOSE sweep - reference FUN_00012aa0). */
_IRQL_requires_max_(PASSIVE_LEVEL) VOID
    RdaSessionSweepByProcess(_In_ PEPROCESS Process);

/* Destroy every session bound to the given disk (filter REMOVE path -
 * reference FUN_0001324c). */
_IRQL_requires_max_(PASSIVE_LEVEL) VOID RdaSessionKillByDisk(_In_ ULONG DiskId);

/* TRUE when a session on the disk is in the standby/copying state
 * (filter TRIM swallow + write-park gating - reference FUN_00012d64). */
_IRQL_requires_max_(PASSIVE_LEVEL) BOOLEAN RdaSessionActiveOnDisk(_In_ ULONG DiskId);

/* Filter WRITE coordination (reference FUN_0001189c/FUN_0001573c):
 * STANDBY sessions park the write (async, worker forwards it through
 * LowerDeviceObject once the session wakes); COPYING sessions COW-save the
 * covered range and the caller forwards synchronously; Blocked means the
 * caller must complete the IRP with STATUS_INSUFFICIENT_RESOURCES. */
typedef enum _RDA_WRITE_INTERCEPT {
    RdaWriteForward = 0, /* caller forwards down the stack */
    RdaWriteParked = 1,  /* session owns the IRP (async forward) */
    RdaWriteBlocked = 2  /* caller completes the IRP with an error */
} RDA_WRITE_INTERCEPT;

_IRQL_requires_max_(PASSIVE_LEVEL) RDA_WRITE_INTERCEPT
    RdaSessionInterceptWrite(_In_ ULONG DiskId, _In_ PIRP Irp,
                             _In_ PDEVICE_OBJECT LowerDeviceObject, _In_ ULONG64 StartSec,
                             _In_ ULONG SecCount);

/* ---------------------------------------------------------------------------
 * rda_disk.c - per-disk target cache (session/direct/RRWR resolution)
 *
 * The reference resolved session/direct/RRWR diskIds through the per-disk
 * wrapper objects created at filter AddDevice, with an id-indexed sector
 * size cache (DAT_00020350, 32 entries). RDA resolves diskIds on demand
 * through the EUEDKEPM chain (Partition0 + walk to the disk class layer),
 * probes geometry, and caches the referenced target so live-OS (non-filter)
 * deployments get the same protocol. Cache is flushed at unload and when a
 * disk is removed.
 * ------------------------------------------------------------------------- */
typedef struct _RDA_DISK_TARGET {
    LIST_ENTRY Link;
    ULONG DiskId;
    ULONG SectorSize;         /* probed logical sector size */
    PDEVICE_OBJECT Target;    /* referenced disk-class layer */
    PFILE_OBJECT FileObject;  /* referenced (IoGetDeviceObjectPointer) */
} RDA_DISK_TARGET, *PRDA_DISK_TARGET;

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    RdaDiskTargetAcquire(_In_ ULONG DiskId, _Out_ PRDA_DISK_TARGET *Target);
_IRQL_requires_max_(PASSIVE_LEVEL) VOID RdaDiskTargetRelease(_In_ PRDA_DISK_TARGET Target);
_IRQL_requires_max_(PASSIVE_LEVEL) VOID RdaDiskCacheInit(VOID);
_IRQL_requires_max_(PASSIVE_LEVEL) VOID RdaDiskCacheShutdown(VOID);
_IRQL_requires_max_(PASSIVE_LEVEL) VOID RdaDiskCacheRemoveDisk(_In_ ULONG DiskId);

/* Sector IO against a cached disk target (LBA -> byte offset internally). */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    RdaDiskReadWriteSectors(_In_ PRDA_DISK_TARGET Disk, _In_ UCHAR MajorFunction,
                           _In_ PVOID SystemAddress, _In_ ULONG64 StartLba, _In_ ULONG SectorCount,
                           _Out_opt_ PULONG_PTR Information);

/* ---------------------------------------------------------------------------
 * rda_filter.c - PnP disk-class upper-filter role
 * ------------------------------------------------------------------------- */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS RdaFilterStart(VOID);
_IRQL_requires_max_(PASSIVE_LEVEL) VOID RdaFilterStop(VOID);

/* Filter-stack dispatch: forwards everything, intercepts WRITEs overlapping
 * active session ranges (park / COW), swallows TRIMs, serves the discovery +
 * RRWR handshake (reference FUN_00012b70/00018890). */
DRIVER_DISPATCH RdaDispatchFilter;

DRIVER_DISPATCH RdaDispatchPnp;
DRIVER_DISPATCH RdaDispatchPower;
DRIVER_ADD_DEVICE RdaFilterAddDevice;

#pragma warning(pop)
#endif /* _RDA_P_H_ */
