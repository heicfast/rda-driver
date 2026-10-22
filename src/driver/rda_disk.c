/*
 * rda_disk.c - per-disk target resolution and sector-IO cache.
 *
 * Reference model (EUDCPEPM, decompile-verified 2026-10-22):
 *   - Session/direct/sized/RRWR disk numbers resolve through per-disk wrapper
 *     objects created at filter AddDevice (FUN_00012014) with an id-indexed
 *     sector-size cache (FUN_00014748 over DAT_00020350, 32 entries).
 *   - Sector IO is built with IoBuildSynchronousFsdRequest against the disk
 *     wrapper's target device, byte offset = LBA * probed sector size
 *     (FUN_00014300 "ReadSectors" / FUN_000141f8 direct write).
 *
 * RDA implementation: diskIds resolve on demand through the EUEDKEPM chain
 * ("\Device\HarddiskN\Partition0" + walk to the disk-class layer), geometry
 * probed once, and the referenced target cached. This makes the session
 * protocol usable in BOTH deployment roles (live OS without the filter, and
 * WinPE with the filter), matching the reference when the filter is active.
 *
 * Licensed under the MIT license. See LICENSE.
 */

#include "rda_p.h"

#define RDA_DISK_CACHE_MAX 32 /* reference cache width (DAT_00020350) */

static LIST_ENTRY g_RdaDiskListHead;
static FAST_MUTEX g_RdaDiskListLock;
static BOOLEAN g_RdaDiskListInitialized = FALSE;

_IRQL_requires_max_(PASSIVE_LEVEL) VOID RdaDiskCacheInit(VOID) {
    InitializeListHead(&g_RdaDiskListHead);
    ExInitializeFastMutex(&g_RdaDiskListLock);
    g_RdaDiskListInitialized = TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL) VOID RdaDiskCacheRemoveDisk(_In_ ULONG DiskId) {
    PLIST_ENTRY entry;

    if (!g_RdaDiskListInitialized) {
        return;
    }

    ExAcquireFastMutex(&g_RdaDiskListLock);
    entry = g_RdaDiskListHead.Flink;
    while (entry != &g_RdaDiskListHead) {
        PRDA_DISK_TARGET disk = CONTAINING_RECORD(entry, RDA_DISK_TARGET, Link);
        PLIST_ENTRY next = entry->Flink;

        if (disk->DiskId == DiskId) {
            RemoveEntryList(entry);
            ObDereferenceObject(disk->Target);
            ObDereferenceObject(disk->FileObject);
            RdaFree(disk);
        }
        entry = next;
    }
    ExReleaseFastMutex(&g_RdaDiskListLock);
}

_IRQL_requires_max_(PASSIVE_LEVEL) VOID RdaDiskCacheShutdown(VOID) {
    if (!g_RdaDiskListInitialized) {
        return;
    }

    ExAcquireFastMutex(&g_RdaDiskListLock);
    while (!IsListEmpty(&g_RdaDiskListHead)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_RdaDiskListHead);
        PRDA_DISK_TARGET disk = CONTAINING_RECORD(entry, RDA_DISK_TARGET, Link);

        ObDereferenceObject(disk->Target);
        ObDereferenceObject(disk->FileObject);
        RdaFree(disk);
    }
    ExReleaseFastMutex(&g_RdaDiskListLock);
}

/* Find-or-create the cached target for DiskId. Returns a caller-referenced
 * cache entry that must be released with RdaDiskTargetRelease. */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    RdaDiskTargetAcquire(_In_ ULONG DiskId, _Out_ PRDA_DISK_TARGET *Target) {
    NTSTATUS status;
    PLIST_ENTRY entry;
    PRDA_DISK_TARGET disk = NULL;
    PRDA_OPEN_CONTEXT context = NULL;

    *Target = NULL;
    if (!g_RdaDiskListInitialized) {
        return STATUS_UNSUCCESSFUL;
    }

    ExAcquireFastMutex(&g_RdaDiskListLock);
    for (entry = g_RdaDiskListHead.Flink; entry != &g_RdaDiskListHead; entry = entry->Flink) {
        PRDA_DISK_TARGET found = CONTAINING_RECORD(entry, RDA_DISK_TARGET, Link);

        if (found->DiskId == DiskId) {
            *Target = found;
            ExReleaseFastMutex(&g_RdaDiskListLock);
            return STATUS_SUCCESS;
        }
    }

    /* Cache full: recycle the oldest entry (head). The reference had a fixed
     * 32-entry array; we evict the least recently inserted. */
    if (g_RdaDiskListHead.Flink != &g_RdaDiskListHead) {
        ULONG count = 0;

        for (entry = g_RdaDiskListHead.Flink; entry != &g_RdaDiskListHead; entry = entry->Flink) {
            count++;
        }
        if (count >= RDA_DISK_CACHE_MAX) {
            PLIST_ENTRY victim = RemoveHeadList(&g_RdaDiskListHead);
            PRDA_DISK_TARGET dead = CONTAINING_RECORD(victim, RDA_DISK_TARGET, Link);

            ObDereferenceObject(dead->Target);
            ObDereferenceObject(dead->FileObject);
            RdaFree(dead);
        }
    }
    ExReleaseFastMutex(&g_RdaDiskListLock);

    /* Resolve outside the lock (touches the object namespace). */
    context = (PRDA_OPEN_CONTEXT)RdaAllocZero(sizeof(RDA_OPEN_CONTEXT));
    if (context == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = RdaResolveDiskEpm(DiskId, context);
    if (!NT_SUCCESS(status)) {
        RdaFree(context);
        return status;
    }

    disk = (PRDA_DISK_TARGET)RdaAllocZero(sizeof(RDA_DISK_TARGET));
    if (disk == NULL) {
        ObDereferenceObject(context->TargetDevice);
        ObDereferenceObject(context->TargetFileObject);
        RdaFree(context);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    disk->DiskId = DiskId;
    disk->SectorSize = context->SectorSize;
    disk->Target = context->TargetDevice;
    disk->FileObject = context->TargetFileObject;
    RdaFree(context);

    ExAcquireFastMutex(&g_RdaDiskListLock);
    /* Re-check: another thread may have raced us for this disk id. */
    for (entry = g_RdaDiskListHead.Flink; entry != &g_RdaDiskListHead; entry = entry->Flink) {
        PRDA_DISK_TARGET found = CONTAINING_RECORD(entry, RDA_DISK_TARGET, Link);

        if (found->DiskId == DiskId) {
            ObDereferenceObject(disk->Target);
            ObDereferenceObject(disk->FileObject);
            RdaFree(disk);
            *Target = found;
            ExReleaseFastMutex(&g_RdaDiskListLock);
            return STATUS_SUCCESS;
        }
    }
    InsertTailList(&g_RdaDiskListHead, &disk->Link);
    ExReleaseFastMutex(&g_RdaDiskListLock);

    *Target = disk;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL) VOID RdaDiskTargetRelease(_In_ PRDA_DISK_TARGET Target) {
    /* Entries are cache-owned; nothing to do (documented: the cache holds the
     * references so direct/sized call sites need no pairing). */
    UNREFERENCED_PARAMETER(Target);
}

/* Sector-granular read/write against a cached disk target. Byte offset is
 * computed as LBA * probed sector size (reference FUN_00014300/FUN_000141f8). */
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    RdaDiskReadWriteSectors(_In_ PRDA_DISK_TARGET Disk, _In_ UCHAR MajorFunction,
                            _In_ PVOID SystemAddress, _In_ ULONG64 StartLba, _In_ ULONG SectorCount,
                            _Out_opt_ PULONG_PTR Information) {
    LARGE_INTEGER byteOffset;
    NTSTATUS status;
    ULONG_PTR info = 0;

    if (Information != NULL) {
        *Information = 0;
    }
    if (Disk == NULL || Disk->Target == NULL || SectorCount == 0 ||
        StartLba > (ULONG64)MAXLONGLONG / Disk->SectorSize) {
        return STATUS_INVALID_PARAMETER;
    }

    byteOffset.QuadPart = (LONGLONG)(StartLba * Disk->SectorSize);
    status = RdaSyncDiskReadWrite(Disk->Target, MajorFunction, SystemAddress,
                                  SectorCount * Disk->SectorSize, &byteOffset, &info);
    if (NT_SUCCESS(status) && Information != NULL) {
        *Information = info;
    }
    return status;
}
