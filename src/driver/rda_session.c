/*
 * rda_session.c - copy-session engine (EUDCPEPM protocol merge).
 *
 * REVERIFIED against the decompile on 2026-10-22 (see
 * docs/audit/2026-10-22-decompile-reverification.md). This file implements
 * the full reference semantics of the control-device protocol:
 *
 *   OPEN_SESSION (in >= 0x840)   - overlap guard (SHARING_VIOLATION), spb
 *                                  selection with tail rules, 0x800 bitmap
 *                                  copy, sector-size probe, writebacks at
 *                                  +0x30 (spb) and +0x83C (sector size),
 *                                  handle at +0x834, Information = 0.
 *   SESSION_OP (in >= 8)         - flush the protected file's volume: the
 *                                  path is the WCHAR string at the head of
 *                                  the 0x800 buffer (reference storage),
 *                                  IRP_MJ_FLUSH_BUFFERS <= 20 retries,
 *                                  state {0 -> 1, 0 on open fail, 3 on
 *                                  done/exhaust}, returns 0.
 *   SESSION_OP2 (in >= 0x28)     - StartBackup: requires state 3; locks the
 *                                  caller pump buffer (MDL), validates
 *                                  spb match + pump alignment, merges the
 *                                  optional user exclusion bitmap, computes
 *                                  the copy plan {start, blocks, skip bits},
 *                                  state -> 4, kicks the worker.
 *   GETNEXTBLOCK (in,out >= 0x1E)- async copy pump: the worker copies
 *                                  min(max, pump capacity, plan remaining)
 *                                  sectors from the source disk into the
 *                                  locked pump buffer, serves COW-saved
 *                                  data for externally-written ranges, and
 *                                  completes the IRP with the 0x1E record
 *                                  {+0x14 diskId, +0x18 progress %,
 *                                  +0x1C map %, +0x1D map ok} and
 *                                  Information = 0x1E.
 *   SESSION_STATUS (in >= 8)     - returns the block-map status AS the
 *                                  returned NTSTATUS.
 *   GET_PROGRESS (in >= 0xC)     - FINALIZE: state -> 5, frees the copy plan
 *                                  and unlocks the pump MDL, reports the
 *                                  final percent at buffer +8, Info = 0.
 *   CLOSE_SESSION (in >= 8)       - teardown; invalid handle -> 0xC0000008.
 *   DIRECT_READ/WRITE (out>0x10) - METHOD_OUT_DIRECT; header+data in the
 *                                  MDL'd output buffer {diskId, count, LBA};
 *                                  per-request disk resolution; Information
 *                                  = OutputBufferLength (always).
 *   SIZED_XFER/2                 - same as direct with sector size from the
 *                                  per-disk cache.
 *   MODE3/MODE4 (in >= 0x1C)     - raw paging-IO file read/write by handle
 *                                  {handle, user buffer, offset, length}.
 *   CANCEL (in >= 8)             - state := 3 (standby), kick, SUCCESS.
 *   GET_VERSION (in >= 0x84)     - 0x00010100 + product string, Info = 0.
 *   DISCOVERY (0x800C2AC0)       - {diskId of session 0's disk, Info = 4}.
 *
 * Session lifecycle: sessions are owned by the creating process
 * (IoGetCurrentProcess, referenced); the control-device CLEANUP/CLOSE sweep
 * destroys them (reference FUN_00012aa0), and filter REMOVE destroys the
 * sessions bound to the removed disk (reference FUN_0001324c).
 *
 * Deviation F12 (kept): the wire session handle is an opaque generation-
 * tagged ID, never a kernel pointer.
 *
 * Licensed under the MIT license. See LICENSE.
 */

#include "rda_p.h"

#define RDA_SESSION_MAGIC         (('R' << 24) | ('D' << 16) | ('A' << 8) | 'S')
#define RDA_SESSION_TABLE_SIZE    64
#define RDA_SESSION_KICK_CAP      301  /* reference: 0x12D */
#define RDA_SESSION_QUEUE_CAP     2000 /* reference free-pool size */
#define RDA_SESSION_FLUSH_RETRIES 20
#define RDA_SESSION_BITMAP_BYTES  0x800
#define RDA_SESSION_MAX_BLOCKS    (RDA_SESSION_BITMAP_BYTES * 8)
#define RDA_SESSION_COW_MAX_BYTES (64u * 1024 * 1024)
#define RDA_SESSION_PUMP_GUARD_MS 10000

typedef enum _RDA_PUMP_KIND {
    RdaPumpGetNextBlock = 0, /* IRP carries the 0x1E pump request */
    RdaPumpParkedWrite = 1   /* external WRITE parked while state == STANDBY */
} RDA_PUMP_KIND;

typedef struct _RDA_PUMP_NODE {
    LIST_ENTRY ListEntry;
    RDA_PUMP_KIND Kind;
    PIRP Irp;
    PDEVICE_OBJECT DeviceObject; /* parked-write origin (to forward) */
    ULONG StartSec;              /* parked-write range */
    ULONG SecCount;
} RDA_PUMP_NODE, *PRDA_PUMP_NODE;

typedef struct _RDA_COW_BLOCK {
    LIST_ENTRY ListEntry;
    ULONG64 StartSec;
    ULONG SecCount;
    /* Data follows the header (SecCount * SectorSize bytes). */
} RDA_COW_BLOCK, *PRDA_COW_BLOCK;

typedef struct _RDA_SESSION {
    /* Identity + ownership. */
    volatile LONG Magic;
    volatile LONG Active;
    volatile LONG Generation;
    PEPROCESS Owner; /* referenced; the reference compared raw IoGetCurrentProcess */

    /* Bound source disk. */
    ULONG DiskId;
    ULONG SectorSize;
    PRDA_DISK_TARGET Disk; /* cache-owned; never freed per-session */

    /* Copy geometry (OPEN_SESSION inputs, reference field map). */
    ULONG Spb;         /* sectors per block */
    ULONG TailSectors; /* tSecs & 0xF when the client left spb = 0 and tSecs >= 0x20 */
    ULONG64 DataFirstSec;
    ULONG64 TotalSecs;
    PUCHAR Bitmap; /* 0x800-byte wire bitmap copy (path head doubles as the
                      SESSION_OP protected-file path - reference storage) */

    /* Copy plan (StartBackup). */
    volatile LONG State; /* RDA_SESSION_STATE_* (spinlock-guarded) */
    KSPIN_LOCK StateLock;
    ULONG PlanStartSec;        /* absolute LBA of plan block 0 */
    ULONG PlanBlocks;          /* plan block count (spb-sized) */
    PUCHAR SkipBitmap;         /* bit per plan block: 1 = do not copy */
    PVOID PumpUserBuffer;      /* caller pump buffer user VA */
    PMDL PumpMdl;              /* locked MDL over PumpUserBuffer */
    PVOID PumpSystemVa;        /* MmGetSystemAddressForMdlSafe(PumpMdl) */
    ULONG PumpBytes;           /* pump buffer byte size */
    ULONG PlanCursorBlock;     /* next plan block for the pump */
    volatile LONG64 BytesDone; /* sectors copied */
    ULONG64 TotalPlanSecs;     /* progress denominator (sectors to copy) */
    volatile LONG MapStatus;   /* block-map status (SESSION_STATUS payload) */
    volatile LONG KickCount;   /* worker kicks, capped at 301 */
    KSEMAPHORE WorkerKick;
    KEVENT WorkerStop;

    /* COW consistency (external writes into the plan range). */
    LIST_ENTRY CowList;
    SIZE_T CowBytes;

    /* Worker. */
    PETHREAD WorkerThread; /* referenced */
    KSPIN_LOCK QueueLock;
    LIST_ENTRY PumpQueueHead;
    volatile LONG QueuedCount;
} RDA_SESSION, *PRDA_SESSION;

static RDA_SESSION g_RdaSessions[RDA_SESSION_TABLE_SIZE];
static FAST_MUTEX g_RdaSessionTableLock;

/* ---------------------------------------------------------------------------
 * Table management
 * ------------------------------------------------------------------------- */
static PRDA_SESSION RdaSessionFromHandle(_In_ ULONG64 Handle) {
    ULONG64 index = Handle >> 16;
    ULONG64 generation = Handle & 0xFFFF;
    PRDA_SESSION session;

    if (index == 0 || index > RDA_SESSION_TABLE_SIZE) {
        return NULL;
    }
    session = &g_RdaSessions[index - 1];
    if (session->Magic != RDA_SESSION_MAGIC || session->Active == 0) {
        return NULL;
    }
    if ((ULONG64)(session->Generation) != generation) {
        return NULL;
    }
    return session;
}

/* Allocates a table slot AND claims the {disk, range} under the table lock
 * so the overlap check + activation are atomic (S6). Returns STATUS of the
 * overlap pre-check via *Overlap. */
static PRDA_SESSION RdaSessionAllocate(_In_ ULONG DiskId, _In_ ULONG64 StartSec,
                                       _In_ ULONG64 LengthSecs, _Out_ PULONG64 Handle,
                                       _Out_ PBOOLEAN Overlap) {
    ULONG i;
    PRDA_SESSION session = NULL;

    *Overlap = FALSE;
    ExAcquireFastMutex(&g_RdaSessionTableLock);

    for (i = 0; i < RDA_SESSION_TABLE_SIZE; i++) {
        PRDA_SESSION s = &g_RdaSessions[i];

        if (s->Active == 0 && s->Magic == 0) {
            session = s;
            break;
        }
    }
    if (session == NULL) {
        ExReleaseFastMutex(&g_RdaSessionTableLock);
        *Handle = 0;
        return NULL;
    }

    /* Overlap pre-check over all active sessions of the same disk
     * (reference FUN_00011734: newStart < oldStart + oldLen &&
     * oldStart < newStart + newLen -> SHARING_VIOLATION). */
    for (i = 0; i < RDA_SESSION_TABLE_SIZE; i++) {
        PRDA_SESSION s = &g_RdaSessions[i];

        if (s->Active == 0 || s->Magic != RDA_SESSION_MAGIC || s->DiskId != DiskId) {
            continue;
        }
        if (StartSec < s->DataFirstSec + s->TotalSecs && s->DataFirstSec < StartSec + LengthSecs) {
            ExReleaseFastMutex(&g_RdaSessionTableLock);
            *Handle = 0;
            *Overlap = TRUE;
            return NULL;
        }
    }

    RtlZeroMemory(session, sizeof(RDA_SESSION));
    session->Active = 1;
    session->Magic = RDA_SESSION_MAGIC;
    session->Generation += 1;
    if (session->Generation <= 0) {
        session->Generation = 1;
    }
    /* Range claimed NOW so concurrent opens cannot overlap us. */
    session->DiskId = DiskId;
    session->DataFirstSec = StartSec;
    session->TotalSecs = LengthSecs;
    *Handle = ((ULONG64)(session - g_RdaSessions) + 1) << 16 | (ULONG64)(session->Generation);

    ExReleaseFastMutex(&g_RdaSessionTableLock);
    return session;
}

static VOID RdaSessionFreeSlot(_In_ PRDA_SESSION Session) {
    ExAcquireFastMutex(&g_RdaSessionTableLock);
    Session->Active = 0;
    Session->Magic = 0;
    ExReleaseFastMutex(&g_RdaSessionTableLock);
}

/* ---------------------------------------------------------------------------
 * State helpers
 * ------------------------------------------------------------------------- */
static VOID RdaSessionSetState(_In_ PRDA_SESSION Session, _In_ LONG NewState) {
    KIRQL oldIrql;

    KeAcquireSpinLock(&Session->StateLock, &oldIrql);
    Session->State = NewState;
    KeReleaseSpinLock(&Session->StateLock, oldIrql);
}

static LONG RdaSessionGetState(_In_ PRDA_SESSION Session) {
    KIRQL oldIrql;
    LONG state;

    KeAcquireSpinLock(&Session->StateLock, &oldIrql);
    state = Session->State;
    KeReleaseSpinLock(&Session->StateLock, oldIrql);
    return state;
}

static VOID RdaSessionKick(_In_ PRDA_SESSION Session) {
    if (Session->KickCount < RDA_SESSION_KICK_CAP) {
        InterlockedIncrement(&Session->KickCount);
        KeReleaseSemaphore(&Session->WorkerKick, IO_NO_INCREMENT, 1, FALSE);
    }
}

/* ---------------------------------------------------------------------------
 * COW consistency machinery
 * ------------------------------------------------------------------------- */

/* TRUE when [StartSec, +SecCount) intersects the plan range of an ACTIVE
 * (copying) session. Called from the filter WRITE path at PASSIVE. */
static BOOLEAN RdaSessionRangeNeedsCow(_In_ PRDA_SESSION Session, _In_ ULONG64 StartSec,
                                       _In_ ULONG64 SecCount) {
    ULONG64 planEnd = (ULONG64)Session->PlanStartSec + (ULONG64)Session->PlanBlocks * Session->Spb;

    if (Session->PlanBlocks == 0 || planEnd <= Session->PlanStartSec) {
        return FALSE;
    }
    return StartSec < planEnd && Session->PlanStartSec < StartSec + SecCount;
}

/* Saves the pre-image of [StartSec, +SecCount) from the source disk into the
 * session's COW list (skipping ranges already saved). Returns the final
 * status; on failure the caller fails the external write. */
static NTSTATUS RdaSessionCowSave(_In_ PRDA_SESSION Session, _In_ ULONG64 StartSec,
                                  _In_ ULONG SecCount) {
    NTSTATUS status;
    PLIST_ENTRY entry;
    PRDA_COW_BLOCK block;
    ULONG sectorBytes;
    PVOID data;

    /* Already fully covered by an existing saved block? (coarse check: the
     * first matching block covers the range). Ranges are small (one write). */
    for (entry = Session->CowList.Flink; entry != &Session->CowList; entry = entry->Flink) {
        PRDA_COW_BLOCK existing = CONTAINING_RECORD(entry, RDA_COW_BLOCK, ListEntry);

        if (existing->StartSec <= StartSec &&
            existing->StartSec + existing->SecCount >= StartSec + SecCount) {
            return STATUS_SUCCESS; /* superseded data already snapshotted */
        }
    }

    if (Session->CowBytes + (SIZE_T)SecCount * Session->SectorSize > RDA_SESSION_COW_MAX_BYTES) {
        return STATUS_INSUFFICIENT_RESOURCES; /* bounded - documented */
    }

    sectorBytes = SecCount * Session->SectorSize;
    block = (PRDA_COW_BLOCK)RdaAllocZero(sizeof(RDA_COW_BLOCK) + sectorBytes);
    if (block == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    data = (PUCHAR)block + sizeof(RDA_COW_BLOCK);

    status = RdaDiskReadWriteSectors(Session->Disk, IRP_MJ_READ, data, StartSec, SecCount, NULL);
    if (!NT_SUCCESS(status)) {
        RdaFree(block);
        return status;
    }

    block->StartSec = StartSec;
    block->SecCount = SecCount;
    InsertTailList(&Session->CowList, &block->ListEntry);
    Session->CowBytes += sectorBytes;
    return STATUS_SUCCESS;
}

/* Copies [StartSec, +SecCount) bytes into Dest from the COW list when fully
 * covered; returns FALSE when the range is not (fully) COW-saved so the
 * caller reads from the source disk instead. */
static BOOLEAN RdaSessionCowRead(_In_ PRDA_SESSION Session, _In_ ULONG64 StartSec,
                                 _In_ ULONG SecCount, _Out_ PUCHAR Dest) {
    PLIST_ENTRY entry;

    for (entry = Session->CowList.Flink; entry != &Session->CowList; entry = entry->Flink) {
        PRDA_COW_BLOCK block = CONTAINING_RECORD(entry, RDA_COW_BLOCK, ListEntry);

        if (block->StartSec <= StartSec &&
            block->StartSec + block->SecCount >= StartSec + SecCount) {
            ULONG64 skip = (StartSec - block->StartSec) * Session->SectorSize;

            RtlCopyMemory(Dest, (PUCHAR)block + sizeof(RDA_COW_BLOCK) + (SIZE_T)skip,
                          (SIZE_T)SecCount * Session->SectorSize);
            return TRUE;
        }
    }
    return FALSE;
}

/* ---------------------------------------------------------------------------
 * Worker thread
 * ------------------------------------------------------------------------- */
static VOID RdaSessionCancelPumpIrp(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

/* Search the queue for this IRP; if found, remove the node and complete the
 * IRP ourselves. S2 fix: a cancel routine ALWAYS owns completion when the
 * node is not found too (the worker dropped ownership by observing the swap
 * fail); the global cancel spinlock is released before completing. */
static VOID RdaSessionCancelPumpIrp(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
    PRDA_SESSION session = (PRDA_SESSION)Irp->Tail.Overlay.DriverContext[0];
    PRDA_PUMP_NODE node = NULL;
    PLIST_ENTRY entry;
    BOOLEAN removed = FALSE;
    KIRQL cancelIrql = Irp->CancelIrql;

    UNREFERENCED_PARAMETER(DeviceObject);

    /* The IO manager holds the global cancel spinlock when it calls us and
     * has already swapped our routine pointer to NULL; drop the spinlock
     * before touching the queue (S2). */
    IoReleaseCancelSpinLock(cancelIrql);

    if (session == NULL) {
        Irp->IoStatus.Status = STATUS_CANCELLED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return;
    }

    KeAcquireSpinLockAtDpcLevel(&session->QueueLock);
    for (entry = session->PumpQueueHead.Flink; entry != &session->PumpQueueHead;
         entry = entry->Flink) {
        PRDA_PUMP_NODE candidate = CONTAINING_RECORD(entry, RDA_PUMP_NODE, ListEntry);

        if (candidate->Irp == Irp) {
            RemoveEntryList(entry);
            node = candidate;
            removed = TRUE;
            break;
        }
    }
    KeReleaseSpinLockFromDpcLevel(&session->QueueLock);

    if (node != NULL) {
        InterlockedDecrement(&session->QueuedCount);
        RdaFree(node);
    }
    /* Complete on BOTH paths: once the cancel routine has been invoked it
     * owns the IRP - the worker delegated completion to us when its cancel
     * swap came back NULL (S2 ownership contract). */
    Irp->IoStatus.Status = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    UNREFERENCED_PARAMETER(removed);
}

/* Dequeue one node under the lock; claims completion ownership by clearing
 * the cancel routine. Returns FALSE when the queue is empty. */
static BOOLEAN RdaSessionDequeue(_In_ PRDA_SESSION Session, _Out_ PRDA_PUMP_NODE *Node,
                                 _Out_ PIRP *Irp) {
    KIRQL oldIrql;

    *Node = NULL;
    *Irp = NULL;

    KeAcquireSpinLock(&Session->QueueLock, &oldIrql);
    if (!IsListEmpty(&Session->PumpQueueHead)) {
        PLIST_ENTRY entry = RemoveHeadList(&Session->PumpQueueHead);
        PRDA_PUMP_NODE node = CONTAINING_RECORD(entry, RDA_PUMP_NODE, ListEntry);
        PIRP irp = node->Irp;

        if (IoSetCancelRoutine(irp, NULL) == NULL) {
            /* Cancel path owns completion; drop the node silently. */
            RdaFree(node);
        } else {
            *Node = node;
            *Irp = irp;
        }
        InterlockedDecrement(&Session->QueuedCount);
        KeReleaseSpinLock(&Session->QueueLock, oldIrql);
        return *Node != NULL;
    }
    KeReleaseSpinLock(&Session->QueueLock, oldIrql);
    return FALSE;
}

/* Process one GETNEXTBLOCK request (reference FUN_00017620 semantics). */
static NTSTATUS RdaSessionPumpBlock(_In_ PRDA_SESSION Session, _In_ PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    PRDA_GETNEXTBLOCK wire = (PRDA_GETNEXTBLOCK)buffer;
    ULONG64 cursor;
    ULONG maxSec;
    ULONG doSec;
    ULONG64 remaining;
    NTSTATUS status;
    PUCHAR dest;
    ULONG i;

    if (buffer == NULL ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < RDA_SESSION_GETNEXTBLOCK_MIN_OUT) {
        return STATUS_INVALID_PARAMETER;
    }

    cursor = wire->CursorSec;
    maxSec = wire->MaxSec;

    /* No active plan (pre-StartBackup or finalized): reference returns
     * 0xC0000120 with the progress fields filled. */
    if (Session->PlanBlocks == 0 || Session->PumpSystemVa == NULL) {
        wire->DiskId = Session->DiskId;
        wire->Progress = Session->TotalPlanSecs != 0
                             ? (UINT32)((ULONG64)Session->BytesDone * 100 / Session->TotalPlanSecs)
                             : 0;
        wire->MapProgress = 100;
        wire->MapOk = (Session->MapStatus >= 0) ? 1 : 0;
        return ((NTSTATUS)0xC0000120); /* reference literal (no friendly name used) */
    }

    /* Clip to the plan. */
    {
        ULONG64 planEnd =
            (ULONG64)Session->PlanStartSec + (ULONG64)Session->PlanBlocks * Session->Spb;

        if (cursor < Session->PlanStartSec) {
            cursor = Session->PlanStartSec;
        }
        if (cursor >= planEnd) {
            cursor = planEnd;
            remaining = 0;
        } else {
            remaining = planEnd - cursor;
        }
    }

    /* Skip plan blocks whose skip-bit is set (advance the cursor over whole
     * blocks, reference gap-skipping semantics). */
    while (remaining != 0) {
        ULONG64 block = (cursor - Session->PlanStartSec) / Session->Spb;
        ULONG64 blockStart = Session->PlanStartSec + block * Session->Spb;
        ULONG64 step;
        ULONG bitIdx = (ULONG)block;

        if (bitIdx >= Session->PlanBlocks) {
            break;
        }
        if ((Session->SkipBitmap[bitIdx / 8] & (1U << (bitIdx % 8))) == 0) {
            break; /* this block is selected for copying */
        }
        step = blockStart + Session->Spb - cursor; /* advance to next block */
        if (step > remaining) {
            step = remaining;
        }
        cursor += step;
        remaining -= step;
    }

    if (remaining == 0) {
        /* Stream complete: reference completes with success and a
         * fully-progressed record. */
        Session->BytesDone = (LONG64)Session->TotalPlanSecs;
        wire->DiskId = Session->DiskId;
        wire->Progress = 100;
        wire->MapProgress = 100;
        wire->MapOk = (Session->MapStatus >= 0) ? 1 : 0;
        return STATUS_SUCCESS;
    }

    doSec = maxSec;
    if ((ULONG64)doSec > remaining) {
        doSec = (ULONG)remaining;
    }
    if (Session->PumpBytes != 0 &&
        (ULONG64)doSec > (ULONG64)(Session->PumpBytes / Session->SectorSize)) {
        doSec = Session->PumpBytes / Session->SectorSize;
    }
    if (doSec == 0) {
        wire->DiskId = Session->DiskId;
        wire->Progress = Session->TotalPlanSecs != 0
                             ? (UINT32)((ULONG64)Session->BytesDone * 100 / Session->TotalPlanSecs)
                             : 0;
        wire->MapProgress = 100;
        wire->MapOk = (Session->MapStatus >= 0) ? 1 : 0;
        return STATUS_SUCCESS;
    }

    dest = (PUCHAR)Session->PumpSystemVa;
    for (i = 0; i < doSec; i += Session->Spb) {
        ULONG chunk = Session->Spb;

        if (chunk > doSec - i) {
            chunk = doSec - i;
        }

        if (RdaSessionCowRead(Session, cursor, chunk, dest)) {
            status = STATUS_SUCCESS;
        } else {
            status = RdaDiskReadWriteSectors(Session->Disk, IRP_MJ_READ, dest, cursor, chunk, NULL);
        }
        if (!NT_SUCCESS(status)) {
            Session->MapStatus = (LONG)status;
            wire->DiskId = Session->DiskId;
            wire->Progress =
                Session->TotalPlanSecs != 0
                    ? (UINT32)((ULONG64)Session->BytesDone * 100 / Session->TotalPlanSecs)
                    : 0;
            wire->MapProgress = 0;
            wire->MapOk = 0;
            return status;
        }
        dest += (SIZE_T)chunk * Session->SectorSize;
        cursor += chunk;
        Session->BytesDone += (LONG64)chunk;
    }

    wire->DiskId = Session->DiskId;
    wire->Progress = Session->TotalPlanSecs != 0
                         ? (UINT32)((ULONG64)Session->BytesDone * 100 / Session->TotalPlanSecs)
                         : 0;
    wire->MapProgress = 100;
    wire->MapOk = (Session->MapStatus >= 0) ? 1 : 0;
    return STATUS_SUCCESS;
}

static VOID RdaSessionWorker(_In_ PVOID StartContext) {
    PRDA_SESSION session = (PRDA_SESSION)StartContext;

    for (;;) {
        NTSTATUS waitStatus;
        PVOID waitObjects[2];
        LARGE_INTEGER timeout;

        timeout.QuadPart = -(LONGLONG)RDA_SESSION_PUMP_GUARD_MS * 10000;
        waitObjects[0] = (PVOID)&session->WorkerStop;
        waitObjects[1] = (PVOID)&session->WorkerKick;
        waitStatus = KeWaitForMultipleObjects(2, waitObjects, WaitAny, Executive, KernelMode, FALSE,
                                              &timeout, NULL);
        if (waitStatus == STATUS_WAIT_0) {
            break; /* stop requested (finalize/close/unload) */
        }

        for (;;) {
            PRDA_PUMP_NODE node;
            PIRP irp;

            if (!RdaSessionDequeue(session, &node, &irp)) {
                break;
            }

            if (node->Kind == RdaPumpParkedWrite) {
                /* Parked external write: forward it down the filter stack
                 * (the reference forwards once the session left standby).
                 * node->DeviceObject is the LOWER device captured at park
                 * time - calling our own DO would re-enter the dispatch. */
                IoSkipCurrentIrpStackLocation(irp);
                IoCallDriver(node->DeviceObject, irp);
                RdaFree(node);
                continue;
            }

            {
                NTSTATUS status = RdaSessionPumpBlock(session, irp);

                irp->IoStatus.Status = status;
                irp->IoStatus.Information = RDA_SESSION_GETNEXTBLOCK_INFO; /* 0x1E constant */
                IoCompleteRequest(irp, IO_NO_INCREMENT);
                RdaFree(node);
            }
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

/* ---------------------------------------------------------------------------
 * Session teardown
 * ------------------------------------------------------------------------- */
static VOID RdaSessionCloseWorker(_In_ PRDA_SESSION Session) {
    PETHREAD thread = Session->WorkerThread;

    if (thread != NULL) {
        KeSetEvent(&Session->WorkerStop, IO_NO_INCREMENT, FALSE);
        KeReleaseSemaphore(&Session->WorkerKick, IO_NO_INCREMENT, 1, FALSE);
        KeWaitForSingleObject(thread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(thread);
        Session->WorkerThread = NULL;
    }
}

/* Drain every queued node: pump IRPs complete CANCELLED (or the reference's
 * 0xC0000120 when a plan exists), parked writes are forwarded down. */
static VOID RdaSessionDrainQueue(_In_ PRDA_SESSION Session, _In_ NTSTATUS PumpStatus) {
    for (;;) {
        KIRQL oldIrql;
        PRDA_PUMP_NODE node = NULL;
        PIRP irp = NULL;

        KeAcquireSpinLock(&Session->QueueLock, &oldIrql);
        if (!IsListEmpty(&Session->PumpQueueHead)) {
            PLIST_ENTRY entry = RemoveHeadList(&Session->PumpQueueHead);

            node = CONTAINING_RECORD(entry, RDA_PUMP_NODE, ListEntry);
            irp = node->Irp;
            InterlockedDecrement(&Session->QueuedCount);
        }
        KeReleaseSpinLock(&Session->QueueLock, oldIrql);

        if (node == NULL) {
            break;
        }
        if (IoSetCancelRoutine(irp, NULL) != NULL) {
            /* Teardown never forwards parked writes - the stack below may
             * already be detaching (filter REMOVE kills the session); the
             * reference worker exits and the pending writes die with it. */
            if (node->Kind == RdaPumpParkedWrite) {
                irp->IoStatus.Status = STATUS_DELETE_PENDING;
                irp->IoStatus.Information = 0;
            } else {
                irp->IoStatus.Status = PumpStatus;
                irp->IoStatus.Information = 0;
            }
            IoCompleteRequest(irp, IO_NO_INCREMENT);
        }
        /* Else: the cancel routine owns completion (S2 contract). */
        RdaFree(node);
    }
}

static VOID RdaSessionFreePlan(_In_ PRDA_SESSION Session) {
    if (Session->PumpMdl != NULL) {
        if (Session->PumpSystemVa != NULL) {
            MmUnmapLockedPages(Session->PumpSystemVa, Session->PumpMdl);
        }
        MmUnlockPages(Session->PumpMdl);
        IoFreeMdl(Session->PumpMdl);
        Session->PumpMdl = NULL;
        Session->PumpSystemVa = NULL;
        Session->PumpUserBuffer = NULL;
        Session->PumpBytes = 0;
    }
    if (Session->SkipBitmap != NULL) {
        RdaFree(Session->SkipBitmap);
        Session->SkipBitmap = NULL;
    }
    Session->PlanBlocks = 0;
    Session->PlanStartSec = 0;
}

static VOID RdaSessionFreeCow(_In_ PRDA_SESSION Session) {
    while (!IsListEmpty(&Session->CowList)) {
        PLIST_ENTRY entry = RemoveHeadList(&Session->CowList);
        PRDA_COW_BLOCK block = CONTAINING_RECORD(entry, RDA_COW_BLOCK, ListEntry);

        RdaFree(block);
    }
    Session->CowBytes = 0;
}

static VOID RdaSessionDestroy(_In_ PRDA_SESSION Session) {
    /* Unlink semantics are enforced by Active=0 under the table lock; the
     * range stays claimed until the slot is reused. */
    RdaSessionSetState(Session, RDA_SESSION_STATE_DONE);

    RdaSessionDrainQueue(Session, STATUS_CANCELLED);
    RdaSessionCloseWorker(Session);
    RdaSessionFreePlan(Session);
    RdaSessionFreeCow(Session);

    if (Session->Owner != NULL) {
        ObDereferenceObject(Session->Owner);
        Session->Owner = NULL;
    }
    if (Session->Bitmap != NULL) {
        RdaFree(Session->Bitmap);
        Session->Bitmap = NULL;
    }
    RdaSessionFreeSlot(Session);
}

/* ---------------------------------------------------------------------------
 * Command handlers
 * ------------------------------------------------------------------------- */
static NTSTATUS RdaSessionOpen(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack) {
    PRDA_OPEN_SESSION in = (PRDA_OPEN_SESSION)Irp->AssociatedIrp.SystemBuffer;
    ULONG inLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    NTSTATUS status;
    PRDA_SESSION session;
    ULONG64 handle = 0;
    BOOLEAN overlap;
    PRDA_DISK_TARGET disk = NULL;
    HANDLE threadHandle = NULL;
    PETHREAD thread = NULL;
    SIZE_T bitmapBytes;

    /* Reference gate: InputBufferLength >= 0x840 (FUN_000120f8 branch). */
    if (in == NULL || inLength < RDA_SESSION_STRUCT_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (in->TotalSecs == 0 || in->BitmapSize == 0 || in->BitmapCount == 0) {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    session = RdaSessionAllocate(in->DiskId, in->DataFirstSec, in->TotalSecs, &handle, &overlap);
    if (session == NULL) {
        return overlap ? STATUS_SHARING_VIOLATION : STATUS_INSUFFICIENT_RESOURCES;
    }

    status = RdaDiskTargetAcquire(in->DiskId, &disk);
    if (!NT_SUCCESS(status)) {
        RdaSessionFreeSlot(session);
        return status;
    }

    session->SectorSize = disk->SectorSize;
    session->Disk = disk; /* cache-owned */
    session->State = RDA_SESSION_STATE_CREATED;
    KeInitializeSpinLock(&session->StateLock);
    KeInitializeSpinLock(&session->QueueLock);
    InitializeListHead(&session->PumpQueueHead);
    InitializeListHead(&session->CowList);
    KeInitializeEvent(&session->WorkerStop, NotificationEvent, FALSE);
    KeInitializeSemaphore(&session->WorkerKick, 0, 0x7FFFFFFF);

    /* Owner reference (the reference compared raw IoGetCurrentProcess
     * pointers; we keep a formal reference to make the sweep race-free). */
    session->Owner = PsGetCurrentProcess();
    if (session->Owner != NULL) {
        ObfReferenceObject(session->Owner);
    }

    /* spb selection + tail rules (reference ctor, G13): tail is computed
     * ONLY when the client passed spb == 0 and tSecs >= 0x20. */
    session->Spb = in->SpbInOut;
    if (session->Spb == 0) {
        if (in->TotalSecs < 0x20) {
            session->Spb = 1;
            session->TailSectors = 0;
        } else {
            session->Spb = 0x10;
            session->TailSectors = (ULONG)(in->TotalSecs & 0xF);
        }
    } else {
        session->TailSectors = 0;
    }

    /* 0x800-byte wire bitmap copy (NUL pad at 0x7FE - the buffer head doubles
     * as the SESSION_OP protected-file path, exactly like the reference). */
    bitmapBytes = in->BitmapSize;
    if (bitmapBytes > RDA_SESSION_BITMAP_BYTES) {
        bitmapBytes = RDA_SESSION_BITMAP_BYTES;
    }
    session->Bitmap = (PUCHAR)RdaAllocZero(RDA_SESSION_BITMAP_BYTES);
    if (session->Bitmap == NULL) {
        ObDereferenceObject(session->Owner);
        session->Owner = NULL;
        RdaSessionFreeSlot(session);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(session->Bitmap, in->BlockBitmap, bitmapBytes);
    session->Bitmap[0x7FE] = 0;
    session->Bitmap[0x7FF] = 0;

    status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL,
                                  RdaSessionWorker, session);
    if (NT_SUCCESS(status)) {
        status = ObReferenceObjectByHandle(threadHandle, 0, *PsThreadType, KernelMode,
                                           (PVOID *)&thread, NULL);
        ZwClose(threadHandle);
    }
    if (!NT_SUCCESS(status)) {
        RdaFree(session->Bitmap);
        session->Bitmap = NULL;
        ObDereferenceObject(session->Owner);
        session->Owner = NULL;
        RdaSessionFreeSlot(session);
        return status;
    }
    session->WorkerThread = thread;

    /* Outputs (reference ctor writebacks): handle at +0x834, effective spb
     * at +0x30, sector size at +0x83C. Information = 0 (G14). */
    in->SessionHandle = handle;
    in->SpbInOut = session->Spb;
    in->SectorSize = session->SectorSize;
    Irp->IoStatus.Information = 0;

    RDA_TRACE(RDA_LEVEL_INFO, "OpenSession: disk=%u first=%llu secs=%llu spb=%u ss=%u", in->DiskId,
              in->DataFirstSec, in->TotalSecs, session->Spb, session->SectorSize);
    return STATUS_SUCCESS;
}

/* SESSION_OP: flush the protected file's volume (reference FUN_0001590c). */
static NTSTATUS RdaSessionFlushProtectedFile(_In_ PRDA_SESSION Session) {
    NTSTATUS status;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK iosb;
    HANDLE fileHandle = NULL;
    PFILE_OBJECT fileObject = NULL;
    PDEVICE_OBJECT device = NULL;
    UNICODE_STRING path;
    WCHAR pathBuffer[260];
    int attempt;
    LONG state;

    /* Path = NUL-terminated WCHAR string at the head of the 0x800 bitmap
     * buffer (the reference's storage slot). Empty -> open fails -> state 0
     * and the command still returns 0, mirroring the reference. */
    RtlZeroMemory(pathBuffer, sizeof(pathBuffer));
    {
        SIZE_T i = 0;

        while (i + 1 < 260 && ((PWCHAR)Session->Bitmap)[i] != UNICODE_NULL) {
            pathBuffer[i] = ((PWCHAR)Session->Bitmap)[i];
            i++;
        }
    }
    RtlInitUnicodeString(&path, pathBuffer);

    state = RdaSessionGetState(Session);
    if (state == RDA_SESSION_STATE_FLUSHING) {
        return STATUS_SUCCESS; /* already in progress (reentrant call) */
    }

    if (path.Length != 0) {
        InitializeObjectAttributes(&attributes, &path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                                   NULL, NULL);
        status = ZwCreateFile(&fileHandle, FILE_READ_DATA | SYNCHRONIZE, &attributes, &iosb, NULL,
                              FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                              FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
        if (NT_SUCCESS(status)) {
            status = ObReferenceObjectByHandle(fileHandle, 0, *IoFileObjectType, KernelMode,
                                               (PVOID *)&fileObject, NULL);
            ZwClose(fileHandle);
        }
        if (NT_SUCCESS(status)) {
            device = IoGetRelatedDeviceObject(fileObject);
        }
    } else {
        status = STATUS_OBJECT_NAME_NOT_FOUND;
    }

    if (!NT_SUCCESS(status)) {
        if (fileObject != NULL) {
            ObDereferenceObject(fileObject);
        }
        RdaSessionSetState(Session, RDA_SESSION_STATE_CREATED);
        return STATUS_SUCCESS; /* reference returns 0 on open failure */
    }

    RdaSessionSetState(Session, RDA_SESSION_STATE_FLUSHING);

    /* IRP_MJ_FLUSH_BUFFERS against the file's volume stack, <= 20 retries
     * (reference loop), tolerating PENDING-class results. */
    for (attempt = 0; attempt < RDA_SESSION_FLUSH_RETRIES; attempt++) {
        PIRP irp;
        KEVENT event;
        IO_STATUS_BLOCK flushIosb;

        state = RdaSessionGetState(Session);
        if (state == RDA_SESSION_STATE_STANDBY || state == RDA_SESSION_STATE_DONE) {
            break;
        }

        KeInitializeEvent(&event, NotificationEvent, FALSE);
        irp = IoBuildSynchronousFsdRequest(IRP_MJ_FLUSH_BUFFERS, device, NULL, 0, NULL, &event,
                                           &flushIosb);
        if (irp == NULL) {
            break;
        }
        /* Inject the file object into the CURRENT (built) stack location -
         * the reference rewrote an ioctl IRP's next slot for the same
         * effect; the FSD needs the stream identity. */
        IoGetCurrentIrpStackLocation(irp)->FileObject = fileObject;
        status = IoCallDriver(device, irp);
        if (status == STATUS_PENDING) {
            KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
            status = flushIosb.Status;
        }
        if (status == STATUS_PENDING) {
            status = STATUS_SUCCESS; /* reference maps 0xC0000010 to 0 */
        }
        if (!NT_SUCCESS(status)) {
            break;
        }
    }

    ObDereferenceObject(fileObject);

    /* Retry-exhaust / completion -> standby (state 3, reference semantics). */
    RdaSessionSetState(Session, RDA_SESSION_STATE_STANDBY);
    RdaSessionKick(Session);
    return STATUS_SUCCESS;
}

/* SESSION_OP2: StartBackup (reference FUN_0001601c). */
static NTSTATUS RdaSessionStartBackup(_In_ PRDA_SESSION Session, _In_ PIRP Irp,
                                      _In_ PIO_STACK_LOCATION Stack) {
    PRDA_STARTBACKUP_IN in = (PRDA_STARTBACKUP_IN)Irp->AssociatedIrp.SystemBuffer;
    ULONG inLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    LONG state;
    ULONG64 planSectors;
    SIZE_T skipBytes;
    ULONG i;
    ULONG setBits = 0;

    if (in == NULL || inLength < RDA_SESSION_STARTBACKUP_MIN_IN) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Reset progress. */
    Session->BytesDone = 0;

    state = RdaSessionGetState(Session);
    if (state != RDA_SESSION_STATE_STANDBY) {
        return STATUS_UNSUCCESSFUL; /* reference: 0xC0000001 unless state==3 */
    }

    if (in->UserBitmap != NULL && in->Spb != Session->Spb) {
        return STATUS_INVALID_PARAMETER;
    }

    if (in->PumpBytes != 0 && in->PumpBytes % (Session->Spb * Session->SectorSize) != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Tear down any previous plan (the reference frees + rebuilds). */
    RdaSessionFreePlan(Session);

    /* Build the copy plan. */
    Session->PlanStartSec = (ULONG)in->StartSec;
    Session->PlanBlocks = in->BlockCount;
    Session->PlanCursorBlock = 0;

    skipBytes = ((SIZE_T)in->BlockCount + 7) / 8;
    if (skipBytes == 0) {
        skipBytes = 1;
    }
    Session->SkipBitmap = (PUCHAR)RdaAllocZero(skipBytes);
    if (Session->SkipBitmap == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (in->UserBitmap != NULL) {
        /* Probe + merge the caller's bitmap as exclusions (the reference
         * inverts: skip = ~(user) & ~(existing)). We copy the caller bits
         * verbatim into the skip map (1 = skip). */
        try {
            ProbeForRead(in->UserBitmap, skipBytes, 1);
            RtlCopyMemory(Session->SkipBitmap, in->UserBitmap, skipBytes);
        }
        except(EXCEPTION_EXECUTE_HANDLER) {
            RdaSessionFreePlan(Session);
            return GetExceptionCode();
        }
    }

    /* Lock the caller pump buffer (destination of pumped data). */
    if (in->PumpBuffer != NULL && in->PumpBytes != 0) {
        Session->PumpMdl = IoAllocateMdl(in->PumpBuffer, in->PumpBytes, FALSE, FALSE, NULL);
        if (Session->PumpMdl == NULL) {
            RdaSessionFreePlan(Session);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        try {
            MmProbeAndLockPages(Session->PumpMdl, UserMode, IoWriteAccess);
        }
        except(EXCEPTION_EXECUTE_HANDLER) {
            IoFreeMdl(Session->PumpMdl);
            Session->PumpMdl = NULL;
            RdaSessionFreePlan(Session);
            return GetExceptionCode();
        }
        Session->PumpSystemVa = MmGetSystemAddressForMdlSafe(Session->PumpMdl, NormalPagePriority);
        if (Session->PumpSystemVa == NULL) {
            MmUnlockPages(Session->PumpMdl);
            IoFreeMdl(Session->PumpMdl);
            Session->PumpMdl = NULL;
            RdaSessionFreePlan(Session);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        Session->PumpUserBuffer = in->PumpBuffer;
        Session->PumpBytes = in->PumpBytes;
    }

    /* Progress denominator: plan sectors that are NOT skipped. */
    for (i = 0; i < Session->PlanBlocks; i++) {
        if ((Session->SkipBitmap[i / 8] & (1U << (i % 8))) == 0) {
            setBits++;
        }
    }
    planSectors = (ULONG64)setBits * Session->Spb;
    if (planSectors == 0) {
        RdaSessionFreePlan(Session);
        return STATUS_INVALID_PARAMETER;
    }
    Session->TotalPlanSecs = planSectors;
    Session->MapStatus = STATUS_SUCCESS;

    RdaSessionSetState(Session, RDA_SESSION_STATE_COPYING);
    RdaSessionKick(Session);

    RDA_TRACE(RDA_LEVEL_INFO, "StartBackup: start=%u blocks=%u spb=%u pumpBytes=%u planSecs=%llu",
              Session->PlanStartSec, Session->PlanBlocks, Session->Spb, Session->PumpBytes,
              planSectors);
    return STATUS_SUCCESS;
}

/* GET_PROGRESS: finalize + report (reference FUN_00016490 with query). */
static NTSTATUS RdaSessionFinalize(_In_ PRDA_SESSION Session, _In_ PIRP Irp,
                                   _In_ PIO_STACK_LOCATION Stack) {
    ULONG inLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG percent;

    if (inLength < RDA_SESSION_PROGRESS_MIN_IN) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RdaSessionSetState(Session, RDA_SESSION_STATE_DONE);

    /* Wake the worker so it exits its wait and observes the state, then
     * drain: queued pump IRPs see the freed plan and complete with the
     * reference's 0xC0000120. */
    RdaSessionKick(Session);
    RdaSessionDrainQueue(Session, (NTSTATUS)0xC0000120);
    RdaSessionFreePlan(Session);
    RdaSessionFreeCow(Session);

    percent = Session->TotalPlanSecs != 0
                  ? (ULONG)((ULONG64)Session->BytesDone * 100 / Session->TotalPlanSecs)
                  : 0;
    if (buffer != NULL) {
        *(PULONG)((PUCHAR)buffer + 8) = percent;
    }
    Irp->IoStatus.Information = 0;
    return STATUS_SUCCESS;
}

/* Direct/sized sector IO (reference FUN_000120f8 direct branches):
 * METHOD_OUT_DIRECT - the 0x10-byte header and the data both live in the
 * IRP's MDL'd output buffer. Offsets are LBA sector numbers. Information is
 * ALWAYS the OutputBufferLength. */
static NTSTATUS RdaSessionDirectIo(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack,
                                   _In_ BOOLEAN IsWrite, _In_ BOOLEAN UseProbeCache) {
    NTSTATUS status;
    ULONG outLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    PRDA_DISK_TARGET disk = NULL;
    PUCHAR mdl;
    ULONG diskId;
    ULONG sectorCount;
    ULONG64 startLba;
    ULONG bytes;
    ULONG_PTR info = 0;
    NTSTATUS ioStatus;

    if (Irp->MdlAddress == NULL || outLength <= RDA_SESSION_DIRECT_MIN_OUT - 1) {
        return STATUS_BUFFER_TOO_SMALL; /* reference: out > 0x10 */
    }

    mdl = (PUCHAR)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
    if (mdl == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    diskId = *(PULONG)(mdl + 0x00);
    sectorCount = *(PULONG)(mdl + 0x04);
    startLba = *(PULONG64)(mdl + 0x08);

    status = RdaDiskTargetAcquire(diskId, &disk);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    bytes = sectorCount * disk->SectorSize;
    if (bytes == 0) {
        RdaDiskTargetRelease(disk);
        return STATUS_INVALID_PARAMETER;
    }
    if ((SIZE_T)bytes + 0x10 > (SIZE_T)outLength) {
        RdaDiskTargetRelease(disk);
        return STATUS_BUFFER_TOO_SMALL;
    }

    ioStatus = RdaDiskReadWriteSectors(disk, IsWrite ? IRP_MJ_WRITE : IRP_MJ_READ, mdl + 0x10,
                                       startLba, sectorCount, &info);
    RdaDiskTargetRelease(disk);

    UNREFERENCED_PARAMETER(UseProbeCache); /* cache is always probed */
    Irp->IoStatus.Information = outLength; /* reference semantics (G20) */
    return ioStatus;
}

/* MODE3/MODE4: raw paging-IO file read/write by handle (reference
 * FUN_00013fe4). */
static NTSTATUS RdaSessionFileIo(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack,
                                 _In_ UCHAR MajorFunction) {
    PRDA_FILEIO_IN in = (PRDA_FILEIO_IN)Irp->AssociatedIrp.SystemBuffer;
    ULONG inLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    NTSTATUS status;
    PFILE_OBJECT fileObject = NULL;
    PDEVICE_OBJECT device;
    PIRP irp;
    KEVENT event;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offset;

    if (in == NULL || inLength < RDA_SESSION_FILEIO_MIN_IN) {
        return STATUS_INVALID_PARAMETER;
    }

    status = ObReferenceObjectByHandle(in->FileHandle, 0, *IoFileObjectType, UserMode,
                                       (PVOID *)&fileObject, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    device = IoGetRelatedDeviceObject(fileObject);
    offset.QuadPart = (LONGLONG)in->ByteOffset;

    KeInitializeEvent(&event, NotificationEvent, FALSE);
    RtlZeroMemory(&iosb, sizeof(iosb));
    irp = IoBuildSynchronousFsdRequest(MajorFunction, device, in->Buffer, in->Length, &offset,
                                       &event, &iosb);
    if (irp == NULL) {
        ObDereferenceObject(fileObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Paging-IO semantics with the caller's file object (reference stack
     * edits: FileObject := file, paging IO flag bits). The built request's
     * CURRENT location is the one the FSD consumes. */
    IoGetCurrentIrpStackLocation(irp)->FileObject = fileObject;
    irp->Flags |= IRP_PAGING_IO;

    status = IoCallDriver(device, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    }
    ObDereferenceObject(fileObject);

    if (NT_SUCCESS(status)) {
        Irp->IoStatus.Information = sizeof(ULONG64); /* reference: 8 */
    }
    return status;
}

/* CANCEL: state := 3 (standby) + kick (reference 0x800C2B38 branch). */
static VOID RdaSessionCancelCommand(_In_ PRDA_SESSION Session) {
    RdaSessionSetState(Session, RDA_SESSION_STATE_STANDBY);
    RdaSessionKick(Session);
}

/* ---------------------------------------------------------------------------
 * Engine lifecycle
 * ------------------------------------------------------------------------- */
VOID RdaSessionInit(VOID) {
    RtlZeroMemory(g_RdaSessions, sizeof(g_RdaSessions));
    ExInitializeFastMutex(&g_RdaSessionTableLock);
}

VOID RdaSessionShutdown(VOID) {
    ULONG i;

    for (i = 0; i < RDA_SESSION_TABLE_SIZE; i++) {
        PRDA_SESSION session = &g_RdaSessions[i];

        if (session->Active != 0 && session->Magic == RDA_SESSION_MAGIC) {
            RdaSessionDestroy(session);
        }
    }
}

VOID RdaSessionSweepByProcess(_In_ PEPROCESS Process) {
    ULONG i;

    ExAcquireFastMutex(&g_RdaSessionTableLock);
    for (i = 0; i < RDA_SESSION_TABLE_SIZE; i++) {
        PRDA_SESSION session = &g_RdaSessions[i];

        if (session->Active != 0 && session->Magic == RDA_SESSION_MAGIC &&
            session->Owner == Process) {
            ExReleaseFastMutex(&g_RdaSessionTableLock);
            RdaSessionDestroy(session);
            ExAcquireFastMutex(&g_RdaSessionTableLock);
        }
    }
    ExReleaseFastMutex(&g_RdaSessionTableLock);
}

VOID RdaSessionKillByDisk(_In_ ULONG DiskId) {
    ULONG i;

    ExAcquireFastMutex(&g_RdaSessionTableLock);
    for (i = 0; i < RDA_SESSION_TABLE_SIZE; i++) {
        PRDA_SESSION session = &g_RdaSessions[i];

        if (session->Active != 0 && session->Magic == RDA_SESSION_MAGIC &&
            session->DiskId == DiskId) {
            ExReleaseFastMutex(&g_RdaSessionTableLock);
            RdaSessionDestroy(session);
            ExAcquireFastMutex(&g_RdaSessionTableLock);
        }
    }
    ExReleaseFastMutex(&g_RdaSessionTableLock);
}

BOOLEAN RdaSessionActiveOnDisk(_In_ ULONG DiskId) {
    ULONG i;
    BOOLEAN active = FALSE;

    if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
        return FALSE;
    }

    ExAcquireFastMutex(&g_RdaSessionTableLock);
    for (i = 0; i < RDA_SESSION_TABLE_SIZE && !active; i++) {
        PRDA_SESSION session = &g_RdaSessions[i];

        if (session->Active == 0 || session->Magic != RDA_SESSION_MAGIC ||
            session->DiskId != DiskId) {
            continue;
        }
        /* Reference TRIM-eat condition: state == 3 OR (dest + map ok). */
        if (session->State == RDA_SESSION_STATE_STANDBY ||
            (session->PumpSystemVa != NULL && session->MapStatus >= 0)) {
            active = TRUE;
        }
    }
    ExReleaseFastMutex(&g_RdaSessionTableLock);
    return active;
}

/*
 * RdaSessionInterceptWrite - filter WRITE path coordination
 * (reference FUN_0001189c/FUN_00011a00/FUN_0001573c/FUN_000167f4).
 *
 * Semantics (reference net effect):
 *   - STANDBY (state 3) session on this disk: the write is PARKED - queued
 *     async and forwarded down the filter stack once the session leaves the
 *     standby state (StartBackup/Cancel/finalize wake the worker).
 *   - COPYING (state 4) session whose plan covers the write range: the
 *     original sectors are COW-saved FIRST (snapshot consistency), then the
 *     write returns Forward so the caller forwards it synchronously.
 *   - COW save failure: Blocked - the caller completes the IRP with
 *     STATUS_INSUFFICIENT_RESOURCES (bounded snapshot memory, documented).
 *   - No session / no coverage: Forward.
 */
RDA_WRITE_INTERCEPT RdaSessionInterceptWrite(_In_ ULONG DiskId, _In_ PIRP Irp,
                                             _In_ PDEVICE_OBJECT LowerDeviceObject,
                                             _In_ ULONG64 StartSec, _In_ ULONG SecCount) {
    ULONG i;
    PRDA_SESSION target = NULL;
    PRDA_PUMP_NODE node;
    LONG state;

    ExAcquireFastMutex(&g_RdaSessionTableLock);
    for (i = 0; i < RDA_SESSION_TABLE_SIZE; i++) {
        PRDA_SESSION session = &g_RdaSessions[i];

        if (session->Active != 0 && session->Magic == RDA_SESSION_MAGIC &&
            session->DiskId == DiskId) {
            target = session;
            break;
        }
    }
    ExReleaseFastMutex(&g_RdaSessionTableLock);

    if (target == NULL) {
        return RdaWriteForward;
    }

    state = RdaSessionGetState(target);
    if (state == RDA_SESSION_STATE_STANDBY) {
        /* Park: the worker forwards it through LowerDeviceObject after the
         * session leaves standby. */
        node = (PRDA_PUMP_NODE)RdaAllocZero(sizeof(RDA_PUMP_NODE));
        if (node == NULL) {
            return RdaWriteBlocked;
        }
        node->Kind = RdaPumpParkedWrite;
        node->Irp = Irp;
        node->DeviceObject = LowerDeviceObject; /* lower target, NOT our DO */
        node->StartSec = (ULONG)StartSec;
        node->SecCount = SecCount;

        Irp->Tail.Overlay.DriverContext[0] = target;
        IoMarkIrpPending(Irp);
        Irp->IoStatus.Status = STATUS_PENDING;
        IoSetCancelRoutine(Irp, RdaSessionCancelPumpIrp);

        {
            KIRQL oldIrql;

            KeAcquireSpinLock(&target->QueueLock, &oldIrql);
            InsertTailList(&target->PumpQueueHead, &node->ListEntry);
            KeReleaseSpinLock(&target->QueueLock, oldIrql);
            InterlockedIncrement(&target->QueuedCount);
        }
        RdaSessionKick(target);
        return RdaWriteParked;
    }

    if (state == RDA_SESSION_STATE_COPYING && RdaSessionRangeNeedsCow(target, StartSec, SecCount)) {
        NTSTATUS cowStatus = RdaSessionCowSave(target, StartSec, SecCount);

        if (!NT_SUCCESS(cowStatus)) {
            return RdaWriteBlocked;
        }
    }
    return RdaWriteForward;
}

/* ---------------------------------------------------------------------------
 * Protocol dispatch (control device)
 * ------------------------------------------------------------------------- */
NTSTATUS RdaSessionDispatch(_In_ ULONG CustomCode, _In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack,
                            _In_opt_ PRDA_OPEN_CONTEXT Context) {
    PRDA_SESSION session;
    ULONG inLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;

    UNREFERENCED_PARAMETER(Context);

    /* Commands that do NOT require a session handle first. */
    switch (CustomCode) {
    case RDA_SESSION_CODE_GET_VERSION:
        /* Reference gate: INPUT length >= 0x84 (G12); Information = 0. */
        if (inLength < RDA_SESSION_GET_VERSION_MIN_IN || buffer == NULL) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        *(PULONG)buffer = RDA_SESSION_PROTO_VERSION;
        {
            SIZE_T n = 0;

            while (n + 1 < RDA_SESSION_PRODUCT_STRING_MAX &&
                   RDA_SESSION_PRODUCT_STRING[n] != '\0') {
                ((PCHAR)buffer)[4 + n] = RDA_SESSION_PRODUCT_STRING[n];
                n++;
            }
            ((PCHAR)buffer)[4 + n] = '\0';
        }
        Irp->IoStatus.Information = 0;
        return STATUS_SUCCESS;

    case RDA_SESSION_CODE_OPEN_SESSION:
        return RdaSessionOpen(Irp, Stack);

    case RDA_SESSION_CODE_DIRECT_READ:
    case RDA_SESSION_CODE_DIRECT_WRITE:
    case RDA_SESSION_CODE_SIZED_XFER:
    case RDA_SESSION_CODE_SIZED_XFER2:
        /* Direct-family commands are session-FREE (the disk id comes from
         * the MDL header) - reference FUN_000120f8 direct branches. */
        return RdaSessionDirectIo(Irp, Stack,
                                  CustomCode == RDA_SESSION_CODE_DIRECT_WRITE ||
                                      CustomCode == RDA_SESSION_CODE_SIZED_XFER2,
                                  CustomCode == RDA_SESSION_CODE_SIZED_XFER ||
                                      CustomCode == RDA_SESSION_CODE_SIZED_XFER2);

    case RDA_SESSION_CODE_RRWR_VERSION:
    case RDA_SESSION_CODE_RRWR_READ:
    case RDA_SESSION_CODE_RRWR_WRITE:
    case RDA_SESSION_CODE_DISCOVERY:
        /* Reference-verified: the discovery + RRWR families are served on the
         * FILTER stacks only (the disk binding comes from the filter device
         * extension, FUN_00012b70/FUN_00013310). On the CONTROL device these
         * codes fall through the reference's if-chain to the plain
         * STATUS_SUCCESS completion (LAB_000129f9 with status 0). */
        return STATUS_SUCCESS;

    default:
        break;
    }

    if (CustomCode == RDA_SESSION_CODE_MODE3 || CustomCode == RDA_SESSION_CODE_MODE4) {
        if (inLength < RDA_SESSION_FILEIO_MIN_IN || outLength < sizeof(ULONG) || buffer == NULL) {
            return STATUS_INVALID_PARAMETER;
        }
        return RdaSessionFileIo(Irp, Stack,
                                CustomCode == RDA_SESSION_CODE_MODE3 ? IRP_MJ_READ : IRP_MJ_WRITE);
    }

    /* Everything else requires a session handle in the first 8 bytes. */
    if (buffer == NULL || inLength < RDA_SESSION_INPUT_MIN_LEN) {
        return STATUS_INVALID_HANDLE;
    }
    session = RdaSessionFromHandle(*(PULONG64)buffer);
    if (session == NULL) {
        /* Per-command invalid-handle statuses (reference). */
        if (CustomCode == RDA_SESSION_CODE_CLOSE_SESSION ||
            CustomCode == RDA_SESSION_CODE_GET_PROGRESS) {
            return STATUS_INVALID_HANDLE;
        }
        return STATUS_INVALID_PARAMETER;
    }

    switch (CustomCode) {
    case RDA_SESSION_CODE_SESSION_OP:
        /* Flush protected file; the reference always returns 0. */
        return RdaSessionFlushProtectedFile(session);

    case RDA_SESSION_CODE_SESSION_OP2:
        return RdaSessionStartBackup(session, Irp, Stack);

    case RDA_SESSION_CODE_SESSION_STATUS:
        /* Returns the block-map status AS the NTSTATUS (G18). */
        return (NTSTATUS)session->MapStatus;

    case RDA_SESSION_CODE_GET_PROGRESS:
        return RdaSessionFinalize(session, Irp, Stack);

    case RDA_SESSION_CODE_CLOSE_SESSION:
        RdaSessionDestroy(session);
        Irp->IoStatus.Information = 0;
        return STATUS_SUCCESS;

    case RDA_SESSION_CODE_CANCEL:
        RdaSessionCancelCommand(session);
        Irp->IoStatus.Information = 0;
        return STATUS_SUCCESS;

    case RDA_SESSION_CODE_GETNEXTBLOCK: {
        PRDA_PUMP_NODE node;
        KIRQL oldIrql;

        if (outLength < RDA_SESSION_GETNEXTBLOCK_MIN_OUT ||
            inLength < RDA_SESSION_GETNEXTBLOCK_MIN_IN) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        if (session->QueuedCount >= RDA_SESSION_QUEUE_CAP) {
            return STATUS_NO_MEMORY; /* reference: exhausted free pool */
        }
        node = (PRDA_PUMP_NODE)RdaAllocZero(sizeof(RDA_PUMP_NODE));
        if (node == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        node->Kind = RdaPumpGetNextBlock;
        node->Irp = Irp;

        Irp->Tail.Overlay.DriverContext[0] = session;
        KeAcquireSpinLock(&session->QueueLock, &oldIrql);
        IoMarkIrpPending(Irp);
        Irp->IoStatus.Status = STATUS_PENDING;
        IoSetCancelRoutine(Irp, RdaSessionCancelPumpIrp);
        InsertTailList(&session->PumpQueueHead, &node->ListEntry);
        KeReleaseSpinLock(&session->QueueLock, oldIrql);
        InterlockedIncrement(&session->QueuedCount);

        RdaSessionKick(session);
        return STATUS_PENDING;
    }

    default:
        /* Reference fall-through: unknown codes complete SUCCESS on the
         * control device (LAB_000129f9 with status 0). */
        return STATUS_SUCCESS;
    }
}
