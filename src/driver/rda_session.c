/*
 * rda_session.c - copy-session engine (EUDCPEPM 15-command protocol merge).
 *
 * Wire contract (reference-exact; docs/ground-truth-contracts.md section 5):
 *   codes are normalized by the caller (rda_ioctl.c) as (code - IoctlBase)
 *   and dispatched here when SessionsEnabled. Every command validates its
 *   session via a magic-guarded opaque HANDLE (RDA deviation F12: the
 *   reference passed raw kernel pointers back and forth; the wire value is
 *   opaque to consumers, so an ID table is wire-compatible AND removes the
 *   arbitrary-pointer-dereference attack surface).
 *
 * Session semantics:
 *   OpenSession: validates {tSecs != 0, bitmapSize != 0, bitmapCount != 0},
 *     computes spb (0 -> tSecs<0x20 ? 1 : 0x10, tail = tSecs & 0xF), rejects
 *     overlapping ranges on the same disk with STATUS_SHARING_VIOLATION
 *     (reference-verified), resolves the disk, probes sector size, copies
 *     the 0x800-byte block bitmap, spawns the worker thread, returns
 *     handle, effective spb @+0x30, sector size @+0x83C.
 *   GETNEXTBLOCK: queues the caller IRP pending; the worker streams
 *     bitmap-selected blocks (spb sectors each) from the source into the
 *     IRP's output buffer and completes it asynchronously. Bounded worker
 *     kicks (0x12D = 301, reference parity) guard against release storms.
 *   Direct/sized sector R/W: {u32 diskId, u32 sectorCount, u64 offset, data}
 *     headers with bounds checks (reference gates).
 *   GET_PROGRESS: percent = bytesDone * 100 / totalBytes at out+8.
 *   CANCEL: state 3 (abort); pending IRPs complete with STATUS_CANCELLED.
 *   GET_VERSION: 0x00010100 + product string (RDA identity string; the
 *     reference returned its own - documented divergence, same layout).
 *
 * Clean-room notes (documented divergences from unobserved internals):
 *   - The reference's internal urgent-IRP pagefile blocking
 *     ("ProcessUrgentIrp pagefile bk") is not re-implemented: paging-file
 *     region detection is not part of any wire contract and is irrelevant
 *     to the quiesced WinPE deployment profile. Tracked in docs as F14.
 *   - Commands 0x800C2AD8/0x800C2AE0 (session run/parameter ops) and
 *     0x800C2B18/0x800C2B20 (lock/hold families) return SUCCESS and track
 *     state; the DRW consumer set does not use them and the reference
 *     semantics were not fully decompiled (documented as parity stubs).
 *
 * Licensed under the MIT license. See LICENSE.
 */

#include "rda_p.h"

#define RDA_SESSION_MAGIC       (('R' << 24) | ('D' << 16) | ('A' << 8) | 'S')
#define RDA_SESSION_TABLE_SIZE  64
#define RDA_SESSION_KICK_CAP    301 /* reference: 0x12D */
#define RDA_SESSION_STATE_INIT  0x38
#define RDA_SESSION_STATE_ABORT 3
#define RDA_SESSION_MAX_BLOCKS  (0x800 * 8) /* 0x800-byte bitmap, 16384 blocks */

typedef struct _RDA_PUMP_NODE {
    LIST_ENTRY ListEntry;
    PIRP Irp;
    ULONG OutBytes;
} RDA_PUMP_NODE, *PRDA_PUMP_NODE;

typedef struct _RDA_SESSION {
    volatile LONG Magic;
    volatile LONG Active;
    volatile LONG Generation;
    ULONG DiskId;
    ULONG SectorSize;
    ULONG Spb;         /* sectors per block */
    ULONG TailSectors; /* remainder sectors of the final block */
    ULONG64 TotalSecs;
    ULONG64 DataFirstSec;
    ULONG64 NextBlock; /* cursor: index of the next block to stream */
    ULONG TotalBlocks; /* ceil(TotalSecs / Spb) */
    volatile LONG64 BytesDone;
    ULONG64 TotalBytes;
    volatile LONG State;
    volatile LONG Abort;
    PUCHAR BlockBitmap;          /* owned copy, TotalBlocks bits, 0x800 bytes max */
    PDEVICE_OBJECT TargetDevice; /* referenced */
    PFILE_OBJECT TargetFileObject;
    PETHREAD WorkerThread;
    KEVENT WorkerStop;
    KSEMAPHORE WorkerKick;
    KSPIN_LOCK QueueLock;
    LIST_ENTRY PumpQueueHead; /* LIST_ENTRY of RDA_PUMP_NODE */
    volatile LONG KickCount;
    FAST_MUTEX Lock; /* session create/destroy serialization */
} RDA_SESSION, *PRDA_SESSION;

static RDA_SESSION g_RdaSessions[RDA_SESSION_TABLE_SIZE];
static FAST_MUTEX g_RdaSessionTableLock;
static volatile LONG g_RdaSessionNextId = 1;

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
    /* Generation guard: prevents stale-handle reuse after close (ABA). */
    if (session->Generation != (LONG)generation) {
        return NULL;
    }
    return session;
}

/* Allocates a table slot and returns an opaque handle. */
static PRDA_SESSION RdaSessionAllocate(_Out_ PULONG64 Handle) {
    ULONG i;

    ExAcquireFastMutex(&g_RdaSessionTableLock);
    for (i = 0; i < RDA_SESSION_TABLE_SIZE; i++) {
        if (g_RdaSessions[i].Active == 0 && g_RdaSessions[i].Magic == 0) {
            RtlZeroMemory(&g_RdaSessions[i], sizeof(RDA_SESSION));
            KeInitializeSpinLock(&g_RdaSessions[i].QueueLock);
            InitializeListHead(&g_RdaSessions[i].PumpQueueHead);
            KeInitializeEvent(&g_RdaSessions[i].WorkerStop, NotificationEvent, FALSE);
            KeInitializeSemaphore(&g_RdaSessions[i].WorkerKick, 0, 0x7FFFFFFF);
            ExInitializeFastMutex(&g_RdaSessions[i].Lock);
            g_RdaSessions[i].Active = 1;
            g_RdaSessions[i].Magic = RDA_SESSION_MAGIC;
            /* Generation increments per reuse; new handle carries it. */
            g_RdaSessions[i].Generation += 1;
            if (g_RdaSessions[i].Generation <= 0) {
                g_RdaSessions[i].Generation = 1;
            }
            *Handle = ((ULONG64)(i + 1) << 16) | (ULONG64)(ULONG)g_RdaSessions[i].Generation;
            ExReleaseFastMutex(&g_RdaSessionTableLock);
            return &g_RdaSessions[i];
        }
    }
    ExReleaseFastMutex(&g_RdaSessionTableLock);
    return NULL;
}

static VOID RdaSessionFreeSlot(_In_ PRDA_SESSION Session) {
    ExAcquireFastMutex(&g_RdaSessionTableLock);
    Session->Active = 0;
    Session->Magic = 0;
    ExReleaseFastMutex(&g_RdaSessionTableLock);
}

/* Reference-verified overlap guard: same disk + overlapping sector range. */
static BOOLEAN RdaSessionOverlapsExisting(_In_ ULONG DiskId, _In_ ULONG64 StartSec,
                                          _In_ ULONG64 LengthSecs,
                                          _In_opt_ PRDA_OPEN_SESSION Self) {
    ULONG i;
    BOOLEAN overlaps = FALSE;

    ExAcquireFastMutex(&g_RdaSessionTableLock);
    for (i = 0; i < RDA_SESSION_TABLE_SIZE && !overlaps; i++) {
        PRDA_SESSION s = &g_RdaSessions[i];

        if (s->Active == 0 || s->Magic != RDA_SESSION_MAGIC) {
            continue;
        }
        if (s->DiskId != DiskId) {
            continue;
        }
        {
            ULONG64 sStart = s->DataFirstSec;
            ULONG64 sLen = s->TotalSecs;

            if (StartSec < sStart + sLen && sStart < StartSec + LengthSecs) {
                overlaps = TRUE;
            }
        }
    }
    ExReleaseFastMutex(&g_RdaSessionTableLock);
    return overlaps;
}

/* ---------------------------------------------------------------------------
 * Worker thread: streams bitmap-selected blocks into queued pump IRPs.
 * ------------------------------------------------------------------------- */
static VOID RdaSessionCancelPumpIrp(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
    PRDA_SESSION session = (PRDA_SESSION)Irp->Tail.Overlay.DriverContext[0];
    PRDA_PUMP_NODE node;
    PLIST_ENTRY entry;
    BOOLEAN removed = FALSE;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (session == NULL) {
        Irp->IoStatus.Status = STATUS_CANCELLED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return;
    }

    KeAcquireSpinLockAtDpcLevel(&session->QueueLock); /* already at DISPATCH */
    /* Ownership test: if we can clear the routine, we own completion. */
    if (IoSetCancelRoutine(Irp, NULL) != NULL) {
        for (entry = session->PumpQueueHead.Flink; entry != &session->PumpQueueHead;
             entry = entry->Flink) {
            node = CONTAINING_RECORD(entry, RDA_PUMP_NODE, ListEntry);
            if (node->Irp == Irp) {
                RemoveEntryList(&node->ListEntry);
                RdaFree(node);
                removed = TRUE;
                break;
            }
        }
    }
    KeReleaseSpinLockFromDpcLevel(&session->QueueLock); /* stays DISPATCH */

    if (removed) {
        Irp->IoStatus.Status = STATUS_CANCELLED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }
    /* If not removed: the worker dequeued it first and will complete it. */
}

/* Reads one block into the pump IRP's SystemBuffer. Returns bytes produced. */
static NTSTATUS RdaSessionReadBlock(_In_ PRDA_SESSION Session, _Out_ PUCHAR Buffer,
                                    _In_ ULONG BufferBytes, _Out_ PULONG Produced) {
    NTSTATUS status;
    ULONG block;
    ULONG sectors;
    ULONG bytes;
    LARGE_INTEGER offset;
    ULONG_PTR information = 0;

    *Produced = 0;

    /* Bitmap-driven gap skipping: advance to the next SELECTED block (the
     * copy engine streams only bitmap-marked blocks; unmarked holes are
     * jumped, never emitted). */
    for (;;) {
        block = (ULONG)Session->NextBlock;
        if (block >= Session->TotalBlocks || block >= RDA_SESSION_MAX_BLOCKS) {
            return STATUS_END_OF_FILE; /* stream complete */
        }
        if ((Session->BlockBitmap[block / 8] & (1U << (block % 8))) != 0) {
            break;
        }
        Session->NextBlock = block + 1;
    }

    sectors = Session->Spb;
    if ((ULONG64)block * Session->Spb + sectors > Session->TotalSecs) {
        sectors = (ULONG)(Session->TotalSecs - (ULONG64)block * Session->Spb);
    }
    bytes = sectors * Session->SectorSize;
    if (bytes > BufferBytes) {
        bytes = BufferBytes;
        bytes -= bytes % Session->SectorSize;
        sectors = bytes / Session->SectorSize;
        if (sectors == 0) {
            return STATUS_BUFFER_TOO_SMALL;
        }
    }

    offset.QuadPart = ((ULONG64)block * Session->Spb + Session->DataFirstSec) * Session->SectorSize;
    status = RdaSyncDiskReadWrite(Session->TargetDevice, IRP_MJ_READ, Buffer, bytes, &offset,
                                  &information);
    if (NT_SUCCESS(status)) {
        *Produced = (ULONG)information;
        Session->BytesDone += information;
    }
    Session->NextBlock = block + 1;
    return status;
}

static VOID RdaSessionWorker(_In_ PVOID StartContext) {
    PRDA_SESSION session = (PRDA_SESSION)StartContext;

    for (;;) {
        NTSTATUS waitStatus;
        PVOID waitObjects[2];
        LARGE_INTEGER timeout;

        timeout.QuadPart = (LONGLONG)(-10) * 1000 * 1000 * 10; /* 10s guard poll */

        waitObjects[0] = (PVOID)&session->WorkerStop;
        waitObjects[1] = (PVOID)&session->WorkerKick;
        waitStatus = KeWaitForMultipleObjects(2, waitObjects, WaitAny, Executive, KernelMode, FALSE,
                                              &timeout, NULL);
        if (waitStatus == STATUS_WAIT_0) {
            break; /* stop requested */
        }

        /* Drain the pump queue. */
        for (;;) {
            PLIST_ENTRY entry;
            PRDA_PUMP_NODE node = NULL;
            PIRP irp = NULL;

            {
                KIRQL oldIrql;
                KeAcquireSpinLock(&session->QueueLock, &oldIrql);
                if (!IsListEmpty(&session->PumpQueueHead)) {
                    entry = RemoveHeadList(&session->PumpQueueHead);
                    node = CONTAINING_RECORD(entry, RDA_PUMP_NODE, ListEntry);
                    irp = node->Irp;
                    /* Claim completion ownership before releasing the lock. */
                    if (IoSetCancelRoutine(irp, NULL) == NULL) {
                        /* Cancel already claimed: drop the node; the cancel
                         * routine completes the IRP. */
                        RdaFree(node);
                        node = NULL;
                        irp = NULL;
                    }
                }
                KeReleaseSpinLock(&session->QueueLock, oldIrql);
            }

            if (node == NULL) {
                if (irp == NULL) {
                    break; /* queue drained */
                }
                continue;
            }

            if (session->Abort != 0) {
                irp->IoStatus.Status = STATUS_CANCELLED;
                irp->IoStatus.Information = 0;
                IoCompleteRequest(irp, IO_NO_INCREMENT);
                RdaFree(node);
                continue;
            }

            {
                PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
                ULONG outBytes = stack->Parameters.DeviceIoControl.OutputBufferLength;
                NTSTATUS status;
                ULONG produced = 0;

                if (irp->AssociatedIrp.SystemBuffer != NULL && outBytes != 0) {
                    status = RdaSessionReadBlock(session, (PUCHAR)irp->AssociatedIrp.SystemBuffer,
                                                 outBytes, &produced);
                } else {
                    status = STATUS_INVALID_PARAMETER;
                }

                if (status == STATUS_END_OF_FILE) {
                    status = STATUS_SUCCESS; /* end of stream: short/zero read */
                } else if (!NT_SUCCESS(status)) {
                    produced = 0;
                }
                irp->IoStatus.Status = status;
                irp->IoStatus.Information = produced;
                IoCompleteRequest(irp, IO_NO_INCREMENT);
                RdaFree(node);
            }
        }

        /* Abort completes queued IRPs; when both queue is empty and stream
         * ended, exit through the stop event check. */
        if (session->Abort != 0 && IsListEmpty(&session->PumpQueueHead)) {
            KeSetEvent(&session->WorkerStop, IO_NO_INCREMENT, FALSE);
        }
    }

    /* System threads terminate explicitly (reference-parity discipline). */
    PsTerminateSystemThread(STATUS_SUCCESS);
}

/* ---------------------------------------------------------------------------
 * Command handlers
 * ------------------------------------------------------------------------- */
static NTSTATUS RdaSessionOpen(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack) {
    NTSTATUS status;
    PRDA_OPEN_SESSION in = (PRDA_OPEN_SESSION)Irp->AssociatedIrp.SystemBuffer;
    ULONG outLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    PRDA_SESSION session;
    ULONG64 handle;
    PRDA_OPEN_CONTEXT context = NULL;

    if (in == NULL || outLength < RDA_SESSION_STRUCT_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (in->TotalSecs == 0 || in->BitmapSize == 0 || in->BitmapCount == 0) {
        return STATUS_INVALID_DEVICE_REQUEST; /* reference parity */
    }

    /* Overlap guard (reference-verified: STATUS_SHARING_VIOLATION). */
    if (RdaSessionOverlapsExisting(in->DiskId, in->DataFirstSec, in->TotalSecs, in)) {
        return STATUS_SHARING_VIOLATION;
    }

    session = RdaSessionAllocate(&handle);
    if (session == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Resolve the source disk via the EUEDKEPM chain (Partition0 + walk to
     * the disk class layer) - the copy engine's reference used the same
     * partition0 binding. */
    context = (PRDA_OPEN_CONTEXT)RdaAllocZero(sizeof(RDA_OPEN_CONTEXT));
    if (context == NULL) {
        RdaSessionFreeSlot(session);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    status = RdaResolveDiskEpm(in->DiskId, context);
    if (!NT_SUCCESS(status)) {
        RdaFree(context);
        RdaSessionFreeSlot(session);
        return status;
    }

    session->DiskId = in->DiskId;
    session->DataFirstSec = in->DataFirstSec;
    session->TotalSecs = in->TotalSecs;
    session->SectorSize = context->SectorSize;
    session->TargetDevice = context->TargetDevice; /* adopt reference */
    session->TargetFileObject = context->TargetFileObject;
    RdaFree(context);

    /* spb selection (reference parity). */
    session->Spb = in->SpbInOut;
    if (session->Spb == 0) {
        session->Spb = (in->TotalSecs < 0x20) ? 1 : 0x10;
    }
    session->TailSectors = (ULONG)(in->TotalSecs & 0xF);
    session->TotalBlocks = (ULONG)((in->TotalSecs + session->Spb - 1) / session->Spb);
    if (session->TotalBlocks > RDA_SESSION_MAX_BLOCKS) {
        session->TotalBlocks = RDA_SESSION_MAX_BLOCKS;
    }
    session->TotalBytes = in->TotalSecs * session->SectorSize;
    session->State = RDA_SESSION_STATE_INIT;

    /* Block bitmap copy (reference: 0x800 bytes + NUL pad at 0x7FE). */
    {
        SIZE_T bitmapBytes = in->BitmapSize;
        if (bitmapBytes > 0x800) {
            bitmapBytes = 0x800;
        }
        session->BlockBitmap = (PUCHAR)RdaAllocZero(0x800);
        if (session->BlockBitmap == NULL) {
            RdaSessionFreeSlot(session);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlCopyMemory(session->BlockBitmap, in->BlockBitmap, bitmapBytes);
    }

    /* Worker thread: PsCreateSystemThread yields a HANDLE; reference the
     * PETHREAD and close the handle so the session owns the object. */
    {
        HANDLE threadHandle = NULL;
        PETHREAD thread = NULL;

        status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL,
                                      RdaSessionWorker, session);
        if (NT_SUCCESS(status)) {
            status = ObReferenceObjectByHandle(threadHandle, 0, *PsThreadType, KernelMode,
                                               (PVOID *)&thread, NULL);
            ZwClose(threadHandle);
        }
        if (!NT_SUCCESS(status)) {
            if (thread != NULL) {
                ObDereferenceObject(thread);
            }
            RdaFree(session->BlockBitmap);
            session->BlockBitmap = NULL;
            ObDereferenceObject(session->TargetDevice);
            session->TargetDevice = NULL;
            ObDereferenceObject(session->TargetFileObject);
            session->TargetFileObject = NULL;
            RdaSessionFreeSlot(session);
            return status;
        }
        session->WorkerThread = thread;
    }

    /* Outputs (reference layout). */
    in->SessionHandle = handle;
    in->SpbInOut = session->Spb;
    in->SectorSize = session->SectorSize;
    Irp->IoStatus.Information = RDA_SESSION_STRUCT_SIZE;

    RDA_TRACE(RDA_LEVEL_INFO, "OpenSession: disk=%u first=%llu secs=%llu spb=%u ss=%u blocks=%u",
              session->DiskId, session->DataFirstSec, session->TotalSecs, session->Spb,
              session->SectorSize, session->TotalBlocks);
    return STATUS_SUCCESS;
}

static VOID RdaSessionCloseWorker(_In_ PRDA_SESSION Session) {
    PETHREAD thread = Session->WorkerThread;

    if (thread != NULL) {
        Session->Abort = 1;
        KeSetEvent(&Session->WorkerStop, IO_NO_INCREMENT, FALSE);
        KeReleaseSemaphore(&Session->WorkerKick, IO_NO_INCREMENT, 1, FALSE);
        KeWaitForSingleObject(thread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(thread);
        Session->WorkerThread = NULL;
    }
}

static NTSTATUS RdaSessionClose(_In_ PRDA_SESSION Session) {
    /* Complete any abandoned queued IRPs first. */
    {
        KIRQL oldIrql;
        KeAcquireSpinLock(&Session->QueueLock, &oldIrql);
        Session->Abort = 1;
        KeReleaseSpinLock(&Session->QueueLock, oldIrql);
    }

    for (;;) {
        PLIST_ENTRY entry;
        PRDA_PUMP_NODE node;
        KIRQL oldIrql;

        KeAcquireSpinLock(&Session->QueueLock, &oldIrql);
        if (!IsListEmpty(&Session->PumpQueueHead)) {
            entry = RemoveHeadList(&Session->PumpQueueHead);
            node = CONTAINING_RECORD(entry, RDA_PUMP_NODE, ListEntry);
            KeReleaseSpinLock(&Session->QueueLock, oldIrql);
            if (IoSetCancelRoutine(node->Irp, NULL) != NULL) {
                node->Irp->IoStatus.Status = STATUS_CANCELLED;
                node->Irp->IoStatus.Information = 0;
                IoCompleteRequest(node->Irp, IO_NO_INCREMENT);
            }
            RdaFree(node);
        } else {
            KeReleaseSpinLock(&Session->QueueLock, oldIrql);
            break;
        }
    }

    RdaSessionCloseWorker(Session);

    if (Session->TargetDevice != NULL) {
        ObDereferenceObject(Session->TargetDevice);
        Session->TargetDevice = NULL;
    }
    if (Session->TargetFileObject != NULL) {
        ObDereferenceObject(Session->TargetFileObject);
        Session->TargetFileObject = NULL;
    }
    if (Session->BlockBitmap != NULL) {
        RdaFree(Session->BlockBitmap);
        Session->BlockBitmap = NULL;
    }
    RdaSessionFreeSlot(Session);
    return STATUS_SUCCESS;
}

static NTSTATUS RdaSessionGetNextBlock(_In_ PRDA_SESSION Session, _In_ PIRP Irp,
                                       _In_ PIO_STACK_LOCATION Stack) {
    NTSTATUS status;
    ULONG inLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    PRDA_PUMP_NODE node;
    PIRP oldRoutine;

    if (inLength < RDA_SESSION_GETNEXTBLOCK_MIN_IN) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    node = (PRDA_PUMP_NODE)RdaAllocZero(sizeof(RDA_PUMP_NODE));
    if (node == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    node->Irp = Irp;

    /* The cancel routine locates the session through DriverContext[0]
     * (FileObject->FsContext belongs to the caller's handle, never us). */
    Irp->Tail.Overlay.DriverContext[0] = Session;

    KeAcquireSpinLockAtDpcLevel(&Session->QueueLock); /* DISPATCH after arming */
    IoMarkIrpPending(Irp);
    Irp->IoStatus.Status = STATUS_PENDING;
    IoSetCancelRoutine(Irp, RdaSessionCancelPumpIrp);
    InsertTailList(&Session->PumpQueueHead, &node->ListEntry);
    KeReleaseSpinLockFromDpcLevel(&Session->QueueLock);

    /* Bounded kick (reference parity: 0x12D cap). */
    if (Session->KickCount < RDA_SESSION_KICK_CAP) {
        InterlockedIncrement(&Session->KickCount);
        KeReleaseSemaphore(&Session->WorkerKick, IO_NO_INCREMENT, 1, FALSE);
    }

    status = STATUS_PENDING;
    return status;
}

static NTSTATUS RdaSessionDirectIo(_In_ PRDA_SESSION Session, _In_ PIRP Irp,
                                   _In_ PIO_STACK_LOCATION Stack, _In_ BOOLEAN IsWrite,
                                   _In_ BOOLEAN Sized) {
    NTSTATUS status;
    ULONG inLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    PUCHAR buffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
    ULONG diskId;
    ULONG sectorCount;
    ULONG64 offset;
    ULONG bytes;
    ULONG_PTR information = 0;
    LARGE_INTEGER byteOffset;

    if (buffer == NULL || inLength <= 0x10) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    diskId = *(PULONG)(buffer + 0x00);
    sectorCount = *(PULONG)(buffer + 0x04);
    offset = *(PULONG64)(buffer + 0x08);
    UNREFERENCED_PARAMETER(diskId); /* session's bound disk is authoritative */

    bytes = sectorCount * Session->SectorSize;
    if (bytes == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!IsWrite) {
        /* Reference bounds check: sectorSize*count + 0x10 <= outLength. */
        if ((SIZE_T)bytes + 0x10 > outLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }
    } else {
        if ((SIZE_T)bytes + 0x10 > inLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }
    }

    byteOffset.QuadPart = (LONGLONG)offset;
    status = RdaSyncDiskReadWrite(Session->TargetDevice, IsWrite ? IRP_MJ_WRITE : IRP_MJ_READ,
                                  buffer + 0x10, bytes, &byteOffset, &information);
    if (NT_SUCCESS(status)) {
        Irp->IoStatus.Information = information + 0x10;
    }
    UNREFERENCED_PARAMETER(Sized);
    return status;
}

/* ---------------------------------------------------------------------------
 * Engine lifecycle
 * ------------------------------------------------------------------------- */
VOID RdaSessionInit(VOID) {
    RtlZeroMemory(g_RdaSessions, sizeof(g_RdaSessions));
    ExInitializeFastMutex(&g_RdaSessionTableLock);
    g_RdaSessionNextId = 1;
}

VOID RdaSessionShutdown(VOID) {
    ULONG i;

    for (i = 0; i < RDA_SESSION_TABLE_SIZE; i++) {
        if (g_RdaSessions[i].Active != 0) {
            RdaSessionClose(&g_RdaSessions[i]);
        }
    }
}

/* ---------------------------------------------------------------------------
 * Protocol dispatch
 * ------------------------------------------------------------------------- */
NTSTATUS RdaSessionDispatch(_In_ ULONG CustomCode, _In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack,
                            _In_opt_ PRDA_OPEN_CONTEXT Context) {
    PRDA_SESSION session;
    ULONG inLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Context);

    switch (CustomCode) {
    case RDA_SESSION_CODE_GET_VERSION:
        if (outLength < RDA_SESSION_GET_VERSION_MIN_OUT || buffer == NULL) {
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
            Irp->IoStatus.Information = 4 + n + 1;
        }
        return STATUS_SUCCESS;

    case RDA_SESSION_CODE_OPEN_SESSION:
        return RdaSessionOpen(Irp, Stack);

    case RDA_SESSION_CODE_CLOSE_SESSION:
    case RDA_SESSION_CODE_SESSION_OP:
    case RDA_SESSION_CODE_SESSION_OP2:
    case RDA_SESSION_CODE_SESSION_STATUS:
    case RDA_SESSION_CODE_GET_PROGRESS:
    case RDA_SESSION_CODE_MODE3:
    case RDA_SESSION_CODE_MODE4:
    case RDA_SESSION_CODE_CANCEL:
        /* Session-handle commands. */
        break;

    default:
        /* Direct/sized transfers fall through with the session handle check. */
        if (CustomCode != RDA_SESSION_CODE_DIRECT_READ &&
            CustomCode != RDA_SESSION_CODE_DIRECT_WRITE &&
            CustomCode != RDA_SESSION_CODE_SIZED_XFER &&
            CustomCode != RDA_SESSION_CODE_SIZED_XFER2 &&
            CustomCode != RDA_SESSION_CODE_GETNEXTBLOCK) {
            return STATUS_INVALID_PARAMETER;
        }
        break;
    }

    /* Commands below require a session handle in the first 8 bytes. */
    if (buffer == NULL || inLength < RDA_SESSION_INPUT_MIN_LEN) {
        return STATUS_INVALID_HANDLE;
    }
    session = RdaSessionFromHandle(*(PULONG64)buffer);
    if (session == NULL) {
        RDA_TRACE(RDA_LEVEL_WARN, "session: invalid handle (code 0x%08X)", CustomCode);
        return STATUS_INVALID_HANDLE;
    }

    switch (CustomCode) {
    case RDA_SESSION_CODE_CLOSE_SESSION:
        return RdaSessionClose(session);

    case RDA_SESSION_CODE_SESSION_OP: /* run/pause family (parity stub) */
    case RDA_SESSION_CODE_SESSION_OP2:
        Irp->IoStatus.Information = 0;
        return STATUS_SUCCESS;

    case RDA_SESSION_CODE_SESSION_STATUS:
        if (outLength < sizeof(ULONG)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        *(PULONG)buffer = (ULONG)session->State;
        Irp->IoStatus.Information = sizeof(ULONG);
        return STATUS_SUCCESS;

    case RDA_SESSION_CODE_GET_PROGRESS:
        if (outLength < 0x0C || inLength < 0x0C) { /* reference gates: in > 0xB */
            return STATUS_BUFFER_TOO_SMALL;
        }
        *(PULONG)((PUCHAR)buffer + 8) =
            (ULONG)((session->BytesDone * 100) / (session->TotalBytes ? session->TotalBytes : 1));
        Irp->IoStatus.Information = outLength;
        return STATUS_SUCCESS;

    case RDA_SESSION_CODE_GETNEXTBLOCK:
        return RdaSessionGetNextBlock(session, Irp, Stack);

    case RDA_SESSION_CODE_DIRECT_READ:
    case RDA_SESSION_CODE_DIRECT_WRITE:
    case RDA_SESSION_CODE_SIZED_XFER:
    case RDA_SESSION_CODE_SIZED_XFER2:
        return RdaSessionDirectIo(session, Irp, Stack,
                                  CustomCode == RDA_SESSION_CODE_DIRECT_WRITE ||
                                      CustomCode == RDA_SESSION_CODE_SIZED_XFER2,
                                  CustomCode == RDA_SESSION_CODE_SIZED_XFER ||
                                      CustomCode == RDA_SESSION_CODE_SIZED_XFER2);

    case RDA_SESSION_CODE_MODE3: /* lock/hold family (parity stub) */
    case RDA_SESSION_CODE_MODE4: /* flush/unlock family (parity stub) */
        if (outLength < RDA_SESSION_MODE_MIN_OUT || inLength < RDA_SESSION_MODE_MIN_IN) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        Irp->IoStatus.Information = 0;
        return STATUS_SUCCESS;

    case RDA_SESSION_CODE_CANCEL:
        session->Abort = 1;
        session->State = RDA_SESSION_STATE_ABORT;
        KeReleaseSemaphore(&session->WorkerKick, IO_NO_INCREMENT, 1, FALSE);
        Irp->IoStatus.Information = 0;
        return STATUS_SUCCESS;

    default:
        return STATUS_INVALID_PARAMETER;
    }
}
