/*
 * rda_readwrite.c - IRP_MJ_READ / IRP_MJ_WRITE.
 *
 * Contract (reference-exact; verified both sides, see
 * docs/ground-truth-contracts.md section 3):
 *   - Parameters.Read/Write.Length is BYTES; ByteOffset is the absolute
 *     target offset; negative offsets fail with STATUS_INVALID_PARAMETER.
 *   - The driver forwards exactly Length bytes to the resolved target via a
 *     driver-built asynchronous FSD IRP over the caller's MDL (DO_DIRECT_IO).
 *   - On success the caller's Information is scaled: Length * 512 (the
 *     legacy convention - reference clients divide by 512; preserved).
 *   - DO_DIRECT_IO mapping uses MmGetSystemAddressForMdlSafe (equivalent to
 *     the reference's MmMapLockedPagesSpecifyCache call, minus the bugcheck
 *     path on failure - returns NULL which we fail with
 *     STATUS_INSUFFICIENT_RESOURCES).
 *
 * Global-handle modes (reference parity on bare/global opens):
 *   WRITE len==4: park the caller's u32 handle value in the driver-global
 *                slot (used by the reference GetDriverInfo handshake).
 *   READ (slot set, out len >= 0x208): resolve the parked handle's object
 *                name into the caller's buffer (see rda_ident.c).
 *
 * Cancellation (fix F4 - the reference waited without any cancel support,
 * hanging on dead drives):
 *   The design below is the "cancellable forward-wait" pattern:
 *     - A heap context shares {Wake event, DoneFlag, Cancelled, CancelDone
 *       event, final IO_STATUS_BLOCK, forward IRP} between the dispatcher,
 *       the forward completion routine and the caller-IRP cancel routine.
 *     - The cancel routine NEVER completes the caller IRP; it only flags
 *       + wakes the dispatcher (and signals CancelDone on exit).
 *     - The completion routine copies the final status, sets DoneFlag and
 *       wakes the dispatcher (STATUS_MORE_PROCESSING_REQUIRED - dispatcher
 *       frees the forward IRP after the wait, which also removes the
 *       "IoCancelIrp on freed IRP" hazard entirely).
 *     - On a cancel wake, the dispatcher propagates cancellation INTO the
 *       storage stack by calling IoCancelIrp on the forward IRP (owned,
 *       not yet freed - race-free) so a dead drive aborts promptly.
 *     - Single completer invariant: only the dispatcher completes the
 *       caller IRP (STATUS_CANCELLED when cancelled).
 *   The caller's buffer pages stay locked until the forward IRP completes,
 *   so completing the caller IRP early is impossible - this design keeps
 *   the synchronous contract while making the wait interruptible.
 *
 * Licensed under the MIT license. See LICENSE.
 */

#include "rda_p.h"

/*
 * Benchmark round 2 finding: the per-IO heap alloc/zero of the transfer
 * context cost measurable IOPS (we ran ~10% behind the reference on 4 KiB
 * random reads). A driver-wide SLIST free-list pool keeps the per-IO cost
 * at interlocked push/pop rates while preserving full concurrency safety.
 *
 * Kernel-version note (verified the hard way - StartService error 127 on a
 * Server 2022 runner): ExAllocate/FreeFromLookasideListEx are FORCEINLINE
 * before NTDDI_WIN10_NI but REAL ntoskrnl EXPORTS only from Windows 11
 * 22H2; a WDK-26100 build imports them and then cannot load on anything
 * older. A self-contained SLIST pool has zero such version coupling
 * (InterlockedPush/PopEntrySList are Win2000-era interlocks).
 */
static SLIST_HEADER g_RdaXferFreeList;
static volatile LONG g_RdaXferFreeDepth = 0;
#define RDA_XFER_FREE_DEPTH_MAX 32

/* 16-byte alignment: the SLIST link aliases the context head and
 * InterlockedPushEntrySList on x64 needs 16-byte-aligned entries. */
__declspec(align(16)) typedef struct _RDA_XFER_CONTEXT {
    KEVENT Wake;             /* set by completion or cancel routine */
    volatile LONG DoneFlag;  /* set by the completion routine after Iosb copy */
    volatile LONG Cancelled; /* set by the cancel routine */
    KEVENT CancelDone;       /* set by the cancel routine on exit (lifetime sync) */
    volatile LONG CancelStarted;
    IO_STATUS_BLOCK Iosb; /* final forward status (written by completion) */
    PIRP ForwardIrp;      /* driver-owned; freed by the dispatcher */
} RDA_XFER_CONTEXT, *PRDA_XFER_CONTEXT;

static PVOID RdaXferCtxAlloc(VOID) {
    PSLIST_ENTRY entry = InterlockedPopEntrySList(&g_RdaXferFreeList);

    if (entry != NULL) {
        InterlockedDecrement(&g_RdaXferFreeDepth);
        RtlZeroMemory(entry, sizeof(RDA_XFER_CONTEXT));
        return entry;
    }
    return RdaAllocZero(sizeof(RDA_XFER_CONTEXT));
}

/* Cancel routine for the CALLER's IRP. Runs at DISPATCH_LEVEL with the
 * GLOBAL CANCEL SPINLOCK HELD by the IO manager (it swapped our routine out
 * before calling us, so no ownership test is needed or possible here).
 *
 * S1 fix: the cancel routine MUST release the global cancel spinlock via
 * IoReleaseCancelSpinLock(Irp->CancelIrql) before returning - the v0.1.0
 * routine never did, which deadlocked the whole system's cancel machinery
 * on the first cancelled IO.
 *
 * The routine NEVER completes the caller IRP: it only flags cancellation and
 * wakes the dispatcher, which propagates the cancel into the storage stack
 * and owns completion (single-completer invariant). After the spinlock
 * release it touches only the heap context, which stays alive until the
 * dispatcher observes CancelDone. */
static DRIVER_CANCEL RdaReadWriteCancelRoutine;

static VOID RdaReadWriteCancelRoutine(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
    PRDA_XFER_CONTEXT ctx;
    KIRQL cancelIrql = Irp->CancelIrql;

    UNREFERENCED_PARAMETER(DeviceObject);

    IoReleaseCancelSpinLock(cancelIrql);

    ctx = (PRDA_XFER_CONTEXT)Irp->Tail.Overlay.DriverContext[0];
    if (ctx != NULL) {
        InterlockedExchange(&ctx->Cancelled, 1);
        KeSetEvent(&ctx->Wake, IO_NO_INCREMENT, FALSE);
        InterlockedExchange(&ctx->CancelStarted, 1);
        KeSetEvent(&ctx->CancelDone, IO_NO_INCREMENT, FALSE);
    }
    /* Do NOT complete the caller IRP here; the dispatcher owns completion. */
}

/* Completion for the driver-built forward IRP. Runs at DISPATCH_LEVEL.
 * Copies the final status, marks done, wakes the waiter, and returns
 * MORE_PROCESSING so the IO manager leaves the forward IRP alone (the
 * dispatcher frees it after the wait - eliminating use-after-free races
 * with cancellation). */
static IO_COMPLETION_ROUTINE RdaForwardCompletion;

/* Return to the free-list below the depth cap, else the pool. The SLIST
 * link aliases the FIRST field of the context - the context's first field
 * (Wake.KEVENT.Header.Type/Size) is re-initialized by KeInitializeEvent on
 * every reuse, so the aliasing is safe. */
static VOID RdaXferCtxFree(_In_ PRDA_XFER_CONTEXT Context) {
    if (g_RdaXferFreeDepth < RDA_XFER_FREE_DEPTH_MAX) {
        InterlockedIncrement(&g_RdaXferFreeDepth);
        InterlockedPushEntrySList(&g_RdaXferFreeList, (PSLIST_ENTRY)Context);
    } else {
        RdaFree(Context);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL) VOID RdaReadWriteShutdown(VOID) {
    for (;;) {
        PSLIST_ENTRY entry = InterlockedPopEntrySList(&g_RdaXferFreeList);

        if (entry == NULL) {
            break;
        }
        RdaFree(entry);
    }
}

static NTSTATUS RdaForwardCompletion(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp,
                                     _In_opt_ PVOID Context) {
    PRDA_XFER_CONTEXT ctx = (PRDA_XFER_CONTEXT)Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    ctx->Iosb.Status = Irp->IoStatus.Status;
    ctx->Iosb.Information = Irp->IoStatus.Information;
    /* Publish the status before the flag; KeSetEvent orders the release. */
    InterlockedExchange(&ctx->DoneFlag, 1);
    KeSetEvent(&ctx->Wake, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

/* Minimal completion for RdaSyncDiskReadWrite: signal + continue. */
static IO_COMPLETION_ROUTINE RdaSyncCompletion;

static NTSTATUS RdaSyncCompletion(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp,
                                  _In_opt_ PVOID Context) {
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    if (Context != NULL) {
        KeSetEvent((PKEVENT)Context, IO_NO_INCREMENT, FALSE);
    }
    return STATUS_CONTINUE_COMPLETION;
}

/* Core forwarding for a resolved-target READ/WRITE. Returns the NTSTATUS to
 * complete the caller IRP with; *Information set on success. */
static NTSTATUS RdaForwardSynchronous(_In_ PDEVICE_OBJECT TargetDevice, _In_ UCHAR MajorFunction,
                                      _In_ PVOID SystemAddress, _In_ ULONG Length,
                                      _In_ PLARGE_INTEGER ByteOffset, _In_ PIRP CallerIrp,
                                      _Out_ PULONG_PTR Information, _In_ BOOLEAN ScaleInformation) {
    NTSTATUS status;
    PRDA_XFER_CONTEXT ctx;
    PIRP forward;
    BOOLEAN cancelPropagated = FALSE;

    *Information = 0;

    if (ByteOffset->QuadPart < 0) {
        return STATUS_INVALID_PARAMETER;
    }

    ctx = (PRDA_XFER_CONTEXT)RdaXferCtxAlloc();
    if (ctx == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    KeInitializeEvent(&ctx->Wake, NotificationEvent, FALSE);
    KeInitializeEvent(&ctx->CancelDone, NotificationEvent, FALSE);

    /* Stash the context where the cancel routine can reach it. DriverContext
     * is free space on an IRP that has no driver stack yet below the current
     * location. */
    CallerIrp->Tail.Overlay.DriverContext[0] = ctx;

    /* Arm cancellation BEFORE forwarding so no in-flight window exists. */
    IoSetCancelRoutine(CallerIrp, RdaReadWriteCancelRoutine);

    /* Cancel race: if the caller IRP was already cancelled while the routine
     * was being armed and we still own it (swap-back non-NULL), the cancel
     * path never ran - fail fast instead of forwarding a dead request. */
    if (CallerIrp->Cancel && IoSetCancelRoutine(CallerIrp, NULL) != NULL) {
        CallerIrp->Tail.Overlay.DriverContext[0] = NULL;
        RdaXferCtxFree(ctx);
        return STATUS_CANCELLED;
    }

    forward = IoBuildAsynchronousFsdRequest(MajorFunction, TargetDevice, SystemAddress, Length,
                                            ByteOffset, &ctx->Iosb);
    if (forward == NULL) {
        IoSetCancelRoutine(CallerIrp, NULL);
        CallerIrp->Tail.Overlay.DriverContext[0] = NULL;
        RdaXferCtxFree(ctx);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ctx->ForwardIrp = forward;

    IoSetCompletionRoutine(forward, RdaForwardCompletion, ctx, TRUE, TRUE, TRUE);

    status = IoCallDriver(TargetDevice, forward);

    /* Wait until the forward completes (cancel wakes us early to propagate
     * cancellation into the storage stack). Single event, flag-checked loop:
     * no lost wakeups (each KeSetEvent on a notification event wakes one
     * waiter; we re-wait until DoneFlag is observed). */
    for (;;) {
        if (ctx->DoneFlag != 0) {
            break;
        }
        KeWaitForSingleObject(&ctx->Wake, Executive, KernelMode, FALSE, NULL);
        if (ctx->DoneFlag != 0) {
            break;
        }
        if (ctx->Cancelled != 0 && !cancelPropagated) {
            /* The caller gave up: abort the storage request. The forward IRP
             * is still alive (we own it until after this loop), so this
             * IoCancelIrp is race-free. */
            IoCancelIrp(forward);
            cancelPropagated = TRUE;
        }
    }

    /* Disarm the cancel routine. If it already fired, wait for it to finish
     * touching the context before freeing it. */
    if (IoSetCancelRoutine(CallerIrp, NULL) == NULL) {
        KeWaitForSingleObject(&ctx->CancelDone, Executive, KernelMode, FALSE, NULL);
    }
    CallerIrp->Tail.Overlay.DriverContext[0] = NULL;

    status = (ctx->Cancelled != 0) ? STATUS_CANCELLED : ctx->Iosb.Status;
    if (NT_SUCCESS(status)) {
        if (ScaleInformation) {
            *Information = (ULONG_PTR)Length * RDA_LEGACY_INFORMATION_SCALE;
        } else {
            *Information = ctx->Iosb.Information;
        }
    }

    IoFreeIrp(forward);
    RdaXferCtxFree(ctx);
    return status;
}

static NTSTATUS RdaDispatchReadWriteInner(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack,
                                          _In_ UCHAR MajorFunction) {
    PRDA_OPEN_CONTEXT context;
    ULONG length;
    PVOID systemAddress;
    NTSTATUS status;
    ULONG_PTR information = 0;
    LARGE_INTEGER byteOffset;
    ULONG inLen;

    context =
        (PRDA_OPEN_CONTEXT)((Stack->FileObject != NULL) ? Stack->FileObject->FsContext2 : NULL);

    /* Map the caller's MDL once; used by every branch below. */
    if (Irp->MdlAddress != NULL) {
        systemAddress = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
        if (systemAddress == NULL) {
            Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    } else {
        /* DO_DIRECT_IO guarantees an MDL for buffered transfer lengths; a
         * zero-length request may carry none. Treat as a failed mapping. */
        systemAddress = NULL;
    }

    if (MajorFunction == IRP_MJ_READ) {
        length = Stack->Parameters.Read.Length;
        byteOffset = Stack->Parameters.Read.ByteOffset;
        inLen = 0;
    } else {
        length = Stack->Parameters.Write.Length;
        byteOffset = Stack->Parameters.Write.ByteOffset;
        inLen = length;
    }

    if (context == NULL || context->TargetDevice == NULL) {
        /* Global-handle modes (reference parity on bare opens). */
        if (MajorFunction == IRP_MJ_WRITE && inLen == sizeof(ULONG) && systemAddress != NULL) {
            g_RdaGlobalHandle = *(volatile LONG *)systemAddress;
            Irp->IoStatus.Status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(ULONG);
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            RDA_TRACE(RDA_LEVEL_INFO, "global handle parked (write-len-4 mode)");
            return STATUS_SUCCESS;
        }
        if (MajorFunction == IRP_MJ_READ && g_RdaGlobalHandle != 0 && length > 0x207 &&
            systemAddress != NULL) {
            status = RdaIoctlGetFileObjNameCore((HANDLE)(ULONG_PTR)g_RdaGlobalHandle, systemAddress,
                                                length, &information);
            Irp->IoStatus.Status = status;
            Irp->IoStatus.Information = information;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return status;
        }
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_PARAMETER;
    }

    if (length == 0 || systemAddress == NULL) {
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_PARAMETER;
    }

    status = RdaForwardSynchronous(context->TargetDevice, MajorFunction, systemAddress, length,
                                   &byteOffset, Irp, &information, TRUE);

    if (!NT_SUCCESS(status)) {
        if (MajorFunction == IRP_MJ_WRITE) {
            RDA_TRACE(RDA_LEVEL_ERROR, "[epmntdrvDispatchWrite] Write error 0x%x,%u,%I64u,0x%x",
                      status, length, byteOffset.QuadPart, (ULONG_PTR)context->TargetDevice);
        } else {
            RDA_TRACE(RDA_LEVEL_ERROR, "[epmntdrvDispatchRead] Read error 0x%x,%u,%I64u", status,
                      length, byteOffset.QuadPart);
        }
        information = 0;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/*
 * RdaSyncDiskReadWrite - internal synchronous sector IO without a caller IRP
 * (session engine, direct/sized transfers). Single-shot forward + wait; runs
 * at PASSIVE_LEVEL in the caller's context (system thread for the pump).
 * No cancellation here: the session abort path tears the worker down and
 * the storage stack's own timeouts bound pathological waits.
 */
NTSTATUS RdaSyncDiskReadWrite(_In_ PDEVICE_OBJECT TargetDevice, _In_ UCHAR MajorFunction,
                              _In_ PVOID SystemAddress, _In_ ULONG Length,
                              _In_ PLARGE_INTEGER ByteOffset, _Out_ PULONG_PTR Information) {
    NTSTATUS status;
    KEVENT event;
    PIRP forward;
    IO_STATUS_BLOCK iosb;

    *Information = 0;
    if (ByteOffset->QuadPart < 0 || Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    KeInitializeEvent(&event, NotificationEvent, FALSE);
    RtlZeroMemory(&iosb, sizeof(iosb));

    forward = IoBuildAsynchronousFsdRequest(MajorFunction, TargetDevice, SystemAddress, Length,
                                            ByteOffset, &iosb);
    if (forward == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* The completion signals the event and lets the manager free the IRP
     * (STATUS_CONTINUE_COMPLETION): for this internal path nothing must be
     * reclaimed by us, so the plain forward-complete pattern is correct. */
    {
        struct RdaSyncCtx {
            KEVENT *Event;
        } syncCtx;
        syncCtx.Event = &event;

        IoSetCompletionRoutine(forward, RdaSyncCompletion, &event, /* context: the event directly */
                               TRUE, TRUE, TRUE);
    }

    status = IoCallDriver(TargetDevice, forward);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    }
    if (NT_SUCCESS(status)) {
        *Information = iosb.Information;
    }
    return status;
}

NTSTATUS RdaDispatchRead(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    UNREFERENCED_PARAMETER(DeviceObject);
    return RdaDispatchReadWriteInner(Irp, stack, IRP_MJ_READ);
}

NTSTATUS RdaDispatchWrite(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    UNREFERENCED_PARAMETER(DeviceObject);
    return RdaDispatchReadWriteInner(Irp, stack, IRP_MJ_WRITE);
}
