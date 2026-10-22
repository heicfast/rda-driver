# Security Review — RDA merged driver (session 2, 2026-10-22)

Scope: the complete merged driver after the decompile re-verification round
(`src/driver/*`). Per the engagement brief: heap peaks, memory leaks, use-after-free,
double frees, buffer overflows, access control, and general kernel-hygiene review,
performed at senior-security-engineer depth with every finding traced to code and
verified against the reference corpus.

Severity scale: P0 = system-wide deadlock/crash or security boundary break;
P1 = potential UAF/leak under specific races; P2 = hardening/defense-in-depth.

## Findings fixed in this round

### S1 (P0) — READ/WRITE cancel routine held the global cancel spinlock
`RdaReadWriteCancelRoutine` returned without `IoReleaseCancelSpinLock(Irp->CancelIrql)`.
The IO manager invokes cancel routines with the *global* cancel spinlock held; any
driver that fails to release it deadlocks every later `IoCancelIrp`/`IoSetCancelRoutine`
in the system. Trigger: a single cancelled ReadFile on a stuck device (e.g. unplugged
USB disk). v0.1.0 shipped this defect - it would have hard-hung the machine on the
first cancel. **Fix**: release the spinlock first, then touch only the heap context
(single-completer invariant preserved: only the dispatcher completes the caller IRP).

### S2 (P0) — session pump cancel routine: same spinlock bug + never completed
`RdaSessionCancelPumpIrp` had S1's spinlock bug AND called `IoSetCancelRoutine(Irp, NULL)`
*inside* the cancel routine - the IO manager already swapped the pointer to NULL before
invoking us, so the "ownership test" always failed, the queue search never ran, and a
cancelled GETNEXTBLOCK IRP was never completed (permanent user-thread hang at
CloseHandle) while the cancel spinlock stayed held. **Fix**: release the spinlock,
search the queue; complete the IRP on BOTH outcomes (found = we removed it;
not-found = the worker dequeued it and delegated completion to us after its cancel
swap came back NULL - the standard cancel-safe-queue ownership contract).

### S3 (P0) — control-device extension dereference
`RdaDispatchPnp`/`RdaDispatchPower` dereferenced `DeviceObject->DeviceExtension`
*before* checking whether the IRP belonged to the control device. The control device
is created with a **zero-size** extension; the pointer aliases unrelated memory and
the magic test read unowned pool. **Fix**: master dispatch (G11) routes on
`DeviceObject == g_RdaControlDevice`; PnP/Power on the control device complete without
ever touching the extension.

### S4 (P1) — filter REMOVE use-after-free window
`RdaFilterPnpRemove` called `IoCallDriver(lower, Irp)` and immediately
`IoDetachDevice` + `IoDeleteDevice` - if the lower driver returned STATUS_PENDING the
stack below still referenced the device object we just deleted. **Fix**: the
event-wait pattern (copy stack location, completion routine returning
MORE_PROCESSING_REQUIRED, wait, then detach+delete).

### S5 (P1) — OpenSession reference leak on a late failure
After the target references were adopted into the session, a bitmap-allocation
failure freed the slot but not the references. **Fix**: symmetric deref on every
post-adoption failure path.

### S6 (P1) — OpenSession overlap check TOCTOU
The overlap scan and the slot activation ran in separate lock holds; two concurrent
opens of overlapping ranges could both pass. **Fix**: allocate + range-claim in a
single table-lock critical section.

### S7 (P2) — TotalBlocks truncating cast
Plan/block arithmetic mixed 64-bit inputs with a 32-bit store; crafted TotalSecs
values could underflow the plan. **Fix**: 64-bit math with explicit caps and
alignment checks at every plan boundary (StartBackup additionally validates
`pumpBytes % (spb*sectorSize) == 0`).

### S8 (P2) — `RdaCopyUnicodeToBuffer` underflow
`BufferBytes - sizeof(WCHAR)` underflowed for `BufferBytes < 2`. All current callers
pass >= 0x208 (the reference gate), but the helper is a generic utility. **Fix**:
explicit small-buffer guard.

### S9 (P1) — IRQL contract violation in the pump enqueue
`KeAcquireSpinLockAtDpcLevel` at PASSIVE_LEVEL (GETNEXTBLOCK dispatch path). The lock
would silently not raise IRQL, leaving the queue unprotected against any later
DISPATCH_LEVEL interleave. **Fix**: `KeAcquireSpinLock` (which is correct at PASSIVE
and inside the DISPATCH cancel routine we keep the AtDpcLevel form).

### S10 (documented divergence) — zero-length bound READ/WRITE
The reference forwards zero-length FSD IRPs and NULL-dereferences its MDL on that
path (a crash latent in the original for a zero-length DO_DIRECT_IO read with no
MDL). We return STATUS_INVALID_PARAMETER. Kept deliberately; documented.

### S11 (P2) — control-device power path completed INVALID
Dead path (control devices do not receive power IRPs), but completing power IRPs
with STATUS_INVALID_DEVICE_REQUEST is the kind of thing verifier/SDV flags. Now
SUCCESS + `PoStartNextPowerIrp` (harmless everywhere, required on Win7).

### S12 (P2) — dead code removed
Unused `RDA_DP_COMPONENT` macro (also carried an unparenthesized expression bug),
unused `RDA_PNP_COMPLETION` struct, unused session FAST_MUTEX.

## Access control posture

- **Device DACL (F2, kept)**: control device created via `IoCreateDeviceSecure` with
  `D:P(A;;GA;;;BA)(A;;GA;;;SY)` - administrators + SYSTEM only, overridable via
  `Parameters\Sddl`. This is the primary boundary; everything the driver exposes
  (raw disk IO, identity IOCTLs, session engine, pass-through) sits behind it.
- **PID token (retained, demoted)**: the reference byte-sum handshake is kept purely
  for wire compatibility. It is NOT a boundary and is documented as such - a
  calculator-class process could compute its own token; the DACL is what stops it
  from ever getting a handle.
- **Identity IOCTLs (F3, kept)**: reachable only on global handles, which the DACL
  already restricts to admins. `GetProcName` resolves any PID's image path via
  `PsLookupProcessByProcessId + SeLocateProcessImageName` - no undocumented
  `NtOpenProcess` import, no cross-process handle juggling (the reference used
  NtOpenProcess(0x20000); our substitution removes an entire handle-theft class).
- **Session engine**: opaque generation-tagged handles (never kernel pointers - the
  reference handed raw CSession pointers to user mode, a trivially exploitable
  arbitrary-kernel-address primitive if the DACL were ever misconfigured; F12).
  Sessions die with their creating process (CLEANUP/CLOSE sweep), so a killed client
  cannot leave workers running or pump-buffer MDLs locked.
- **Pump buffer**: user-mode buffer locked with `MmProbeAndLockPages(UserMode,
  IoWriteAccess)` inside SEH; unlocked + MDL freed at finalize/close - no way to
  leave pages locked across a session lifetime.
- **Filter role**: the filter never trusts IRP-supplied lengths; every intercept
  path (WRITE park, TRIM swallow, discovery, RRWR) re-validates sizes against the
  stack-provided MDL before touching memory.

## Memory-safety inventory (post-fix)

| Resource | Allocation site | Release site | Notes |
|---|---|---|---|
| RDA_OPEN_CONTEXT | RdaDispatchCreateInner / OpenTarget | CLEANUP release | per-handle, no kernel-side refs survive CLOSE |
| RDA_XFER_CONTEXT + forward IRP | RdaForwardSynchronous | same function, all paths incl. cancel | single owner (dispatcher); cancel touches ctx only after CancelDone |
| 0x800 session bitmap | RdaSessionOpen | RdaSessionDestroy | NUL-padded; head doubles as the flush path (reference parity) |
| Skip bitmap / plan | RdaSessionStartBackup | FreePlan (finalize/close/rebuild) | freed under plan swap on every error path |
| Pump MDL | RdaSessionStartBackup | FreePlan | unmap -> unlock -> free-MDL order |
| COW blocks | RdaSessionCowSave | RdaSessionFreeCow / destroy | byte-capped at 64 MiB/session |
| Pump nodes | enqueue paths | dequeue/cancel/drain | free exactly once: cancel removes from queue, worker claims via cancel-swap, drain at destroy |
| Per-disk cache entries | RdaDiskTargetAcquire | cache shutdown / disk REMOVE | referenced DOs, evicted LRU at 32 |
| Filter extension | AddDevice | REMOVE | detached+deleted after lower completion |

Double-free analysis: every free above is guarded by a nulling assignment or runs
exactly once by construction (queue nodes: the cancel-swap winner is the only freer;
`RdaSessionFreeSlot` marks Active=0 under the table lock so a racing CLOSE+CLEANUP
cannot double-destroy). UAF analysis: IRPs are never completed while a forward IRP
is outstanding (MORE_PROCESSING + dispatcher-owned frees); the parked-write IRPs
never touch the session after the worker claims them via the cancel swap.

## Verification performed

- Line-by-line decompile cross-check (docs/audit/2026-10-22-decompile-reverification.md):
  every contract constant re-derived from the raw binaries with Capstone
  (scripts/verify/verify_reference_binaries.py - 56/57 checks green; the remaining
  one is a compiler-encoding artifact documented in the script).
- ASan+UBSan on the entire portable logic layer (grammar classifier, parser, token
  transform): fuzz/ selftest 4019 adversarial inputs, zero findings; libFuzzer round
  in CI (ubuntu job).
- MSVC /W4 /WX + CodeQL on every push; WDK ApiValidator pass; PE/import gate
  (Win7-safe allowlist, now 14 audited additions with per-import justification).
- Driver-vs-driver runtime comparison + hostile IOCTL hammer via the benchmark
  workflow (contract: cross-driver SHA-256 equality must be exact, fuzz rounds must
  complete with zero hangs; a hung or bugchecked runner surfaces as a job failure).

## Residual risks (documented, accepted)

1. The COW cache is capped, not unbounded like the reference's urgent-block list;
   an external writer flooding an active session's range faster than the pump drains
   it gets STATUS_INSUFFICIENT_RESOURCES after the cap. Deliberate: kernel memory
   is finite and a recovery environment must not OOM the box.
2. `DbgPrintEx` tracing remains compiled-in (reference parity; level-gated to errors
   by default). WPP/ETW is the roadmap item.
3. The session engine is served on the control device whenever `SessionsEnabled=1`
   (default). Hostile-input surface is bounded: every command validates lengths and
   handles before touching memory; the fuzzer in CI exercises the full table.
