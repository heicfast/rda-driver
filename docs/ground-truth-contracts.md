# RDA Ground-Truth Contracts — Verified Against Decompiled Reference Drivers

> SOURCE OF TRUTH for the RDA rewrite. Every constant below was re-verified directly from
> `easeus-drw-research/re-workspace/reversed/ghidra-drivers/{eprdtdrv,EUEDKEPM,EUDCPEPM}_decompiled.c`
> and the driver binaries themselves (PE/imports/certs), NOT copied from prose artifacts.
> Two errors found in prior research artifacts are explicitly CORRECTED here.

Reference roles being merged:
- EPMNtDrv (eprdtdrv.sys / eprdtdrv_win7older.sys / ebrntdrv.sys / epmdkdrv.sys) — raw disk gate
- EUEDKEPM.sys (EuDskAcs) — second raw gate (subset grammar)
- EUDCPEPM.sys (EuBackup) — disk-class upper filter + copy-session engine (15-cmd protocol)

Excluded by decision: EuMrx.sys (NAS RDBSS redirector).

---

## 1. Identity, naming, and deployment (EPMNtDrv + EUEDKEPM)

### 1.1 Device naming (service-name derived) [VERIFIED: eprdtdrv FUN_000121a4]
```
dev_name  = "\Device\"      + UPPERCASE(last path component of DriverEntry RegistryPath)
dos_name  = "\DosDevices\"  + UPPERCASE(same)
fallback  = "EPMNTDRV"      (when RegistryPath NULL / Length < 2 wchars / empty component)
```
- RegistryPath scanned BACKWARD for last `\` (0x5C); each char appended via RtlUpcaseUnicodeChar.
- IoCreateDevice(DriverObject, ExtSize=0, &dev_name, FILE_DEVICE_UNKNOWN (0x22), 0, Exclusive=FALSE, &devObj)
- IoCreateSymbolicLink(&dos_name, &dev_name); on failure IoDeleteDevice (driver fails).
- DeviceObject->Flags |= DO_DIRECT_IO (0x10).
- Consequence: service `eprdtdrv`→\Device\EPRDTDRV, `ebrntdrv`→EBRNTDRV, `epmdkdrv`→EPMDKDRV,
  any `%s%d` numbered variant gets its own device identity (hot-upgrade without reboot).
- EUEDKEPM variant [VERIFIED: EUEDKEPM FUN_000119bc region]: registry `DeviceName` value →
  `\Device\%s` + `\DosDevices\%s` (EUDCPEPM uses `\DosDevices\%s1`). RDA: honor BOTH
  (service-name scheme for compat; optional `DeviceName` registry override).

### 1.2 Dispatch table (WDM, raw IRP majors) [VERIFIED]
| Slot | IRP major | Reference behavior | RDA |
|---|---|---|---|
| DriverUnload | — | delete symlink+device, free names (log "[EPMNtDrv]DriverUnload called") | keep (plus filter teardown) |
| 0x70 | IRP_MJ_CREATE | path grammar + token + target resolution | keep + grammar superset |
| 0x80 | IRP_MJ_CLOSE | free ctx, deref | MOVE resource release to CLEANUP, keep CLOSE minimal |
| 0x88 | IRP_MJ_READ | sector-forward via async FSD IRP | keep + cancel + pass-through global-handle mode |
| 0x90 | IRP_MJ_WRITE | twin of READ | keep + global-handle set mode |
| 0xE0 | IRP_MJ_DEVICE_CONTROL | 3 custom IOCTLs + pass-through | keep + session protocol (merged) |
| 0x100 | IRP_MJ_CLEANUP | trivial complete | release target refs here (FIX) |

NOTE/CORRECTION-1: prior artifact called slot +0x100 "IRP_MJ_DIRECTORY_CONTROL". It is
IRP_MJ_CLEANUP (0x70 + 0x12*8 = 0x100). RDA docs state the correct major.

### 1.3 Deployment profiles (drop-in)
| Service name as installed | Device | Replaces | Consumers |
|---|---|---|---|
| eprdtdrv | \Device\EPRDTDRV | live DRW gate | Device.mo (`\\.\EPRDTDRV\%d\%d`, `\Volume\%d`) |
| ebrntdrv / epmdkdrv | EBRNTDRV/EPMDKDRV | WinPE spares | PE failover host |
| EUEDKEPM-style | \Device\<DeviceName reg> | dormant 2nd door | EPM/Todo-Backup lineage |
| epmdiskcopydrv (BOOT_START disk UpperFilter) | filter on every disk DO | EUDCPEPM PE role | copy chain (15-cmd protocol) |

---

## 2. Open grammar + PID token (shared auth handshake)

### 2.1 PID token transform [VERIFIED identical in eprdtdrv CREATE + EUEDKEPM CREATE + Device.mo client]
```
pid  = (u32)PsGetCurrentProcessId();   b0..b3 = little-endian bytes
TOKEN = b0 | (b0+b1)<<8 | (b1+b2)<<16 | (b2+b3)<<24   // 8-bit wrapping adds
```
- Path's FIRST numeric segment (chars[0..first-`\`) parsed base-10 via RtlUnicodeStringToInteger;
  compare 32-bit with TOKEN; mismatch → STATUS_INVALID_PARAMETER (0xC000000D).
- The `\` scan starts at index 1 (a leading `\` is tolerated but empty token then fails).
- Anti-abuse properties: binds the open path to the CALLING process's PID (recomputed at IRP
  time). NOT a real security boundary — RDA adds SDDL + admin gate (fix F2) while keeping the
  handshake for compat.

### 2.2 Grammar (superset — RDA supports all reference variants)
```
\\.\{SYM}\<PID-TOKEN>\Volume\<N>       → EPMNtDrv volume branch
\\.\{SYM}\<PID-TOKEN>\<disk>\<part>    → EPMNtDrv disk branch (part# used for DR-fallback naming)
\\.\{SYM}\<PID-TOKEN>\<disk>           → EUEDKEPM branch (2-segment)
\\.\{SYM}                              → "global" handle (identity IOCTLs + global-handle modes)
```
No-path/empty open (FileName.Length < 2 wchars): CREATES the handle with NO target context
("global" mode). EPMNtDrv requires Length ≥ 2 wchars to have a target; otherwise the handle
still completes SUCCESSFULLY with NULL context in the reference (checked: empty name →
`goto LAB_00011277` with uVar14=0xC000000D when FileObject missing... actually: Length<2 →
reject). RDA: match reference — Length < 2 wchars → STATUS_INVALID_PARAMETER (except via
explicit no-path opens the clients do; Device.mo always passes a path).

### 2.3 Volume branch (EPMNtDrv) [VERIFIED: eprdtdrv CREATE branch A]
1. Remaining path after `\<token>` must contain `\Volume` (7-wchar literal) with >8 wchars after token segment.
2. Parse N (base 10). NUL-termination copied to temp buffer first.
3. `RtlStringCbPrintfW("\\Device\\HarddiskVolume%u", N)` → IoGetDeviceObjectPointer(name, 0, &fileObj, &devObj).
4. ObfReferenceObject(fileObj); FO->FsContext = fileObj.
5. top = IoGetAttachedDeviceReference(devObj).
6. ctx (16B, tag 'esdr') = { PDEVICE_OBJECT top; LONG mode=0 } → FO->FsContext2. Information=0, status=0.
- Failure at any point: STATUS_INVALID_PARAMETER; log `[GetVolumeDeviceObejct] %ws open error 0x%x,that's it!` (vendor typo preserved in our compat log strings, flagged in docs).

### 2.4 Disk branch (EPMNtDrv `\<disk>\<part>`) [VERIFIED: branch B]
1. Parse disk# (base 10, must be ≤ 199 → else INVALID_PARAMETER). part# parsed after (any 32-bit).
2. `\Device\Harddisk%u\Partition0` → IoGetDeviceObjectPointer; on failure retry `\Device\Harddisk%u\DR%u`
   (SAME disk# twice — the legacy DR device), then give up: `[GetDiskDeviceObejct] ... that's it!`.
3. ObfReferenceObject(fileObj) → FsContext.
4. top = IoGetAttachedDeviceReference(diskDO); walk DOWN (IoGetLowerDeviceObject loop):
   - ObQueryNameString(layer) into 0x200 buffer; if name contains L"\Device\Harddisk" (wcsstr):
     mode = (RtlCompareUnicodeString(layer->DriverObject->DriverName, L"Disk", TRUE) != 0) → stop.
   - Free the name buffer each step; keep references sane.
5. ctx = { found_layer; mode } → FsContext2. Status 0.
- Semantic: skip any filter layers above the first "\Device\Harddisk"-named device (e.g. EUDCPEPM
  filter DO in PE) — the IO target is the partition/disk-class device, NOT top-of-stack.
- mode: 0 = driven by \Driver\Disk (disk.sys), 1 = otherwise. Exposed via IOCTL 0x60002408.

### 2.5 Disk branch (EUEDKEPM `\<disk>`) [VERIFIED: EUEDKEPM FUN_000110f8]
1. Same PID token gate.
2. Parse disk# ≤ 99 (note: 100 vs EPMNtDrv's 200).
3. `\Device\Harddisk%u\Partition0` only (NO DR fallback).
4. Walk DOWN from top: stop at first layer whose DriverObject->DriverName == "Disk" (case-insens).
5. FsContext2 = the disk-class layer device ITSELF (referenced via IoGetLowerDeviceObject chain);
   FsContext = fileObj from the open. NO mode context.
- In RDA the merged driver: `\<disk>` variant → EUEDKEPM semantics; `\<disk>\<part>` → EPMNtDrv semantics.

---

## 3. READ / WRITE contract (DO_DIRECT_IO)

CORRECTION-2 (critical): the prior artifact claimed "read length is expressed in sectors of
512 bytes". BYTE-LEVEL VERIFICATION OF BOTH SIDES proves:
- Client (Device.mo FUN at ~57004): `ReadFile(h, buf, chunkBytes)` where chunkBytes =
  chunkSectors × sectorSize — **BYTES**. Accumulates returned bytes, finally divides total
  by sectorSize.
- Driver (eprdtdrv FUN_00011fd8/00011de4): forwards `Parameters.Read.Length` (**BYTES**) as the
  async-FSD length to the disk stack; on success reports `Information = Length << 9` (×512).
- Net contract: buffer receives exactly Length BYTES from the target; the reported
  lpNumberOfBytesRead is 512× actual. Legacy clients rescale (÷512). Any other reading of the
  artifact would cause a 512× buffer overflow.

### 3.1 READ with target [VERIFIED]
```
buffer = MmMapLockedPagesSpecifyCache(Irp->MdlAddress, KernelMode, MmCached,...)
         if (Mdl->MdlFlags & 5) == 0   // not (MAPPED_TO_SYSTEM_VA|SOURCE_IS_NONPAGED_POOL)
         else Mdl->MappedSystemVa       // RDA: MmGetSystemAddressForMdlSafe — semantics equal, safer
offset = Parameters.Read.ByteOffset (signed check; < 0 → STATUS_INVALID_PARAMETER)
length = Parameters.Read.Length
irp = IoBuildAsynchronousFsdRequest(IRP_MJ_READ, ctx->target, buffer, length, &offset, &iosb)
IoSetCompletionRoutine(..., FltReadWriteSectorsCompletion, &event, TRUE,TRUE,TRUE)  // Control=0xE0
IofCallDriver(ctx->target, irp); PENDING → KeWaitForSingleObject(event)
success → Irp->IoStatus.Information = (u64)length << 9
```
- Completion routine (FltReadWriteSectorsCompletion): frees bounce buffer if ctx flag 0x20,
  walks MDL chain (MmUnlockPages + IoFreeMdl per link), logs errors, writes {status, info} to
  submitter's result slot + KeSetEvent when signaled, IoFreeIrp, return
  STATUS_MORE_PROCESSING_REQUIRED (0xC0000016).
- No IRP cancellation in reference (hang risk on dead disks). RDA FIX F4: cancel support.

### 3.2 WRITE with target
Identical twin with IRP_MJ_WRITE(4); failure log
`[epmntdrvDispatchWrite] Write error 0x%x,%u,%I64u,0x%x` (status, len, offset, target).

### 3.3 Global-handle modes (context-less opens) [VERIFIED — new detail not in artifacts]
- WRITE, no FsContext2 target, Parameters.Write.Length == 4: store first DWORD of mapped user
  buffer into the driver global `g_GlobalHandle`.
- READ, no target, g_GlobalHandle != 0, out length > 0x207 (≥ 0x208): resolve
  GetFileObjName(g_GlobalHandle, buffer) → name of the stored handle; Information = len+2.
  (This is the GetDriverInfo handshake: user mode parks a kernel handle and reads its name.)
- RDA keeps both modes (compat), gates the set-mode to admin (F3).

---

## 4. IOCTL contract (control device)

Codes: CTL_CODE(0x600, fn, METHOD_BUFFERED, FILE_ANY_ACCESS). Dispatch order [VERIFIED]:
```
target = FsContext2 ? *(FsContext2) : NULL
if (target == NULL):                      // global handle
    0x60002400 GetProcName | 0x60002404 GetFileObjName | else STATUS_INVALID_PARAMETER
else:                                    // target-bound handle
    0x60002408 GetDiskContextMode | else → pass-through
```
(GetProcName/GetFileObjName on a TARGET-BOUND handle fall through to pass-through — harmless.)

| IOCTL | In | Out | Semantics |
|---|---|---|---|
| 0x60002400 GetProcName | 4 bytes: u32 PID (InputBufferLength==4) | ≥0x208: image path WCHAR | NtOpenProcess(pid, 0x20000) + ZwQueryInformationProcess(ProcessImageFileName=0x1B, buf 0x400); copy+NUL; Information = pathBytes+2. RDA: PsLookupProcessByProcessId + SeLocateProcessImageName (documented APIs, same result), admin-gated. |
| 0x60002404 GetFileObjName | 4 bytes: u32 HANDLE | ≥0x208: full NT path | ObReferenceObjectByHandle(h, 0x80000000, *IoFileObjectType, KernelMode) → ObQueryNameString(FileObject->DeviceObject) + RtlAppendUnicodeStringToString(FileObject->FileName); copy+NUL; Information = bytes+2. |
| 0x60002408 GetDiskContextMode | — | exactly 4 bytes | *SystemBuffer = ctx->mode (LONG at ctx+8); Information = 4. |
| anything else (with target) | per-method | per-method | pass-through to IoGetAttachedDeviceReference(ctx->target) top; IoBuildDeviceIoControlRequest(code, top, SystemBuffer, inLen, SystemBuffer, outLen, FALSE, &event, &iosb); wait; Information = iosb.Information; ObDereferenceObjectDeferDelete(top). RDA FIX F10: honor buffered vs direct vs neither properly (buffered: SystemBuffer/2; direct: in=SystemBuffer, out=Irp->UserBuffer; neither: reject INVALID_DEVICE_REQUEST, documented). |

---

## 5. Copy-session protocol (EUDCPEPM merge) — control-device private protocol

### 5.1 Code normalization [VERIFIED: EUDCPEPM MainDispatch FUN_000120f8]
```
custom = (u32)(ioctl_code - IoctlBase)
IoctlBase: registry DWORD "IoctlBase" under the service key; DEFAULT 0 if absent
           (regdrv.reg sets 0x10000 in the PE deployment)
custom range served: 0x800C2AC8 … 0x800C2B38 (15 commands)
non-IOCTL majors: forwarded; other IOCTL codes: pass-through to disk stack (traced)
```
Router stub: `DeviceObject->DeviceType == 0x800C` → session dispatch; else forward path.
(RDA: control DO uses FILE_DEVICE_UNKNOWN 0x22 like EPMNtDrv for the compat door; the
session protocol is dispatched by code range on the control device; the FILTER role creates
its own device objects. Wire compat maintained: same normalized codes.)

### 5.2 Command table [VERIFIED buffer gates + handlers]
| custom | name | Gate | Behavior |
|---|---|---|---|
| 0x800C2AC8 | GET_VERSION | out ≥ 0x84 | writes 0x00010100 then 0x2E-byte string "EASEUS Todo Backup Driver (c) Ea…"; RDA: same version number, our product string (documented divergence), same layout |
| 0x800C2AD0 | OpenSession | out ≥ 0x840 | creates CSession; validates; overlap-checked; see 5.3 |
| 0x800C2AD8 | session op | in ≥ 8 | FUN_0001590c(session) control op (run/pause family) |
| 0x800C2AE0 | session op 2 | in ≥ 0x28 | FUN_0001601c(session, in, out) parameterized session command |
| 0x800C2AE8 | IOCTL_GETNEXTBLOCK | in ≥ 0x1E | async pump: IRP queued pending; completed by read path; worker kicks bounded 0x12D (301) |
| 0x800C2AF0 | session status | in ≥ 8 | returns u32 at session+0x100 (state code) |
| 0x800C2AF8 | GET_PROGRESS | in > 0xB | out+8 = u32 percent = bytesDone(+0xE8) × 100 / totalBytes(+0xF0) |
| 0x800C2B00 | CloseSession | in ≥ 8 | magic check session+0x28 == 0x74534298; destructor; ExFreePool; status 0 |
| 0x800C2B0A | direct sector read | in > 0x10 | {u32 diskId, u32 sectorCount, u64 offset, data…}; bounds devSectorSize(+0x98)×count+0x10 ≤ outLen |
| 0x800C2B12 | direct sector write | in > 0x10 | twin of 0xB0A (write direction) |
| 0x800C2B18 | op mode 4 | out ≥ 0x1C, in > 3 | mode-4 control (flush/unlock family) |
| 0x800C2B20 | op mode 3 | out ≥ 0x1C?, in > 3 | lock/hold family (3/4 pair) |
| 0x800C2B2A | sized transfer | in > 0x10 | unit-size probe then unit×count+0x10 ≤ outLen |
| 0x800C2B2E | sized transfer 2 | in > 0x10 | twin of 0xB2A |
| 0x800C2B38 | CANCEL/ABORT | in ≥ 8 | spinlock; session+0x38 = 3 (abort state); worker kick budget 301 |
Session validity: every handler dereferences in[0] as session ptr and checks
`*(u32*)(session+0x28) == 0x74534298`; failures → STATUS_INVALID_HANDLE (0xC0000008) or
DbgBreakPoint on GETNEXTBLOCK path (RDA FIX F7: return STATUS_INVALID_HANDLE, no breakpoint).

### 5.3 OpenSession input/output layout (0x840 bytes, METHOD_BUFFERED) [VERIFIED]
```
in/out (overlaid buffer):
+0x000 u32 diskId            (resolved: \Device\Harddisk{diskId}\Partition0 family)
+0x004 u64 DataFirstSec      (copy range start sector)
+0x00C u64 tSecs             (total sectors; ≠0 required)
+0x014 u64 extentParam1      → block-map builder
+0x01C u64 extentParam2      → block-map builder
+0x024 u64 bitmapSize        (≠0 required)
+0x02C u32 bitmapCount       (≠0 required)
+0x030 u32 spbIn             (0 → driver picks: tSecs<0x20 → 1 else 0x10; tail=tSecs&0xF)
+0x034 0x800 bytes block bitmap (bit per copy block; copied to session; NUL pad at 0x7FE)
+0x834 u64 OUT: session handle (ptr) [RDA: opaque 64-bit handle, not raw pointer]
+0x838 u32 OUT: effective spb
+0x83C u32 OUT: sector size (device +0x98)
```
Overlapping-range guard [VERIFIED, NEW]: OpenSession walks the driver's device list under
mutex; if an ACTIVE session covers an overlapping sector range on the same diskId →
STATUS_SHARING_VIOLATION (0xC0000043). RDA keeps this exclusivity model.

### 5.4 CSession object (reference layout, 0x840-ish allocation) [VERIFIED ctor FUN_00014f0c]
```
+0x000 PDEVICE_OBJECT target
+0x018 devExt (device parameters; sector size at devExt+0x98)
+0x020 block bitmap (0x800, pool tag 'ECLU' 0x4C435545)
+0x028 magic 0x74534298 ("tSB\x98" Todo-Backup-Session)
+0x030 state (0x38 after ctor; 3 = abort)
+0x050 semaphore (init 0, max 0x4000)  +0x90 mutex
+0x0C8 u32 sectorSize                   +0xCC u32 spb     +0xD0 u32 tailSectors
+0x0D8 u64 DataFirstSec                  +0xE0 u64 tSecs
+0x0E8 u64 bytesDone                     +0x0F0 u64 totalBytes
+0x100 state code (returned by 0x800C2AF0)
+0x138 worker (event at worker+0x38, callback-driven)
+0x148 1 MiB transfer buffer (size at +0x150)
+0x158 lookaside / context nodes
+0x160 secondary buffer 0x1B580 (≈2000 × 56B IRP-context nodes)
ctor log: "CSession::CSession DataFirstSec=%I64u tSecs=%I64u spb=%u"
```
RDA implements an equivalent state machine with its own layout (public wire contract above is
what must match), with cancel-safe pending-IRP queue under spinlock (list at +0x40/0x48,
spinlock +0x50, kick counter +0x80 cap 0x12D), pagefile-region block for urgent IRPs
("ProcessUrgentIrp pagefile bk" — urgent reads into pagefile-backed ranges are rejected),
ownIRP reentrancy counter (session+0x88 vs cap at +0x80).

### 5.5 GETNEXTBLOCK pump [VERIFIED]
1. IRP-context node from session lookaside (fail → STATUS_INSUFFICIENT_RESOURCES 0xC0000017).
2. Mark pending: SL_PENDING_RETURNED + IoStatus.Status = STATUS_PENDING (0x103). IRP NOT completed.
3. Insert into session pending queue (doubly-linked, spinlock-guarded).
4. Kick worker bounded: `if (kick++ < 0x12D) kick_worker()`.
5. Return STATUS_PENDING; read path completes queued IRPs as blocks arrive; bytesDone bookkeeping
   drives GET_PROGRESS. AddUrgentIRP variant inserts at queue HEAD with explicit
   (startSector, sectorCount, sectorSize).

---

## 6. Filter role (EUDCPEPM merge, WinPE/PE mode)

### 6.1 Reference deployment (regdrv.reg, BUILDPE)
- `epmdiskcopydrv` = disk-class UpperFilter, `UpperFilters` on GUID_DEVCLASS_DISKDRIVE, BOOT_START.
- IoCreateDevice(FILE_DEVICE_DISK (7), ext 0x130, chars 0x100); Flags DO_DIRECT_IO (+0x2000, clear ~0x80);
  IoAttachDeviceToDeviceStack into every disk stack at PnP AddDevice.
- Sector-size probe IOCTL_DISK_GET_DRIVE_GEOMETRY_EX (0x700A0) → trace "add device sectorsize=%u".
- Magic handshake: writes 0xD2C8E4C5 + callback pointer at +0x38 into ITS OWN device extension
  (RDA: provide equivalent discovery handshake on our filter extension).
- AddDevice-hook patching of OTHER drivers (DrvHookNextAddDevice) — NOT carried over
  (RDA FIX F6: documented UpperFilters class-filter registration only).
- VolSnap attach (\Driver\VolSnap) for snapshot coherence — RDA: optional, parameter-gated.
- Power IRPs: reference uses PoCallDriver + PoStartNextPowerIrp (legacy style, required on Win7).
  RDA: always call PoStartNextPowerIrp (no-op on Win8+, REQUIRED on Win7) + forward.

### 6.2 Service parameters (RDA, Parameters subkey — all optional)
```
DeviceName      REG_SZ   override device-name scheme (EUEDKEPM compat)
IoctlBase       REG_DWORD session-protocol code base (default 0; PE sets 0x10000)
FilterMode      REG_DWORD 1 → attach as disk-class upper filter when AddDevice fires
VolSnapAttach   REG_DWORD 1 → also attach VolSnap devices (PE parity)
MaxDisks        REG_DWORD default 200 (eprdtdrv grammar bound)
SectorEmulate   REG_DWORD default 0 → reject 4Kn disks; 1 → transparent 512e emulation layer
Sddl            REG_SZ   device DACL override (default admin/SYSTEM only — FIX F2)
DebugLevel      REG_DWORD 0..5 trace verbosity (DbgPrintEx component)
```

---

## 7. Security posture

Reference drivers: NO device ACL (IoCreateDevice default), PID-token pseudo-gate only,
identity IOCTLs callable by anyone who can open the device.
RDA hardening (documented deviations, all admin-friendly):
- IoCreateDeviceSecure with default SDDL "D:P(A;;GA;;;BA)(A;;GA;;;SY)" (admin+system full),
  overridable via Parameters\Sddl. Standard users cannot open the device at all.
- PID-token handshake retained (compat) but no longer load-bearing.
- Identity IOCTLs (GetProcName/GetFileObjName) available only through the (admin-only) device.
- Global-handle WRITE mode (stores arbitrary handle) additionally gated by SeAdminCheck.
- No DbgBreakPoint/KeBugCheckEx on request paths (FIX F7); bugcheck only via /GS cookie
  handler (unavoidable, standard).

## 8. Verified reference import sets (Win7-safe allowlist)
eprdtdrv/41 imports (saved scripts/ref_imports.json, union of all six = 75).
RDA driver must import only Win7-SP1 ntoskrnl exports; CI gate compares final binary imports
against this allowlist + documented additions (IoCreateDeviceSecure, SeLocateProcessImageName,
PsLookupProcessByProcessId, IoSetCancelRoutine, IoGetCurrentIrpStackLocation-family, etc. —
all present since Win7/XP era; gate script allowlist = ref union + audited additions).

## 9. Toolchain ground truth (reference binaries)
- eprdtdrv family: VS2019-era toolchain (strsafe/GS fingerprints), OS ver 6.1 in PE header,
  x64, /GS, no CFG (DllChars 0x9000: NX_COMPAT|INTEGRITYCHECK), Authenticode SHA-256(WHQL)
  or SHA-1(DigiCert) — same bytes, two signature chains.
- EUDCPEPM/EUEDKEPM: VS2008-era, fre_wlh, OS 6.0, DllChars 0x5000/0x9000.
- RDA target: latest stable WDK that can emit Win7-loadable x64 binaries (researched in
  Phase 2), /W4 /WX clean, /GS, /guard:cf where toolchain permits without breaking Win7 load,
  OSVERSION/SUBSYSTEM fields pinned like the reference (6.1/native), pool tag 'rda1'.
