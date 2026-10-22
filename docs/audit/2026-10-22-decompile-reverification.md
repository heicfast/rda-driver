# Session 2 Audit — Line-by-line decompile verification (2026-10-22)

Method: every handler of the three reference drivers re-read directly from the
Ghidra corpus (`re-workspace/reversed/ghidra-drivers/{eprdtdrv,EUEDKEPM,EUDCPEPM}_decompiled.c`),
decoded instruction-by-instruction, and cross-checked against our v0.1.0
implementation. Findings below are grouped G1..G28 (reference-contract gaps) and
S1..S12 (defects in our own code), each with the decompile evidence.

## EPMNtDrv (eprdtdrv.sys)

- Dispatch table (FUN_000121a4): CREATE@+0x70=FUN_000110b0, **CLOSE@+0x80=FUN_000117b8
  (the context release)**, READ@+0x88, WRITE@+0x90, IOCTL@+0xe0,
  **CLEANUP@+0x100=FUN_00011dbc (noop-success)**, Unload@+0x68. All other majors NULL.
  - G1 (docs): our F9 claim "reference released at CLOSE" is CORRECT for both
    EPMNtDrv and EUEDKEPM; worklog wording aligned.
- CREATE (FUN_000110b0):
  - **G2 (bug)**: global-mode gate is `FileName.Length < 2` **BYTES** (= empty name
    only). A 1-wchar name (Length==2, e.g. "X") goes to the scan loop, finds no
    separator at index>=1 and REJECTS with STATUS_INVALID_PARAMETER. Our classifier
    used `Chars < 2` (accepting 1-wchar names as global) — off-by-one. FIXED.
  - Token scan from index 1; token = chars[1..sepIdx-1]; transform verified equal to
    RdaComputePidToken (b0 | (b0+b1)<<8 | (b1+b2)<<16 | (b2+b3)<<24, 8-bit wraps).
  - Volume gate: remainder counted **separator-inclusive** (`remTotal > 8`), literal
    L"\Volume" compared AT the separator, number parsed from sepIdx+8;
    **G3 (bug)**: on number-parse failure the reference sets volume number **0** and
    still opens `\Device\HarddiskVolume0`. We rejected. FIXED (mirror reference).
  - Disk branch: parses the FIRST number of the remainder (RtlUnicodeStringToInteger
    over the whole remainder; stops at non-digit) — **the part number is NEVER parsed
    or used** (confirms our vestigial treatment). `disk > 199` → INVALID_PARAMETER.
  - **G4 (reference bug, documented)**: the DR fallback formats
    `"\Device\Harddisk%u\DR%u"` with **a single vararg** — the second %u prints
    uninitialized stack garbage (Ghidra shows one argument in the va_list). The retry
    therefore essentially never resolves. Our formatter accidentally reproduced the
    broken shape (a literal "DR%u" name). FIXED: format DR{disk} with the disk
    number twice; documented divergence (deterministic instead of garbage).
  - **G5 (exactness)**: the walk's `\Driver\Disk` comparison is against
    **DriverObject->DriverExtension->ServiceKeyName** (`*(drv+0x30)+0x18`), case
    insensitive, vs L"Disk" — NOT DriverName. Since ServiceKeyName is
    "\Driver\Disk", the mode is effectively constant 1 for disk opens in both
    implementations. FIXED to use ServiceKeyName for byte-exact parity.
  - Walk ownership (reference): one reference on the current layer; top reference
    dropped at the match point; on top-match the target is stored UNOWNED (pinned by
    the file object). **G6 (docs)**: our F13 "reference leaks the top ref" claim is
    WRONG — both reference drivers drop the top reference on the found path. Our
    owned-reference discipline kept (strictly safer, same observable behavior);
    error-fix-registry F13 reworded.
  - On no-match: reference binds the stack BOTTOM with garbage mode (dead path in
    practice — the named layer always matches). We return INVALID_PARAMETER
    (documented divergence).
  - **G7**: reference uses `ObDereferenceObjectDeferDelete` for the pass-through
    top; we use ObDereferenceObject (equivalent; noted).
- READ/WRITE (FUN_00011fd8/FUN_00011de4): Length is BYTES; ByteOffset negative →
  INVALID_PARAMETER; forward via IoBuildAsynchronousFsdRequest to the RESOLVED
  target (not top); success → **Information = Length << 9**; failure codes match
  ours; MmMapLockedPagesSpecifyCache vs our MmGetSystemAddressForMdlSafe
  (documented F-fix); the reference NULL-derefs its MDL on zero-length requests —
  we reject zero-length (documented sane divergence, S10).
  - Global modes: WRITE len==4 parks *SystemBuffer into DAT_00015170; READ with slot
    nonzero and out>0x207 resolves the parked handle's object name. MATCHES ours.
- IOCTL (FUN_00011bcc): bound handle → 0x60002408 (out==4 → mode at SystemBuffer[0],
  Information=4) else **pass-through of EVERYTHING incl. 0x60002400/04** to
  IoGetAttachedDeviceReference(target), SystemBuffer both ways (METHOD_BUFFERED
  parity; our method-awareness is the documented F10 improvement). Unbound →
  0x60002400 (in==4 && out>0x207; NtOpenProcess(0x20000) +
  ZwQueryInformationProcess(ProcessImageFileName); Information = len+2),
  0x60002404 (in==4 && out>0x207; ObReferenceObjectByHandle(file) +
  ObQueryNameString(DeviceObject) + append FileName; Information = len+2), else
  INVALID_PARAMETER. MATCHES ours (API-substitution documented).
- Unload (FUN_00011060): delete symlink, delete device, free both names. MATCHES.

## EUEDKEPM (EuDskAcs)

- DriverEntry: REQUIRES service-key `DeviceName` REG_SZ (>=2 bytes); device named
  `\Device\%s`/`\DosDevices\%s` from it; DriverEntry FAILS without it.
  - G9: our Parameters\DeviceName override + service-name derivation is a superset
    (documented).
- CREATE (FUN_000110f8): Length<2 bytes → **INVALID_PARAMETER** (EUEDKEPM rejects
  what EPMNtDrv accepts as global — merged driver follows EPMNtDrv, documented).
  Token transform identical. `disk < 100`. `\Device\Harddisk%u\Partition0` only (no
  DR retry), walk DOWN to first layer with ServiceKeyName == L"Disk"; that layer is
  the target (referenced, dropped at CLOSE). MATCHES ours.
- READ/WRITE: no global modes; byte lengths; Information = Length<<9; forward to the
  Disk layer. MATCHES.
- IOCTL (FUN_00011594): **no custom IOCTLs** — unbound → INVALID_PARAMETER; bound →
  pass-through (SystemBuffer both ways). MATCHES (our identity IOCTLs are additive on
  global handles only).
- CLOSE@+0x80 releases; CLEANUP@+0x100 noop — same slots as EPMNtDrv.

## EUDCPEPM (EuBackup) — the copy engine

- Architecture: one **master dispatch** (FUN_000120c4) on ALL 28 majors:
  `DeviceObject->DeviceType == 0x800C` → control path (FUN_000120f8), else filter
  path (FUN_00012b70). AddDevice=FUN_00012014, PNP=FUN_00012f88, POWER=FUN_00013170,
  Unload=FUN_00011fb4. Control device: ext 0xF8, DeviceType 0x800C, DO_EXCLUSIVE,
  named from service-key DisplayName/DeviceName (control symlink gets a literal "1"
  suffix in `\DosDevices\%s1`).
  - **G11 (P0 architecture bug in ours)**: our driver registered control-device
    handlers (CREATE/READ/WRITE/IOCTL/...) on the whole DriverObject. In filter mode,
    IRPs on the FILTER stacks would hit control handlers and be rejected instead of
    forwarded. FIXED: master-dispatch style routing on
    `DeviceObject == g_RdaControlDevice`; filter devices forward all majors.
- Registry (FUN_00011244): service-key ROOT reads DisplayName, DeviceName,
  **IoctlBase** (REG_DWORD, default 0). G10 FIXED (we read service root, keeping
  Parameters\ as an override for forward-compat).
- Session protocol (control device, codes normalized by -IoctlBase):
  - GET_VERSION 0x800C2AC8: gate **InputBufferLength >= 0x84**; writes 0x00010100 +
    0x2E-byte product string at +4; **Information = 0**. G12 (gates+Information FIXED).
  - OPEN_SESSION 0x800C2AD0: gate **in >= 0x840**; fields {DiskId@0, DataFirstSec@4,
    TotalSecs@0xC, Extent1@0x14, Extent2@0x1C, BitmapSize@0x24, BitmapCount@0x2C,
    Spb@0x30}; nonzero gates on TotalSecs/BitmapSize/BitmapCount; overlap guard on
    same disk (SHARING_VIOLATION); spb: 0 → (tSecs<0x20 ? 1 : 0x10),
    **tail = tSecs & 0xF only when spb input was 0 and tSecs >= 0x20** (G13 FIXED);
    sector size probed per disk (InitSectorSize); 0x800-byte bitmap copy (tag 'ECLU',
    NUL pad @0x7FE); handle at +0x834; **spb written back at +0x30, sector size at
    +0x83C; Information = 0** (G14 FIXED — we reported 0x840).
  - SESSION_OP 0x800C2AD8 (in>=8): **FlushProtectedFile** — opens the file path
    stored at the head of the session's 0x800 buffer, sends IRP_MJ_FLUSH_BUFFERS to
    its volume stack (retry <= 20, tolerating PENDING/0xC0000010/0xC00000A2), state
    {0→1 working, 0 on open-fail, 3 on done/exhaust}, returns 0. IMPLEMENTED
    (was a stub; G15).
  - SESSION_OP2 0x800C2AE0 (in>=0x28): **StartBackup** — state must be 3 else
    STATUS_UNSUCCESSFUL; wire {+0x08 pumpBufferPtr (USER address, locked with an MDL),
    +0x10 pumpBufferBytes (must align spb*sectorSize), +0x14 optional user exclusion
    bitmap ptr (bit count +0x20, ProbeForRead), +0x1C startSector, +0x20 blockCount,
    +0x24 spb must match}; rebuilds regions, total = spb*popcount+start; state→4.
    IMPLEMENTED (was a stub; G16).
  - GETNEXTBLOCK 0x800C2AE8: gates **out >= 0x1E (dispatcher) AND in >= 0x1E
    (worker)**; wire in {handle@0, cursorSector@+8, maxSectors@+0x10}; queued async;
    worker copies min(max, pumpBuf, region-remaining) sectors FROM the source disk
    INTO the locked user pump buffer (LBA offsets × sectorSize); out {+0x14 diskId,
    +0x18 progress%, +0x1C mapBuild%, +0x1D mapOk}; **Information = 0x1E constant**.
    **G17 (semantic rewrite)**: our v0.1.0 pump filled the IRP buffer with block
    data — completely different semantics. REWRITTEN.
  - SESSION_STATUS 0x800C2AF0 (in>=8): returns **the block-map status dword as the
    returned NTSTATUS** (no buffer write). G18 FIXED.
  - GET_PROGRESS 0x800C2AF8 (in>=0xC): **finalize** — state→5, kick, drain, free
    regions + pump-buffer MDL, percent at buffer+8, Information=0. G19 FIXED (was a
    non-destructive percent query).
  - CLOSE_SESSION 0x800C2B00 (in>=8): teardown+free; invalid handle →
    STATUS_INVALID_HANDLE (per-command status differences mirrored).
  - DIRECT_READ 0x800C2B0A / DIRECT_WRITE 0x800C2B12: **METHOD_OUT_DIRECT** —
    header+data live in the **MDL'd output buffer**: {diskId@0, sectorCount@+4,
    lba@+8, data@+0x10}; gate out > 0x10; **offset is LBA (× probed sector size)**;
    per-request disk resolution; bound = sectorSize*count + 0x10 <= out;
    **Information = OutputBufferLength** (always). G20+G21 FIXED (we used
    SystemBuffer + in-gate + byte offsets).
  - SIZED_XFER 0x800C2B2A / SIZED_XFER2 0x800C2B2E: same shape; sector size from a
    per-disk id-indexed global cache (DAT_00020350, 32 entries). IMPLEMENTED via a
    probe-cache.
  - MODE4 0x800C2B18 / MODE3 0x800C2B20 (in>=0x1C, out>=4): **raw paging-IO file
    read/write by handle** {fileHandle@0, userBufPtr@+8, byteOffset@+0x10,
    length@+0x18}; next-stack FileObject = the caller's file object;
    Information = 8 on success. IMPLEMENTED (was a stub; G22).
  - CANCEL 0x800C2B38 (in>=8): state = **3** under spinlock (standby/cancel — NOT an
    "abort" semantic); kick (cap 301); SUCCESS. G23 FIXED.
  - Per-command invalid-handle status codes mirrored (CLOSE/PROGRESS →
    STATUS_INVALID_HANDLE; OP/GETNEXTBLOCK → STATUS_INVALID_PARAMETER).
- Session object facts: 0x1B0 bytes; magic 0x74534298@+0x28; owner process@+0x30
  (IoGetCurrentProcess at create); state@+0x38 spinlock@+0x40; kick semaphore@+0x50;
  a worker-thread object with its own queue + kick counter (cap 301); session
  free-pool of 2000 0x38-byte nodes; 1-MiB transfer buffer; spb@+0xCC;
  DataFirstSec@+0xD8, TotalSecs@+0xE0, bytesDone@+0xE8, total@+0xF0, dest@+0xF8,
  block-map status@+0x100, region objects +0x108/+0x110/+0x118, worker@+0x138.
  - **IRP_MJ_CLEANUP and CLOSE on the control device destroy sessions owned by the
    calling process** (list walk, magic + owner==IoGetCurrentProcess). G24 IMPLEMENTED
    (owner tracking + sweep at CLEANUP/CLOSE).
- Filter role (DeviceType != 0x800C):
  - AddDevice (FUN_00012014): allocates a per-disk wrapper (0xA0), IoAttachDevice,
    writes the discovery magic 0xD2C8E4C5 into the device extension, probes sector
    size (InitSectorSize, cached in the wrapper AND a global id-indexed table).
  - External WRITE with sessions active on that disk → FUN_0001189c: byte range →
    sectors; **state-3 sessions PARK the write** on the worker queue until StartBackup;
    state-4 sessions urgent-process (region lookup, COW save, re-read) then forward.
    IMPLEMENTED (park + region-invalidate; G25).
  - **IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES (Action=Trim) on a disk with an
    active session is SWALLOWED (completed SUCCESS, not forwarded)**. IMPLEMENTED
    (G26).
  - Discovery/handshake on filter devices: 0x800C2AC0 → {buffer[0]=diskId,
    Information=4, re-probe sector size}; 0x800C2B40 with magic "RRWR" →
    {buffer+8 = 0x604, Information=0xC}; 0x800C2B3E (write) / 0x800C2B42 (read)
    RRWR raw disk IO {magic@0, sectorSize@+8 (must match disk), outLen@+0xC (must
    match actual out), lba@+0x10, count@+0x18, data = whole MDL buffer}. IMPLEMENTED
    (G27).
  - Everything else: IoSkipCurrentIrpStackLocation + forward.
  - REMOVE: sessions bound to the removed disk are destroyed (FUN_0001324c).
    IMPLEMENTED.
  - **G28**: the prior artifacts' session-code range 0x800C2AC8..0x800C2B38 missed
    0x800C2AC0 (discovery) and 0x800C2B3E/B40/B42 (RRWR). Our dispatch range and
    shared header widened accordingly.

## Our code defects found during this audit (S-series)

- **S1 (P0)**: `RdaReadWriteCancelRoutine` never released the global cancel
  spinlock (`IoReleaseCancelSpinLock(Irp->CancelIrql)`) → system-wide deadlock after
  the first cancelled READ/WRITE. FIXED.
- **S2 (P0)**: `RdaSessionCancelPumpIrp` had the same spinlock bug AND an
  always-false ownership test (the IO manager already NULLs the routine before
  invoking us) → cancelled pump IRPs were never completed (user thread hang) and the
  cancel spinlock stayed held. FIXED (search; complete when found OR when the worker
  delegated ownership; spinlock released before completion).
- **S3 (P0)**: control-device PnP/Power handlers dereferenced the 0-size control
  extension. Guard `DeviceObject == g_RdaControlDevice` added.
- **S4**: filter REMOVE detached/deleted the filter DO immediately after IoCallDriver
  without waiting for the lower stack (use-after-free window). Event-wait added.
- **S5**: OpenSession leaked the target references when the bitmap allocation failed
  (refs already adopted into the session). FIXED.
- **S6**: OpenSession overlap check + activation were not atomic (TOCTOU). Slot is
  now allocated + range-claimed under one mutex hold.
- **S7**: `TotalBlocks` used a truncating ULONG cast from a 64-bit division. 64-bit
  math with explicit cap.
- **S8**: `RdaCopyUnicodeToBuffer` underflowed `BufferBytes - sizeof(WCHAR)` when
  BufferBytes < 2. Guarded.
- **S9**: `KeAcquireSpinLockAtDpcLevel` used at PASSIVE in the GETNEXTBLOCK enqueue
  (IRQL contract violation). Now `KeAcquireSpinLock`.
- **S10**: zero-length bound READ/WRITE: reference forwards (and crashes on a NULL
  MDL); we reject — kept, documented.
- **S11**: `RdaDispatchPower` on the control device completed INVALID (dead path);
  now completes SUCCESS.
- **S12**: dead code removed (RDA_DP_COMPONENT macro, RDA_PNP_COMPLETION struct,
  unused session FAST_MUTEX).
