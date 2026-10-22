# RDA Worklog

Engineering journal for the RDA driver rewrite. Most-recent first. Every push lands with
detailed commit messages; this file is the human-readable narrative.

## Session 1 (2026-10-22) — bootstrap

- Cloned + re-verified the full reference corpus (easeus-drw-research):
  decompiled eprdtdrv/EUEDKEPM/EUDCPEPM, raw binaries, artifacts.
- Extracted byte-exact wire contracts; found 2 corrections vs prior research artifacts
  (IRP_MJ_CLEANUP slot ID; READ/WRITE length unit = BYTES with ×512 Information scaling).
- Locked toolchain: WDK 10 via NuGet (26100.6584 primary / 28000.2526 secondary), VS2022 v143,
  NTDDI pinned 0x06010000 for Win7 SP1→Win11 single binary, machine-verified import gate.
- Repo created (public, for OSSign eligibility + free Windows CI minutes).
- Foundation files: LICENSE (MIT), docs, formatting, CI scaffolding to follow.

## Session 1 (cont.) - shared contract layer + portable tests GREEN

- src/shared/inc/rda_ioctl.h: public wire contract (3 reference identity IOCTLs,
  3 extended RDA IOCTLs, 15 session codes, RDA_OPEN_SESSION packed(4) wire struct
  with compile-time offset asserts).
- src/shared/inc/rda_compat.h: portable pure-logic grammar (RdaParseUnsigned
  RtlUnicodeStringToInteger-compatible; RdaClassifyOpenPath implementing the
  verified open grammar incl. volume-gate boundary; RdaComputePidToken as an
  inline FUNCTION - the macro form had int-promotion shift UB).
- Third correction found vs research artifacts: the EUDCPEPM OpenSession effective-spb
  OUT lives at +0x30 (the input slot); +0x838 is unused padding. C_ASSERTs enforce it.
- tests/unit/test_compat.c: 40+ assertions across token transform (incl. 8-bit wrap),
  parser edge cases, classifier volume/disk/global/reject matrix, volume-gate
  boundary, IOCTL table freeze. Portable: gcc C11 u"" literals / MSVC L"".
- Verified green on gcc -Wall -Wextra -Werror (Ubuntu). MSVC parity via CI next.

## Session 1 (cont.) - CI green end-to-end

Bring-up iterations on the windows-2022 WDK NuGet toolchain (each found by the
CI itself, fixed at the root cause):

1. clang-format `Standard: cpp17` invalid -> `c++17`; unstable keys dropped;
   then `SortIncludes: Never` after the include-order landmine (below).
2. Unit-test harness: C4127 suppression (do{}while macro idiom), bin dir.
3. WDK NuGet plumbing: `WindowsTargetPlatformVersion` pinned to the package
   build (TRK0005 stampinf), INF moved out of the Inf item group (no INF
   tooling in build; shipped verbatim), shared headers via
   AdditionalIncludeDirectories.
4. THE BIG ONE: wdm.h, included first, DEFINES _NTDDK_ - silently neutering
   the later ntddk.h (every DDK-level declaration vanished -> C4013 batch).
   Root cause: clang-format SortIncludes had moved rda_trace.h's wdm.h ahead
   of ntddk.h. Fix: ntifs.h is the canonical base header in rda_p.h
   (ntddk -> wdm order guaranteed, plus the ntifs APIs this driver uses);
   rda_trace.h no longer includes wdm.h; SortIncludes: Never forever.
5. Kernel-C corrections: PBYTE->PUCHAR, LONG_MAX->0x7FFFFFFF, ntdddisk.h for
   DISK_GEOMETRY, W4 residuals (unused params/locals), /W4 C4391 header
   suppression (documented), DriverTargetPlatform=Desktop (ApiValidator is a
   Universal/DDI regime - not applicable to a WDM raw-storage driver).
6. Win7 PE contract: the WDK toolset links OS=(10,0) regardless of linker
   flags -> tools/stamp_osversion.py stamps (6,1)/NATIVE + recomputes the
   checksum, wired into CI+release before the gate.
7. Import gate: extended the audited additions with wdmsec.lib's full
   XP-era SD/security import closure (each entry justified in
   tools/verify_pe.py).

FINAL STATE: full CI green - lint (gcc unit tests + clang-format),
unit (MSVC /W4 /WX), build Debug+Release (rda.sys + rdacli, /W4 /WX,
PE gate, unsigned assertion, artifacts), codeql.

Next: release tag pipeline validation, VM/host test matrix, OSSign
onboarding (disabled by design until certificate approval).

## Session 2 - full decompile re-verification + contract corrections

- Read ALL THREE reference driver decompiles line-by-line again (eprdtdrv,
  EUEDKEPM, EUDCPEPM - 14k lines), decoded every dispatch slot, every
  command gate, and the session engine internals from scratch.
- 28 reference-contract gaps (G1..G28) + 12 self-audit defects (S1..S12)
  documented in docs/audit/2026-10-22-decompile-reverification.md.
  Headline corrections vs both our v0.1.0 AND the prior research artifacts:
  * The session protocol has 18 codes, not 15 (discovery 0x800C2AC0 +
    RRWR family 0x800C2B3E/B40/B42 were missed by earlier research).
  * GETNEXTBLOCK is a kernel-side COPY PUMP into a StartBackup-registered
    user buffer; the IRP only returns a 0x1E metadata record
    (Information = 0x1E constant). Our v0.1.0 pumped data into the IRP
    buffer - completely different semantics.
  * GET_PROGRESS is the FINALIZE command (state 5, frees plan + MDL).
  * Direct/sized commands are METHOD_OUT_DIRECT with LBA offsets; gates on
    the OUTPUT length; Information = outLength always.
  * SESSION_OP = volume flush of a protected file; SESSION_OP2 = StartBackup
    with a 0x28-byte wire input; MODE3/MODE4 = raw paging-IO file R/W.
  * CANCEL sets state 3 (standby) - the state machine is
    0 created / 1 flushing / 3 standby / 4 copying / 5 done.
  * Sessions are owned by the creating process and swept at CLEANUP/CLOSE.
  * The filter: parks external writes on standby sessions, COW-saves ranges
    covered by active sessions, swallows TRIMs, serves discovery + RRWR.
  * Reference dispatch table: CLOSE carries the release, CLEANUP is the
    noop (both EPMNtDrv + EUEDKEPM) - F9 wording corrected, F13 claim
    withdrawn (the reference walks are balanced after all).
- Architecture fix G11 (P0): master dispatch (reference FUN_000120c4
  model) - control handlers can never again run on filter stacks.
- Security fixes S1/S2 (P0): both cancel routines now release the global
  cancel spinlock; the pump cancel routine owns completion on every path
  (v0.1.0 deadlocked the system on first cancelled IO).
- New rda_disk.c: per-disk target cache (session/direct/RRWR resolution
  works in BOTH live-OS and WinPE filter roles).
- Classifier: 1-wchar names now REJECT (reference gate is Length<2 BYTES);
  volume-number parse failure falls back to volume 0 (reference-exact).
- Wire structs for GETNEXTBLOCK/StartBackup/MODE3/4 added with
  compile-time offset freezes; unit tests extended (new codes + layouts).
- Import gate: +14 audited Win7-safe ntoskrnl exports (session engine needs).

## Session 2 (cont.) - independent RE verification + bench/fuzz infrastructure

- Installed pefile + capstone; built scripts/verify/verify_reference_binaries.py
  (56/57 green against the raw reference binaries). Two earlier decompile-based
  interpretations corrected by raw disassembly:
  * G4: the DR retry passes the disk number as BOTH varargs (vararg1 r9d +
    vararg2 [rsp+0x20]) - Ghidra's 4-param helper view hid the second. Our
    (disk, disk) formatter is byte-exact reference behavior.
  * The kick cap compiles to cmp x,300 (source < 0x12D).
  * Product string: 'EASEUS Todo Backup Driver (c) EaseUs Co. 2008' (ASCII,
    46 bytes).
- New rdabench client (src/bench): one JSON-emitting binary drives ANY
  wire-compatible driver (ours, eprdtdrv, EUEDKEPM) - open/seq/rand/info/
  verify/fuzz modes; verify mode emits per-range SHA-256 for cross-driver
  byte-equality proof.
- benchmark.yml: NuGet WDK build -> test-sign (job-local self-signed cert,
  Root+TrustedPublisher, SecureBoot-off runners = no reboot) -> seeded
  4 GiB GPT VHDX (NTFS+FAT32, realistic JPEG/PDF/MP4/ZIP/text/small-file
  corpus) -> original eprdtdrv + our rda.sys under distinct service names ->
  full matrix on both -> markdown comparison + hash-equality verdict +
  fuzz hammer -> artifacts. First runs are iterating on CI (expected).
- fuzz/: libFuzzer harness over the exact CREATE-path logic (kind
  enumeration, volume fallback, first-number coherence, token transform)
  + gcc selftest (4019 adversarial inputs, ASan+UBSan, zero findings) +
  CI fuzz job (ubuntu, installs clang, 60s bounded round).
- Security review formalized: docs/audit/2026-10-22-security-review.md
  (S1..S12 with severity + the full resource-lifetime inventory table).
- MSVC /W4 /WX residuals fixed (unused locals in StartBackup/InterceptWrite,
  filter START param); BCryptCreateHash arity fixed; clang probe in the fuzz
  job. Lint + MSVC unit tests green; driver build iterating in CI.
