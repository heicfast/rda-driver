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
