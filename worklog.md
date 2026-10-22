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
