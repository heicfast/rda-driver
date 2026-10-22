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
