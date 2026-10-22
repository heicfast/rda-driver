# RDA — Unified Raw Disk Access Driver — Requirements (authoritative)

Source: user prompt (session 2). Token redacted. Do not alter semantics.

## Mission
Complete full re-write, as a SINGLE kernel driver in C + WDK, covering Windows 7, 8, 10, 11,
merging: **EPMNtDrv** (raw access gate) + **EUEDKEPM** (second access gate) + **EUDCPEPM**
(session/replication engine). **EuMrx EXCLUDED.** All functions and features preserved
(exact), with the errors in the original design FIXED. Production-grade, senior-level
architecture and code quality.

## Hard requirements
1. New proper repository: structure, documentation, build plan, dependencies.
2. Latest stable C and WDK; industry-standard, production-grade approaches.
3. Windows/Ubuntu/etc GitHub Actions runners for compiling, testing, benchmarking,
   building — local env is Linux; use workflows; NO shortcuts, NO fallbacks, NO compromises.
4. No errors, no warnings, no unsafe practices. Realistic testing and benchmarking.
5. Follow Microsoft official documentation and guidelines.
6. Same setup as the reference drivers (behavioral/contract parity), but with design errors fixed:
   - F1  512-byte sector hardcode → geometry-aware (512e/4Kn correct)
   - F2  Pseudo-security PID token → + real SDDL/admin gating
   - F3  GetProcName/GetFileObjName info-leak IOCTLs → admin-gated
   - F4  No IRP cancellation → cancel support
   - F5  Kernel path-string parsing → keep compat grammar + explicit IOCTL open
   - F6  AddDevice patching of foreign drivers → documented UpperFilters class-filter attach
   - F7  DbgBreakPoint paths in release → removed
   - F8  Proper PnP/Power handling incl. PoStartNextPowerIrp for Win7
   - F9  Cleanup ordering (context free on CLEANUP, not CLOSE)
   - F10 METHOD_NEITHER/buffered/direct pass-through validation
   (registry to be finalized in docs/error-fix-registry.md)
7. Signing infrastructure: implement latest architecture (researched in depth), but DO NOT
   ENABLE (no certificate yet). User will apply to ossign.org (Open Source cross-platform
   code signing) after implementation/testing/validation completes. Study these repos and
   implement analogous architecture (disabled):
   - https://github.com/OSSign/template-installonly
   - https://github.com/OSSign/template-simple
   - https://github.com/OSSign/OSSign
   - https://github.com/OSSign/scheiblingco--dnstui  (live example of their signing)
   Check their actions, logs, workflow results.
8. Maintain a brief worklog in the repo; push often (session-loss protection); detailed
   commit messages for context.
9. No hallucination: verify and validate independently against the RE corpus and Microsoft docs.
10. Process: get context → plan → review/cross-check → build. Run for hours. Push ASAP.

## Compatibility contracts to preserve (from verified RE)
- Device naming derived from service registry path (uppercase last component) — enables
  drop-in as `eprdtdrv` (DRW Device.mo), `ebrntdrv`/`epmdkdrv` (WinPE), `EUEDKEPM`-style names.
- Open grammar: \\.\{SYM}\<PID-TOKEN>\Volume\{N} and \\.\{SYM}\<PID-TOKEN>\{disk}\{part}
  (+ EUEDKEPM's \<token>\<disk> 2-segment variant).
- PID-token transform (both sides): b0 | (b0+b1)<<8 | (b1+b2)<<16 | (b2+b3)<<24 (PID bytes LE, 8-bit wraps).
- ReadFile/WriteFile: length in 512-byte sectors, offset = absolute byte offset; Information = len<<9.
- IOCTLs 0x60002400 (GetProcName), 0x60002404 (GetFileObjName), 0x60002408 (GetDiskContextMode);
  everything else passes through to the resolved target's top-of-stack.
- Target resolution: \Device\HarddiskVolume%u (top-of-stack); \Device\Harddisk{d}\Partition0
  with \Device\Harddisk{d}\DR{p} fallback; stack walk-down + \Driver\Disk verification (mode flag).
- EUDCPEPM protocol on control device: IoctlBase-normalized 15 commands 0x800C2AC8–0x800C2B38
  (GET_VERSION/OpenSession/CloseSession/GETNEXTBLOCK/GET_PROGRESS/direct+sized sector R/W/CANCEL…),
  CSession magic 0x74534298, 0x840-byte session, 301-kick budget; disk-class UpperFilter role
  (BOOT_START in WinPE, DeviceName/IoctlBase registry params); magic 0xD2C8E4C5 handshake.
- WinPE deployment: pre-registered via .reg (regdrv.reg-equivalent), no signature enforcement issues.

## Deliverables
- Git repo (GitHub, under heicfast) with: driver source, UM test client, unit tests,
  docs (architecture/protocol/security/win7/build/testing/signing), CI/CD (Actions),
  benchmark harness, VM/self-hosted test automation, OSSign-style signing pipeline (disabled),
  release pipeline, worklog, README, LICENSE.
- CI green: build matrix (x64, debug+release), zero warnings (/W4 /WX + /external:W0),
  CodeQL, unit tests passing on hosted runners, PE/import Win7-allowlist gate passing.
- Release artifact: one .sys (+ INFs + client + docs) loadable Win7 SP1 → Win11
  (attestation-signable; test-signed in CI test env).

## Decisions made by user
- Merged driver: EPMNtDrv + EUEDKEPM + EUDCPEPM. EuMrx excluded.
- Signing disabled until user receives OSSign approval. Use our API key (token) if needed for research.
- Do not ask questions; execute. Senior production-grade, no vibe-code.
