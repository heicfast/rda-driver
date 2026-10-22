# Testing RDA

Testing is layered so hosted CI catches everything it can, and a Windows test host
(or VM) covers what CI cannot (loading a kernel driver).

## Layer 1 — portable contract tests (run on every push: Linux gcc + Windows MSVC)

`tests/unit/test_compat.c` compiles the shared pure-logic layer (`rda_compat.h`) and locks:

- the PID-token transform (including 8-bit wrap cases and an independent byte-wise
  cross-check),
- the decimal range-parser edge matrix (whitespace, sign, overflow rejection, empties),
- the open-grammar classifier (volume / 3-segment disk / 2-segment EUEDKEPM variant /
  global-mode short names / rejects, including the separator-inclusive volume gate
  boundary verified against the reference decompile),
- the frozen wire tables (IOCTL codes, session command codes, `RDA_OPEN_SESSION`
  byte offsets and total size via compile-time asserts + runtime checks).

This layer has zero kernel dependencies — it exists precisely so wire-contract
regressions are impossible to merge silently.

## Layer 2 — build + artifact gates (CI, windows-2022)

- `/W4 /WX` clean build of both configurations, MSVC v143 + WDK NuGet 26100.6584.
- `tools/verify_pe.py`: Win7 import allowlist + PE header contract (machine AMD64,
  OS 6.1, NATIVE subsystem) + no-signature assertion.
- CodeQL static analysis on the C sources.
- clang-format check (include order frozen; sorting is semantic in kernel C).

## Layer 3 — driver-loaded integration (Windows test host)

Prerequisites: elevation, test-signing enabled (`bcdedit /set testsigning on` + reboot)
or a provisioned test certificate, driver installed via `scripts/install.ps1`
(e.g. `-ServiceName eprdtdrv` for the DRW-compatible device name).

Run the suite:

```powershell
.\scripts\run-integration.ps1 -Client .\bin\x64\Release\rdacli.exe -Disk 0
```

Cases:

1. `info` — extended identity + capability IOCTLs on a bare open.
2. `grammar <disk>` — all three open grammars + mode query + the wrong-token negative
   test (must fail).
3. `read <disk> <off> <len>` — raw sector read through the driver, with the legacy
   `×512` Information scaling observed.
4. `ident <pid>` — GetProcName identity service.
5. `session <disk> <start> <secs>` — copy-session engine: OpenSession (validating the
   `0x840` wire struct), GETNEXTBLOCK pump rounds, GET_PROGRESS, CLOSE_SESSION.
6. `bench read <disk> <secs> [chunk]` — throughput vs a direct `\\.\PhysicalDriveN`
   baseline (see benchmarking.md).

### Recommended host matrix

| Host | Purpose |
|---|---|
| Win11 + Hyper-V, testsigning on | primary functional matrix |
| Win10 22H2 + Driver Verifier (special pool, IRQL checks, deadlock detection, force pending) | verification matrix; run the full suite under verifier |
| Win7 SP1 x64 VM (test-signed via legacy chain or WDAC/test policy) | loads the same artifact; validates the PE-contract claim end to end |
| WinPE (built from scripts/winpe profile) | filter-role attach, copy-engine path, PE-only behavior |

Driver Verifier settings for the verification host: verify `rda.sys`, enable special
pool, IRQL enforcement, pool tracking, deadlock detection, IRP logging and forced
pending requests. The session-engine and cancel paths are designed for these checks.

## Layer 4 — self-hosted CI (optional)

The same integration suite can run on a self-hosted GitHub runner (Windows, admin,
test-signing): `run-integration.ps1` exits non-zero on any failure and emits per-case
PASS/FAIL. Wire it by adding a `workflow_dispatch` job that targets a runner labeled
`self-hosted windows driver-test`.
