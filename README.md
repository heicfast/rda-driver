# RDA — Raw Disk Access Driver

**One unified Windows kernel driver for raw disk/partition/volume I/O and sector-level copy
sessions — a clean-room, contract-exact rewrite merging the roles of three legacy EaseUS
drivers: `EPMNtDrv` (`eprdtdrv.sys`), `EUEDKEPM` (`EuDskAcs.sys`), and `EUDCPEPM`
(`EuBackup.sys`).**

- **Targets**: Windows 7 SP1 → Windows 11, x64 (single binary; WDM, no framework dependency)
- **Language/toolchain**: C17, WDK 10 (NuGet-pinned), MSVC v143/v14.50
- **Quality gates**: `/W4 /WX` zero-warning builds, Win7 import allowlist enforcement on the
  produced PE, CodeQL, clang-format, pure-logic unit tests on every push, driver-level
  integration suite for Windows test hosts
- **Security posture**: SDDL-protected control device (admin/SYSTEM), PID-token handshake kept
  for wire compatibility, hardened identity IOCTLs, IRP cancellation, no bugchecks on request
  paths

> **Status**: active development. See [docs/architecture.md](docs/architecture.md) for the
> full design, [docs/ground-truth-contracts.md](docs/ground-truth-contracts.md) for the
> reverse-engineered wire contracts this driver honors, and
> [worklog.md](worklog.md) for the engineering journal.
>
> **Signing**: the release signing pipeline is present but **disabled** pending certificate
> onboarding (see [docs/signing.md](docs/signing.md)).

## Why

The reference product ships 7 driver binaries for 3 functional subsystems; the raw-access
core alone exists as 4 signed copies of the *same compiled code*. This project proves the
merge: **one** driver, one build, one signature pipeline, all roles — with the original
design errors fixed. The behavioral contracts (open grammar, IOCTLs, sector I/O, the
15-command copy-session protocol) are preserved byte-semantically so existing user-mode
stacks interoperate unchanged when the driver is installed under a compatible service name.

## Quick facts

| | |
|---|---|
| Binary | `rda.sys` (x64, kernel) |
| Control device | `\Device\<UPPERCASE(service name)>` + `\DosDevices\` symlink (service-name derived, like the reference) |
| Drop-in service names | `eprdtdrv` (live DRW), `ebrntdrv` / `epmdkdrv` (WinPE spares), any `name` |
| Open grammar | `\\.\{SYM}\<PID-TOKEN>\Volume\{N}` · `\\.\{SYM}\<PID-TOKEN>\{disk}\{part}` · `\\.\{SYM}\<PID-TOKEN>\{disk}` · bare `\\.\{SYM}` (global-handle modes) |
| Copy protocol | IoctlBase-normalized 15-command session engine (`0x800C2AC8 … 0x800C2B38`) |
| Win7 mode | NTDDI pinned to `0x06010000`, PE OS fields `6.1`, import allowlist gate in CI |

## Repository layout

```
docs/            architecture, protocol, security, win7-compat, build, testing, signing
src/driver/      kernel driver sources (WDM)
src/shared/inc/  public headers shared kernel<->user<->tests
src/client/      user-mode CLI: tests, contract verification, benchmarks
tests/unit/      portable pure-logic tests (run on Linux CI + Windows)
tests/integration/ driver-loaded test suites (Windows test hosts)
tools/           PE/import verification gate + build tooling
scripts/         install/uninstall (SCM + WinPE .reg), VM test automation
signing/ossign/  OSSign-compatible signing workflows (DISABLED until onboarding)
.github/         CI: build matrix, lint, CodeQL, release
```

## Build

Requires: Windows + Visual Studio 2022 (v143) or VS 2026, WDK restored via NuGet
(pinned in [packages.config](packages.config)).

```powershell
nuget restore .\packages.config -PackagesDirectory .\packages\
msbuild .\rda.sln /p:Configuration=Release /p:Platform=x64
```

CI performs the full matrix automatically — see
[.github/workflows/ci.yml](.github/workflows/ci.yml). The produced `rda.sys` is then
validated by `tools/verify_pe.py` (Win7 import allowlist + PE header contract) before any
artifact is published.

## Install (test environments only)

```powershell
# elevated; installs rda.sys as service 'eprdtdrv' → device \Device\EPRDTDRV
.\scripts\install.ps1 -ServiceName eprdtdrv -Source .\bin\x64\Release\rda.sys
```

Kernel drivers must be test-signed (`bcdedit /set testsigning on` + reboot) or properly
signed via the pipeline in [docs/signing.md](docs/signing.md) before Windows 10/11 will
load them. See [docs/testing.md](docs/testing.md) for the full VM-hosted test plan.

## License

MIT — see [LICENSE](LICENSE). This project is an independent clean-room implementation and
is not affiliated with EaseUS or Chengdu Yiwo Tech. EaseUS product names are referenced for
interoperability documentation only.
