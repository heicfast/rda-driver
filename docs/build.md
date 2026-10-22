# Building RDA

## Prerequisites (Windows)

- Visual Studio 2022 (v143 toolset) with the **Windows Driver Kit** VSIX component
  (Individual Components → "Windows Driver Kit"), *or* the standalone WDK 10.
- NuGet (`nuget.exe`) — the WDK/SDK content is restored from the pinned packages in
  `packages.config` (the officially recommended CI pattern; runners no longer bundle a
  standalone WDK).
- MSBuild (inside VS or the Build Tools).

> No EWDK ISO is required; the NuGet path is fully reproducible. An EWDK-based offline
> flow is documented at the end for build labs.

## Build

```powershell
nuget restore .\packages.config -PackagesDirectory .\packages\
msbuild .\rda.sln -m -v:minimal -nologo /p:Configuration=Release /p:Platform=x64
```

Outputs:

- `bin\x64\Release\rda.sys`   — the driver (unsigned by design)
- `bin\x64\Release\rdacli.exe` — user-mode client/test harness

The build is **zero-warning at /W4 /WX**. The only suppression is `C4391`
(wdm.h interlocked-intrinsic prototype mismatch, unfixable from user code — documented
in the project file). WDK/SDK headers are covered by the toolset's `/external` handling.

### What the pinned packages are

`Microsoft.Windows.WDK.x64` + `Microsoft.Windows.SDK.CPP*` version `10.0.26100.6584`
provide the WDK include/lib/build content; the VS component provides toolset plumbing.
`WindowsTargetPlatformVersion` is pinned to `10.0.26100.0` so the WDK tool paths
(stampinf-class tools, if ever needed) resolve inside the package rather than the
machine's installed SDK. Upgrading = edit `packages.config` + `Directory.Build.props`
together, then re-run the PE gate.

## Post-build verification (always on in CI)

```powershell
python tools\verify_pe.py bin\x64\Release\rda.sys
```

Enforces the Win7-loadability contract: AMD64 + NATIVE subsystem + OS version 6.1 and
imports within the reference-derived allowlist (`tools/ref_imports.json` union plus the
audited additions list inside the script).

## Debug vs Release

`Debug` adds full PDBs and bound-checked pool behavior via Driver Verifier-friendly
allocation discipline; both configurations produce the same wire contracts.

## Offline / EWDK alternative

For air-gapped build labs: mount the matching EWDK ISO, run `LaunchBuildEnv.cmd`, then
`msbuild` from that environment with the same project files (the NuGet restore step is
unnecessary there because the EWDK contains the kits; keep `WindowsTargetPlatformVersion`
aligned with the EWDK's build number).

## Layout

```
rda.sln
Directory.Build.props          WDK/SDK NuGet imports (pinned)
packages.config                 WDK 26100.6584 + SDK pair
src/driver/                     kernel driver (rda.vcxproj)
src/client/                     rdacli (rdacli.vcxproj)
src/shared/inc/                 wire-contract headers shared KM/UM/tests
tests/unit/                     portable contract tests (gcc + MSVC + CTest-style)
tools/                          verify_pe.py + allowlist data
scripts/                        install/uninstall/integration (PS)
signing/ossign/                 OSSign workflows (disabled until onboarding)
```
