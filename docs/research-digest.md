# RDA Research Digest (Phase 2+3) — toolchain, CI, signing

## A. Toolchain decision (researched 2026-10, verified against MS docs + runner-images)

### WDK state of the world
- Latest stable WDK line: 10.0.28000.x (RTM + QFEs; pairs with VS2026 toolset v14.50).
  Previous stable line: 10.0.26100.x (Win11 24H2; pairs with VS2022 v143).
- VS2026 WDK support was broken mid-2025, fixed later (developercommunity #10973856 Closed-Fixed);
  microsoft/Windows-driver-samples now builds on `windows-2025-vs2026` runners with
  WDK NuGet 10.0.28000.2526.
- ALL legacy WDKs (≤22H2/2004-era) were REMOVED from Microsoft downloads (Jul 2025).
  NuGet feed only goes back to 26100-era. → The "officially-supported Win7 target WDK" era is over.
- WDK 24H2+ dropped x86 kernel development (irrelevant — x64 only).
- WDK NuGet feed versions (Microsoft.Windows.WDK.x64): 10.0.26100.1→.6584, 10.0.28000.1-RTM→.2526.
- Official CI pattern (microsoft/Windows-driver-samples): packages.config + `nuget restore
  .\packages.config -PackagesDirectory .\packages\` + Directory.Build.props importing
  `packages\Microsoft.Windows.WDK.x64.<ver>\build\native\*.props` + msbuild.
- GitHub runners: windows-2025 dropped bundled WDK (actions/runner-images#13071); NuGet is the
  sanctioned path. windows-2022 retains VS2022 (+ currently a WDK 10.1.26100 install, not relied upon).

### Windows 7 target reality (decision)
- Modern WDK `_NT_TARGET_VERSION` enums list only Windows 10/11 (per DriverGeneral.xml used by
  Get-NtTargetVersions.ps1) — no Win7 target officially.
- BUT the reference drivers themselves prove the viable path: eprdtdrv.sys built 2022 with a
  modern toolchain, PE header OS=6.1, 41 Win7-era imports, runs Win7→Win11 (win7older = same
  bytes, different signature chain). The single binary is toolchain-feasible; signature policy
  is the only divergence (handled at signing stage).
- RDA approach: build with latest stable WDK NuGet, override `NTDDI_VERSION=0x06010000` /
  `_WIN32_WINNT=0x0601` / `WINVER=0x0601` for header gating, pin PE fields
  `/osversion:6.1 /subsystem:native,6.01` (linker options), use ONLY Win7-SP1-safe APIs,
  and ENFORCE via a CI verification gate: parsed PE imports must ⊆ Win7 allowlist
  (extracted from reference binaries) + PE OS fields must equal 6.1. This converts
  "should work on Win7" into a machine-verified property on every build.
- CI matrix: PRIMARY shipped build = windows-2022 + VS2022 v143 + WDK NuGet 10.0.26100.6584
  (conservative toolchain); SECONDARY = windows-2025-vs2026 + VS2026 + WDK NuGet 10.0.28000.2526
  (modern track, compile-check + parity gate) — if that image label is unavailable at runtime,
  keep primary only and document.
- EWDK ISO option documented as alternative for offline build labs (LaunchBuildEnv.cmd).

### Signing state (for docs/signing.md)
Microsoft driver-signing requirements (MS Learn, verified):
- Win10 1607+ (client): kernel drivers must be Microsoft-signed via Hardware Dev Center
  (attestation signing = EV cert + submission, no HLK needed; or HLK-tested for WHQL "certified").
  Cross-signed drivers blocked (except: PCs upgraded from ≤1511, SecureBoot off, or
  pre-2015-07-29 end-entity certs chained to supported cross CA).
- Win7/8/8.1: HCK/HLK dashboard signing OR SHA-1 cross-sign (the grandfathered path the
  reference "win7older" file uses).
- SHA-2 support on Win7 requires KB4474419 (2019).
- Test/dev: testsigning / bcdedit, or VS-provisioned test certs; Driver Verifier for QA.
- WDK/CI: signtool from the SDK; for releases: attestation requires Hardware Dev Center
  (EV cert + company registration) — later-stage item for the user.
- OSSign: free code signing for qualifying OSS; signs PE/COFF (+ MSI, PowerShell) via
  keyless OIDC trusted-publishing (OSSign Server), Azure Trusted Signing, Azure KeyVault,
  or local cert. NOTE (documented honestly): an OSSign Authenticode signature is NOT a
  Microsoft kernel-mode signature; on Win10/11 it satisfies user-mode binaries and
  test-signing deployments; full retail kernel loading on Win10+ still requires
  Hardware Dev Center attestation/HLK. On Win7/8/8.1 OSSign-signed drivers load if the
  cert chains appropriately (equivalent to cross-sign). We implement the pipeline to be
  signing-method-agnostic.

## B. OSSign architecture (from the 4 repos + live example)
- Model: OSSign hosts a MIRROR of the project (e.g. OSSign/scheiblingco--dnstui). Their
  server (ossign-server) dispatches two workflows in the mirror with
  `ref/sha/release_name/dispatch_id` (workflow_dispatch):
  1. review.yml — checks out the PINNED SHA of the SOURCE repo (git init + fetch depth 1 +
     rev-parse verify), runs scanners (gitleaks 8.21.2, osv-scanner 1.9.1 — pinned versions),
     uploads JSON reports to `OSSIGN_SERVER/api/v1/reviews/<dispatch_id>/uploads` with the
     job's OIDC token (audience = OSSIGN_SERVER).
  2. sign.yml — same pinned checkout; build in-workflow; sign via `ossign/ossign@1.3.1`
     action (tokenType ossignServer, key from OSSIGN_KEY var, metadata dispatch+sha);
     `environment: signing` gated by their deployment protection rule until review approved;
     verify via `ossign verify`; fetch review report (OIDC) from
     `/api/v1/reviews/<id>/report/{review-report.json,md,review-scans.zip,.json.p7s}`;
     publish GitHub release (softprops/action-gh-release@v2) with report as body.
- Contract elements marked [DO NOT CHANGE]: run-name with [dispatch_id], 4 inputs,
  env vars SOURCE_REPO/OSSIGN_SERVER/OSSIGN_KEY (repo Variables), permissions
  `contents: write, id-token: write`, `environment: signing`, pinned-SHA checkout,
  at least one signing step through the ossign action.
- installonly variant: `installOnly: true` installs CLI + config; build tool invokes
  `ossign -t pecoff -o <file> <file>` per artifact (good for our multi-artifact build:
  sign .sys + .cat + UM client).
- RDA implementation (DISABLED until user approval):
  * `signing/ossign/sign.yml` + `signing/ossign/review.yml` — exact contract, build adapted
    to our WDK NuGet build, fileType pecoff, all [DO NOT CHANGE] markers preserved.
  * `.github/workflows/ossign-dispatch.yml` — placeholder wiring doc + disabled guard
    (`vars.OSSIGN_ENABLED == 'true'`), so nothing runs until the user sets repo vars
    (SOURCE_REPO/OSSIGN_SERVER/OSSIGN_KEY) + enables.
  * CI already runs the SAME scanners OSSign uses (gitleaks + osv-scanner) so reviews pass
    on first submission.
