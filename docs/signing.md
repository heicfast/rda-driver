# Signing — research, policy, and the (disabled) pipeline

## 1. What Microsoft requires (verified October 2025–2026 documentation)

| Target OS | Kernel driver accepted signatures | Notes |
|---|---|---|
| Windows 10 1607+ (client, Secure Boot) | **Hardware Dev Center dashboard-signed only**: attestation signing (EV code cert + submission; no HLK needed) or HLK-tested "certified" | Cross-signed drivers blocked (upgraded-from-1511 PCs and Secure-Boot-off machines exempt); SHA-256 |
| Windows 8 / 8.1 | HCK/HLK dashboard signed **or** SHA-256 Authenticode cross-signed (EV grandfather window ended 2021+) | |
| Windows 7 SP1 | HCK dashboard signed **or** SHA-1 Authenticode cross-signed by a Microsoft Code Verification Root cross-CA | SHA-256 signatures verify only with KB4474419 (2019) applied |
| Windows 7 RTM/SP1 unpatched | SHA-1 chains only — the reference product ships a *separately signed copy of the same binary* for exactly this reason | |

Key facts that shaped this design:

1. The **"Windows 7 build" of the reference driver is the same compiled bytes** with a
   SHA-1 DigiCert cross-signature, while the "modern" copy carries the Microsoft WHQL
   (Third Party Component CA 2014) SHA-256 signature. One code file, two signature
   chains — RDA keeps exactly one code artifact and treats signing as a deployment step.
2. Microsoft **retired the cross-signing program** (roots delisted 2021+); no CA will issue
   new SHA-1 kernel cross-certificates. Consequence: *new* Win7 retail distribution is
   effectively frozen with whatever grandfathered chains exist; everything else is
   HCK-era packages or test-signing profiles.
3. **Attestation signing** (the pragmatic retail path for Win10/11) requires: a registered
   Hardware Dev Center organization + an **EV code signing certificate**; submissions are
   signed by Microsoft (SHA-256 chain, `Windows Hardware Compatibility Publisher`).
4. During development, **test-signing** (`bcdedit /set testsigning on`) or a VS-provisioned
   test certificate is the only way a locally built driver loads — hosted CI runners
   cannot enable test signing (no reboot), so CI compiles and gates but never loads.

## 2. RDA's signing architecture (method-agnostic by design)

- The build **never signs** (`SignMode=Off`; CI asserts the artifact carries no signature
  table). Reasons: (a) reproducible, byte-comparable artifacts; (b) signing authority
  belongs to the release pipeline, not the toolchain; (c) no accidental test-signing noise
  in the PE gate.
- `tools/verify_pe.py` runs **before** any signing step in every pipeline: a signature is
  only ever applied to a binary whose import set and PE header contract are proven.
- The release pipeline stages `rda.sys` + `rdacli.exe` + INF + SHA256SUMS unsigned.

## 3. OSSign integration (prepared, DISABLED)

[OSSign](https://ossign.org) provides free code signing for qualifying open-source
projects — including **driver binaries** — via a *keyless, OIDC trusted-publishing model*:
their server dispatches a mirror-repository workflow with a **pinned commit SHA**, an
automated review (gitleaks + osv-scanner, versions pinned by their rule) gates a protected
`signing` environment, and the `ossign` action signs artifacts through their server key.

What this repository already has in place:

- `signing/ossign/review.yml` — scanner-report workflow (their template, adapted).
- `signing/ossign/sign.yml` — pinned-SHA rebuild (WDK NuGet + verify_pe gate) + pecoff
  signing through `ossign/ossign@1.3.1` + review-report publication.
- CI already runs the same scanner pair OSSign's review uses.

**Disabled until onboarding completes.** To activate after OSSign approval:

1. OSSign creates the mirror repository and sets repo variables
   `SOURCE_REPO`, `OSSIGN_SERVER`, `OSSIGN_KEY` (on the mirror, per their model — our
   copies serve as the reviewed source of truth for the mirror's workflow).
2. A protected environment named `signing` must exist on the mirror.
3. Their server dispatches `Review` then `Sign release`; nothing on our side holds keys.

### Honest scope note

An OSSign certificate is a standard Authenticode chain — **not** a Microsoft kernel-mode
signature. Concretely:

- On **Win10/11 retail**, an OSSign-signed `rda.sys` still will not load without
  test-signing (or a WDAC policy that trusts the chain). Retail loading on Win10/11
  requires the Hardware Dev Center path (EV cert → attestation/HLK).
- On **Win7/8/8.1**, an OSSign Authenticode signature is loadable exactly like the
  reference product's cross-signed files (that chain class is what those OSes accept).
- For **WinPE** deployments (the copy-engine profile), signature enforcement is relaxed —
  OSSign-signed (or even test-signed) binaries are operational immediately.

The pipeline is intentionally method-agnostic: swapping the sign step to Hardware Dev
Center attestation output (when you register) is a one-step change in `sign.yml`.

## 4. Recommended onboarding order

1. Apply to OSSign (open-source signing) — covers Win7/8/8.1 + PE + test-signed Win10/11
   deployments and gives the repo signed artifacts at zero cost.
2. In parallel, evaluate Hardware Dev Center registration (EV certificate + company
   verification) for Win10/11 retail attestation signing.
3. Optionally pursue HLK certification for the "Windows Compatible" badge (test matrices
   in docs/testing.md align with HLK storage-filter requirements).
