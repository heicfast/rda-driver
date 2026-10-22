# Windows 7 SP1 → Windows 11 from one binary

## The problem

Windows 7 driver *targets* no longer exist in modern WDKs: since the 2004-era WDK the
`_NT_TARGET_VERSION` enumeration only lists Windows 10/11, all legacy WDK downloads were
retired (2025), and the NuGet WDK feed starts at 26100. Meanwhile Windows 10 1607+ requires
Microsoft-signed (attestation/HLK) kernel drivers, while Windows 7 needs HCK or SHA-1-era
cross signing — the *signature* story is a per-OS deployment decision, not a code problem
(see docs/signing.md).

## The RDA position

The reference drivers themselves prove the approach: `eprdtdrv.sys` was built in 2022 with
a then-modern toolchain, declares **OS 6.1** in its PE header, imports only 41
Win7-era `ntoskrnl` exports, and ships for Win7 → Win11 (the "win7older" file is the same
bytes, differently signed).

RDA turns that observation into a machine-verified build contract:

1. **Source discipline** — kernel code uses only APIs present since Windows XP/2003
   (`ExAllocatePoolWithTag`, never `ExAllocatePool2`; no Win8+ kernel APIs anywhere).
   `NTDDI_VERSION=0x06010000` (`NTDDI_WIN7`), `_WIN32_WINNT=0x0601`, `WINVER=0x0601` are
   pinned in the project so the WDK headers gate to Win7 semantics (verified: the 26100
   headers accept `NTDDI_WIN7` and only reject *below* it).
2. **PE header contract** — linked with `/osversion:6.1 /subsystem:native`, matching the
   reference binaries' declared OS version.
3. **The gate** — `tools/verify_pe.py` runs on every CI build *before* artifacts are
   accepted:
   - imports ⊆ Win7-safe allowlist = the 75-function union extracted from the six reference
     binaries **plus** a small audited addition list (`IoCreateDeviceSecure`,
     `PsLookupProcessByProcessId`, `SeLocateProcessImageName`, `IoSetCancelRoutine`,
     `IoCancelIrp`, `KeWaitForMultipleObjects`, `KeInitializeSemaphore`,
     `RtlIntegerToUnicodeString`, `DbgPrintEx`) — every one an XP-era export, each with a
     stated reason in the script;
   - machine = AMD64, subsystem = NATIVE, OS version = (6, 1).
   A single stray import fails the build. "Should run on Windows 7" becomes a checked
   property, updated consciously through the allowlist file.
4. **Toolchain** — primary artifact built with the conservative stable pair
   (VS2022 v143 + WDK/SDK `10.0.26100.6584` NuGet, `WindowsTargetPlatformVersion` pinned to
   the package build so tool paths resolve inside the restored content).

## What is NOT claimed

- A binary built this way still needs the *signature policy* satisfied per OS
  (Win10/11: attestation/HLK through the Hardware Dev Center; Win7: HCK output or the
  SHA-1 cross-sign grandfather). See docs/signing.md.
- We do not run on Windows 7 x86 (x64 only, like the primary reference artifacts).
- Runtime testing on Win7 happens on the self-hosted VM matrix
  (scripts in `scripts/` + docs/testing.md); hosted CI compiles and gates but cannot
  load kernel drivers.
