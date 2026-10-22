# Benchmarking RDA

The engagement's benchmark requirement: install OUR driver and the ORIGINAL
reference binaries on a real Windows runner, seed a disk with realistic
multi-format file content, and measure cold start, throughput, latency and
contract behavior across drivers with everything recorded. The pipeline below
is that requirement, implemented.

## Pipeline (.github/workflows/benchmark.yml)

Runs on `windows-2022` against every `src/**` push (plus manual dispatch):

1. **Build** — NuGet-pinned WDK 26100.6584, Release, then the Win7 stamp +
   PE/import gate (identical discipline to CI).
2. **Reference binaries** — fetched at RUN time from the research corpus
   (never committed to this repository): `eprdtdrv.sys` (Microsoft
   WHQL-counter-signed — loads on stock Windows), `EUEDKEPM.sys`,
   `EUDCPEPM.sys` (SHA-256 recorded in the log).
3. **Test-signing** — job-local self-signed code-signing certificate,
   imported into `LocalMachine\Root` + `TrustedPublisher`; hosted runners
   run with SecureBoot off, so the classic test-certificate flow needs no
   testsigning reboot. Our binary is signed with it for the session only.
4. **Seed disk** — 4 GiB dynamic GPT VHDX with two volumes (NTFS + FAT32)
   and a realistic corpus: JPEG files (real SOI/JFIF/EOI markers + payloads),
   PDF, MP4 (ftyp box), a real ZIP (compressed entropy), a 20k-line text
   log, and 1000 small files — so raw sector reads see realistic
   entropy/metadata patterns, not zeroes.
5. **Install both drivers under distinct service identities** — `eprdtdrv`
   (the original) and `rdatest` (ours). The service-name-derived device
   naming keeps both live side by side: `\\.\EPRDTDRV` vs `\\.\RDATEST`.
6. **Run the matrix** (`rdabench`, see below) against each driver.
7. **Report** — every mode emits JSON lines; the workflow builds a markdown
   comparison table into the job summary, asserts **cross-driver byte
   equality** (SHA-256 over every 1 MiB range — any mismatch fails the job),
   and uploads `bench-results/**` as a 30-day artifact.

## rdabench (src/bench/rdabench.c)

One binary drives ANY wire-compatible driver through its device name,
using the exact reference grammar (PID token + disk/part segments):

| Mode | Measures |
|---|---|
| `open` | cold-open latency through the token grammar; 2000 iterations (mean ns + ops/s) |
| `seq` | sequential read throughput at 1 MiB and 64 KiB blocks over a 512 MiB span |
| `rand` | random-offset IOPS + mean latency at 4 KiB and 64 KiB (deterministic LCG seed) |
| `info` | contract probes: geometry pass-through, GET_PROC_NAME on the global handle, ReadFile Information scaling, open/close churn |
| `verify` | SHA-256 per 1 MiB range — cross-driver CONTENT EQUALITY proof |
| `fuzz` | hostile IOCTL hammer (valid + invalid codes, random lengths incl. boundary sizes); survival + rate. The driver must answer with NTSTATUS failures, never hang |

All timings use `QueryPerformanceCounter`; all buffers are page-aligned with
`FILE_FLAG_NO_BUFFERING` so the comparison is kernel-path honest.

## Manual runs

```powershell
# both drivers against disk N (find with Get-Disk after Mount-VHD):
.\bin\x64\Release\rdabench.exe --device EPRDTDRV --disk 1 --mode seq --mb 512 --run ref-seq
.\bin\x64\Release\rdabench.exe --device RDATEST   --disk 1 --mode seq --mb 512 --run ours-seq
.\bin\x64\Release\rdabench.exe --device EPRDTDRV --disk 1 --mode verify --mb 64 --run ref-hash
.\bin\x64\Release\rdabench.exe --device RDATEST   --disk 1 --mode verify --mb 64 --run ours-hash
```

## Expectations (verify against results, don't assume)

- Large sequential reads: our path costs one extra IRP build + one MDL map +
  a forward, like the reference; expect parity within measurement noise
  for 1 MiB blocks and >= 90% of direct `\\.\PhysicalDriveN` throughput.
- 4 KiB random reads: dominated by the VHDX-backed disk latency, not the
  dispatch path; driver deltas should be small (µs-class per-op overhead:
  allocation + completion + Information scaling).
- Cold open: the reference resolves `\Device\HarddiskN\Partition0` and walks
  the stack with ObQueryNameString per open; we added a geometry probe
  (F1). Expect a small fixed per-open overhead delta; the contract fixes
  (cancellation, SDDL) do not touch this path.
- Byte equality: MUST be exact — the two drivers read the same sectors
  through equivalent resolution chains. A mismatch is a P0 bug, and the
  workflow fails the job.

## Fuzzing (fuzz/, wired into CI)

- **libFuzzer over the exact CREATE-path logic** (grammar classifier, parser,
  token transform, wire-struct invariants): bounded 60-second rounds under
  ASan+UBSan. Current CI round: ~48.5M executions at ~800K exec/s, coverage
  plateau cov:86/ft:265 with a 112-entry corpus, **zero crashes**.
- **Invariant selftest** (gcc path, no libFuzzer needed): 4019 adversarial
  inputs — grammar shapes, random blobs, boundary lengths — zero failures
  under ASan+UBSan.
- **Kernel-side hammer**: `rdabench --mode fuzz` drives the REAL driver
  (arbitrary IOCTL codes/lengths) from the benchmark runner — a hang or
  bugcheck surfaces as a failed job (the runner stops responding), and the
  50k-round survival count + rate are recorded per driver.
