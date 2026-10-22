# Benchmarking RDA

## Model

The interesting cost question for this driver is overhead vs direct raw access: the
driver sits between a client's `ReadFile` and the disk stack (MDL map + async forward +
legacy Information scaling), so the practical benchmark compares:

1. **Driver path** — `\\.\EPRDTDRV\<token>\<disk>` reads through rda.sys
2. **Baseline path** — direct `\\.\PhysicalDriveN` reads, same chunk size

Both through the same `rdacli bench read` implementation (QPM-style sequential reads,
perf-counter timings), so the harness differences are eliminated.

## Running

```powershell
# 128-sector (64 KiB) chunks over 64 MiB on disk 0:
.\bin\x64\Release\rdacli.exe bench read 0 131072 128

# chunk-size sweep:
4,16,64,128,256,512 | % { .\bin\x64\Release\rdacli.exe bench read 0 131072 $_ }
```

Reported: bytes, wall-clock seconds, MB/s for each path, plus the delta.

## Expectations (verify against results, don't assume)

- Large sequential reads (≥64 KiB): driver overhead is one extra IRP allocation + one
  MDL mapping per request — expect ≥90% of baseline throughput.
- Small chunks: fixed overhead dominates; this driver is not the bottleneck for the
  reference clients (their scan IO uses ≥64 KiB chunks; verified in Device.mo).
- Copy-session pump: streaming throughput should track raw device speed; the pump adds
  one completion + wake per block.

## Benchmark protocol for releases

Run on the verification host (quiet disk, no AV real-time scan on the target volume):

1. Three warm-up passes, then five measured passes; take the median.
2. Record OS build, disk model, sector size (512/4Kn), chunk sweep results.
3. Attach results to the release notes (the release workflow stages SHA256SUMS; drop
   benchmark JSON next to it).

## Regression policy

A release is blocked if the driver path drops below 85% of baseline on the 64 KiB
sequential case on the reference test host.
