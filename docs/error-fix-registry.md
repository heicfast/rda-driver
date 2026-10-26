# Error-Fix Registry — RDA vs. the reference drivers

Every entry below is a verified defect (or deliberate divergence) in the reference
drivers, with the RDA resolution. Wire-visible contracts are preserved; internal defects
are fixed. Cross-references: `docs/ground-truth-contracts.md`, `docs/architecture.md`.

| # | Reference defect / gap | Evidence | RDA resolution | Wire-visible? |
|---|---|---|---|---|
| F1 | 512-byte sector hardcode: READ/WRITE and the copy engine assumed `len<<9` semantics on 4Kn-native media; main gate never probed geometry (the copy engine did, proving awareness) | eprdtdrv decompile `Information = Length << 9`; Device.mo rescaling | per-handle logical-sector-size probe at CREATE (`IOCTL_DISK_GET_DRIVE_GEOMETRY`); 4Kn supported; offsets stay absolute bytes | No (improved correctness) |
| F2 | No device ACL: control device created with `IoCreateDevice` default security; any process that could open the device could issue raw-sector and identity IOCTLs | eprdtdrv DriverEntry | `IoCreateDeviceSecure` + SDDL `D:P(A;;GA;;;BA)(A;;GA;;;SY)` default; admin override `Parameters\Sddl` | Open may fail for non-admins where it previously could succeed (security fix, documented) |
| F3 | Identity IOCTLs usable by whoever can open (no ACL above); global-handle park/resolve modes unrestricted | eprdtdrv dispatch | Same services, but reachable only through the SDDL-protected device | As F2 |
| F4 | No IRP cancellation: synchronous waits without cancel support — hung reads on dead/slow drives | eprdtdrv READ/WRITE decompile (KeWaitForSingleObject, no cancel routine) | Cancellable forward-wait: cancel routine flags+wakes; dispatcher propagates `IoCancelIrp` into the storage stack; single-completer invariant; page lifetime never violated | No (hangs fixed) |
| F5 | Kernel string parsing of caller-supplied paths (`wcsstr`, decimal parsing) | eprdtdrv CREATE | Grammar preserved, but implemented in a length-bounded, NUL-independent pure-logic module (`rda_compat.h`) shared with user mode and unit-tested; plus a structured explicit-open IOCTL for new clients | No |
| F6 | `DrvHookNextAddDevice` patched *other drivers'* `DriverObject->AddDevice` (undocumented, verifier-hostile) | EUDCPEPM strings + decompile | Documented disk-class `UpperFilters` registration instead; same attach reach, no foreign object mutation | Filter attach behavior preserved by supported mechanism |
| F7 | `DbgBreakPoint` on malformed session handle in the GETNEXTBLOCK path (release builds!) | EUDCPEPM dispatch decompile | Returns `STATUS_INVALID_HANDLE`; breakpoints only in debug builds | No |
| F8 | Legacy power IRP handling without `PoStartNextPowerIrp` pairing for Win7; minimal PnP filtering | EUDCPEPM decompile | Full PnP/Power forwarding incl. START completion, REMOVE detach, `PoStartNextPowerIrp` (Win7-required, no-op later) | No |
| F9 | Per-handle resources released on IRP_MJ_CLOSE rather than CLEANUP | eprdtdrv CLOSE handler | Release at CLEANUP; CLOSE stays minimal (standard WDM discipline) | No |
| F10 | IOCTL pass-through always forwarded the METHOD_BUFFERED SystemBuffer as both in and out — invalid for direct/other methods | eprdtdrv dispatch decompile | Method-aware forwarding: buffered → SystemBuffer; IN/OUT_DIRECT → out = `Irp->UserBuffer`; METHOD_NEITHER rejected with `STATUS_NOT_SUPPORTED` | Direct-method IOCTLs now work correctly |
| F11 | Misleading success metric: `Information = Length × 512` regardless of actual transfer | eprdtdrv decompile | **Preserved** (legacy clients rescale by 512 — verified in Device.mo); new clients get byte-accurate transfer counts via the extended IOCTL set | Yes — intentionally identical |
| F12 | Session handles were raw kernel pointers passed through user mode; the driver dereferenced them with only a magic check | EUDCPEPM dispatch (`*(session+0x28) == 0x74534298`) | Opaque 64-bit IDs into a generation-guarded table; no user-supplied pointer is ever dereferenced | Handle value is opaque either way — compatible |
| F13 | Per-open reference leak: `IoGetAttachedDeviceReference` result never dereferenced | eprdtdrv CREATE/CLOSE decompile | Ownership-disciplined walk (one reference held at a time; adopted or dropped) | No |
| F14 | Urgent pump IRPs into pagefile-backed ranges were priority-blocked ("pagefile bk") via undecoded internal state | EUDCPEPM trace strings | Not reimplemented: paging-file region detection is not part of any wire contract and the copy profile runs on quiesced media (documented divergence) | Behavioral heuristic only |
| F15 | `KeBugCheckEx` reachable from request-path cookie failures | eprdtdrv decompile | /GS cookie retained (unavoidable, standard); no request-path bugchecks; verifier-clean allocation discipline | No |

## Documented benign divergences

- Session `GET_VERSION` returns the same version dword (`0x00010100`) but RDA's product
  string instead of the reference vendor string (trademark hygiene; length-compatible).
- Session op codes `0x800C2AD8/0x800C2AE0/0x800C2B18/0x800C2B20` are fully
  implemented (flush-protected-file, StartBackup plan pump, MODE4 raw paging
  write, MODE3 raw paging read — see `rda_session.c`); earlier revisions of
  this registry called them stubs, which the post-2026-10-22 reverification
  of the decompiles superseded.
- Commands expecting raw session pointers still work — handles are opaque values to
  compliant clients by construction.
