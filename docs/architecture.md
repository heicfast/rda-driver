# RDA Architecture

> One WDM driver (`rda.sys`), three merged reference roles, Windows 7 SP1 → Windows 11, x64.

## 1. Why this shape

The reference product ships **7 driver binaries for 3 functional subsystems**; the raw-access
core alone exists as 4 signed copies of the *same compiled code* (`eprdtdrv` /
`eprdtdrv_win7older` / `ebrntdrv` / `epmdkdrv` — byte-identical sections, different signature
chains). The merge is therefore mostly about *unifying identity and deployment*, not about
fusing incompatible code:

| Reference binary | Role | Where it went in RDA |
|---|---|---|
| `eprdtdrv.sys` (EPMNtDrv) | raw disk/partition/volume gate | core open grammar + sector forwarding |
| `eprdtdrv_win7older.sys` | same bytes, SHA-1 chain | not needed — one binary, one (future) signature |
| `ebrntdrv.sys` / `epmdkdrv.sys` | same bytes, WinPE spares | not needed — service-name-derived naming already isolates instances |
| `EUEDKEPM.sys` (EuDskAcs) | 2-segment raw gate (subset grammar) | merged into the open grammar (`\<token>\<disk>` variant) |
| `EUDCPEPM.sys` (EuBackup) | disk-class filter + copy-session engine | `Parameters\FilterMode` role + 15-command session protocol |
| `EuMrx.sys` | NAS RDBSS redirector | **excluded by decision** (different subsystem, own product scope) |

## 2. Module map

```
                       DriverEntry (rda_driver.c)
                            │
        ┌───────────────────┼─────────────────────┐
   Parameters read    Control device        Session engine init
  (rda_registry.c)   (rda_control.c)        (rda_session.c)
                            │                     │
             \Device\<SERVICE-NAME>        session table (64 slots,
             \DosDevices\<SERVICE-NAME>    generation-guarded handles)
                            │                     │
                     IRP dispatch (rda_driver.c)   │
       ┌────────┬──────────┼──────────┬──────────┤
    CREATE    READ/WRITE  IOCTL     CLEANUP/CLOSE  PnP/Power (filter role)
 rda_create  rda_readwrite rda_ioctl  rda_create   rda_filter.c
      │           │           │                      │
  grammar +    MDL forward  ┌──┴─────┐              disk-class UpperFilter
  token +     + cancel     │        │              (AddDevice attach,
  resolve     support   identity  session             VolSnap optional)
 (rda_target)  │        (rda_ident)  protocol
            (rda_util.c pool/strings)   (rda_session)
```

- **Naming** (`rda_control.c`): the control device is `\Device\<UPPERCASE(last component of
  the service registry path)>` with an `\DosDevices\` symlink, falling back to `EPMNTDRV` —
  reference-exact. Install the *same binary* under any service name and it answers that
  name's identity: `eprdtdrv` → `\Device\EPRDTDRV` (drop-in for the DRW user-mode stack),
  `ebrntdrv`/`epmdkdrv` for PE failover hosts, `%s%d` hot-upgrade variants coexist without
  conflicts. Optional `Parameters\DeviceName` override reproduces EUEDKEPM's registry naming.
- **Security** (`rda_control.c`): `IoCreateDeviceSecure` with an explicit SDDL
  (`D:P(A;;GA;;;BA)(A;;GA;;;SY)` default, admin overridable via `Parameters\Sddl`). The
  reference devices had no explicit DACL — every identity feature in this driver discloses
  privileged information (process paths, handle names, raw sectors), so the boundary is the
  device, not the caller's goodwill.

## 3. Data contracts (all preserved byte-semantically)

See `docs/ground-truth-contracts.md` for the authoritative, decompile-verified tables:

- **Open grammar** (all three reference variants): `\<PID-TOKEN>\Volume\<N>`,
  `\<PID-TOKEN>\<disk>\<part>`, `\<PID-TOKEN>\<disk>`, bare (global mode).
- **PID token** = `b0 | (b0+b1)<<8 | (b1+b2)<<16 | (b2+b3)<<24` of the caller's own PID,
  re-derived at IRP time — the handshake binds path to process.
- **Sector I/O**: byte-length forwarding through driver-built async FSD IRPs over the
  caller's MDL; success reports `Information = length × 512` (legacy scaled convention;
  reference clients divide by their sector size — verified both sides).
- **Identity IOCTLs**: `0x60002400` GetProcName, `0x60002404` GetFileObjName,
  `0x60002408` GetDiskContextMode; everything else passes through to the resolved target's
  top-of-stack, honoring the transfer method.
- **Copy-session protocol**: IoctlBase-normalized `0x800C2AC8 … 0x800C2B38` (15 commands),
  `0x840`-byte OpenSession wire struct, overlap-guarded exclusive ranges, worker-streamed
  bitmap-driven block pump with bounded kicks (301), progress/cancel/status semantics.

## 4. Extension points (new, clean, non-conflicting)

- `IOCTL_RDA_GET_INFO` (`0x60002440`) — version/capability/limits.
- `IOCTL_RDA_OPEN_TARGET` (`0x60002444`) — explicit structured open (no path strings).
- `IOCTL_RDA_GET_VERSION` (`0x60002448`) — 64-bit packed version.

## 5. Filter role (WinPE profile)

Registered as the disk-drive class UpperFilter (documented mechanism) with
`Parameters\FilterMode=1`: `AddDevice` attaches a transparent filter DO into every disk
stack; PnP/Power forwarded correctly (`PoStartNextPowerIrp` for Win7); the reference
`0xD2C8E4C5` extension handshake is provided. The reference's AddDevice *patching* of
foreign drivers is deliberately not implemented (see the error-fix registry, F6).

## 6. Threading & IRQL discipline

- Dispatchers run at PASSIVE (control-device contract); nothing raises IRQL above DISPATCH.
- The session engine owns one system thread per session; a semaphore (bounded releases)
  wakes it; a stop event terminates it; queued pump IRPs are cancel-safe.
- Cancellation: see `rda_readwrite.c`'s design note — single-completer invariant, cancel
  propagates into the storage stack via `IoCancelIrp` on the driver-owned forward IRP, with
  context lifetime synchronized by a done-event handshake.
- Memory: single pool tag `rda1`, zero-by-default allocations, tag-checked frees.
