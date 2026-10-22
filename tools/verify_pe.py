#!/usr/bin/env python3
"""
verify_pe.py - Win7-loadability gate for the RDA driver binary.

Run on every CI build AFTER linking (before artifacts are published).

Checks:
  1. PE machine = AMD64; subsystem = NATIVE; OS version fields = 6.1
     (Windows 7 SP1 load contract, reference parity: the reference
     eprdtdrv.sys declares OS 6.1 and runs Win7 SP1 -> Win11).
  2. Import table must be a subset of the Win7-safe allowlist:
       - tools/ref_imports.json 'union'  (75 functions extracted from the
         six reference binaries - all present on Win7 SP1 x64 ntoskrnl)
       - plus the audited additions below, each present since XP/2003.
     Any new import FAILS the build: forcing a conscious allowlist update.
  3. No unexpected dynamic-link imports beyond ntoskrnl.exe (hal.dll
     imports are permitted for legacy targets; RDA should not need any).

Usage: python tools/verify_pe.py <path-to-rda.sys> [--allowlist tools/ref_imports.json]
Exit: 0 = passes, nonzero = gate failure.
"""

import json
import struct
import sys
import os

# Audited additions beyond the reference union, with reasons. Each is an
# ntoskrnl export available on Windows XP/2003 and later (hence Win7 SP1):
#   - direct RDA usage: identity services, cancellation, session engine.
#   - wdmsec.lib (IoCreateDeviceSecure, fix F2) statically links its own
#     XP-era implementation: security-descriptor Rtl*/Zw* APIs, object-type
#     globals and CRT string inlines come in as one audited set.
ALLOWLIST_ADDITIONS = {
    # RDA direct usage
    "IoCreateDeviceSecure": "wdmsec device SDDL (fix F2); ntoskrnl export since XP",
    "PsLookupProcessByProcessId": "GetProcName identity service; replaces reference NtOpenProcess juggling",
    "SeLocateProcessImageName": "GetProcName identity service; documented ntifs API",
    "IoSetCancelRoutine": "IRP cancellation (fix F4)",
    "IoCancelIrp": "cancellation propagation into the storage stack (fix F4)",
    "KeWaitForMultipleObjects": "session worker wait",
    "KeInitializeSemaphore": "session worker kick semaphore",
    "RtlIntegerToUnicodeString": "bounded device-name formatting (no printf in kernel)",
    "DbgPrintEx": "leveled tracing (reference used DbgPrint)",
    "KeInitializeSpinLock": "session queue lock init (real function on x64 targets)",
    "ExAcquireFastMutex": "session table lock",
    "ExReleaseFastMutex": "session table lock",
    "PsThreadType": "ObReferenceObjectByHandle type check for PETHREAD (PsCreateSystemThread)",
    # wdmsec.lib static-link internals (IoCreateDeviceSecure implementation)
    "ZwCreateKey": "wdmsec: class-key SDDL lookup",
    "ZwSetValueKey": "wdmsec: class-key SDDL publish",
    "ZwSetSecurityObject": "wdmsec: apply DACL to device object",
    "ZwOpenKey": "wdmsec/registry: open class key",
    "ZwQueryValueKey": "wdmsec/registry: read class-key override",
    "RtlGetDaclSecurityDescriptor": "wdmsec: SD manipulation",
    "RtlSetDaclSecurityDescriptor": "wdmsec: SD manipulation",
    "RtlAbsoluteToSelfRelativeSD": "wdmsec: SD conversion (exported since Windows 2000)",
    "RtlAddAccessAllowedAce": "wdmsec: DACL construction",
    "RtlLengthSid": "wdmsec: SID sizing",
    "IoDeviceObjectType": "wdmsec: object-type constant",
    "ObOpenObjectByPointer": "wdmsec: object handle from pointer",
    "IoIsWdmVersionAvailable": "wdmsec: WDM level probe (exported since XP)",
    "MmGetSystemRoutineAddress": "wdmsec: routine resolution",
    "RtlCreateSecurityDescriptor": "wdmsec: SD construction",
    "RtlGetOwnerSecurityDescriptor": "wdmsec: SD query",
    "RtlGetGroupSecurityDescriptor": "wdmsec: SD query",
    "RtlGetSaclSecurityDescriptor": "wdmsec: SD query",
    "RtlLengthSecurityDescriptor": "wdmsec: SD sizing",
    "SeCaptureSecurityDescriptor": "wdmsec: SD capture (exported since XP)",
    "SeExports": "wdmsec: well-known SID table (exported since Windows 2000)",
    # CRT string inlines pulled through ntifs/wdmsec chains (ntoskrnl exports)
    "_wcsnicmp": "CRT string inline via header chains (ntoskrnl export)",
    "wcschr": "CRT string inline via header chains (ntoskrnl export)",
    "_snwprintf": "CRT formatting inline via wdmsec/header chains (ntoskrnl export)",
    # Session 2 additions (copy-engine + filter role, all Win2000/XP-era
    # ntoskrnl exports - verified against the EUDCPEPM import table which
    # itself uses most of these):
    "IoAllocateMdl": "MDL allocation (EUDCPEPM-era; ntoskrnl since 2000)",
    "IoFreeMdl": "MDL free (ntoskrnl since 2000)",
    "MmProbeAndLockPages": "user-buffer lock for pump buffer (EUDCPEPM-era)",
    "MmUnmapLockedPages": "pump-buffer system-VA unmap (ntoskrnl since 2000)",
    "MmMapLockedPagesSpecifyCache": "reference's own mapping API (EPMNtDrv)",
    "IoBuildSynchronousFsdRequest": "sync FSD IRP build (EUDCPEPM session engine)",
    "IoGetRelatedDeviceObject": "file->volume device (EUDCPEPM flush path)",
    "PsGetCurrentProcess": "session owner identity (EUDCPEPM ctor)",
    "ZwCreateFile": "protected-file open for flush (EUDCPEPM FUN_0001590c)",
    "ZwClose": "handle close (universal)",
    "KeReleaseSemaphore": "worker kick (EUDCPEPM FUN_00013454)",
    "PoCallDriver": "power forward (filter role; ntoskrnl since 2000)",
    "PoStartNextPowerIrp": "Win7 power protocol (filter role)",
    "ProbeForRead": "user exclusion-bitmap probe (EUDCPEPM StartBackup)",
    "IoCreateFile": "object-namespace open fallback (wdmsec/header chain)",
    # Session-2 security fixes (S1/S2 cancel protocol + IRQL guard): both
    # exports exist since Windows 2000.
    "IoReleaseCancelSpinLock": "cancel-routine protocol (S1/S2)",
    "KeGetCurrentIrql": "IRQL guard on the filter session-liveness probe",
    # Benchmark round-2 perf: per-IO context pooling via a self-contained
    # SLIST free-list. (The LookasideListEx ALLOC/FREE pair was tried and
    # REJECTED: those two are FORCEINLINE before NTDDI_WIN10_NI and kernel
    # EXPORTS only from Win11 22H2 - importing them breaks loading on older
    # kernels with error 127, which the runner caught live.)
    "InterlockedPopEntrySList": "xfer-context pool pop (Win2000-era)",
    "InterlockedPushEntrySList": "xfer-context pool push (Win2000-era)",
}

EXPECTED_MACHINE = 0x8664
EXPECTED_OS_MAJOR = 6
EXPECTED_OS_MINOR = 1
EXPECTED_SUBSYSTEM = 1  # IMAGE_SUBSYSTEM_NATIVE
ALLOWED_DLLS = {"ntoskrnl.exe", "hal.dll", "bootvid.dll", "kdcom.dll", "wmilib.sys"}


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def parse_pe(path):
    data = open(path, "rb").read()
    if data[:2] != b"MZ":
        fail("not a PE file")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        fail("bad PE signature")
    coff = e_lfanew + 4
    machine, nsec, _ts, _ps, _ns, ohs, _chars = struct.unpack_from("<HHIIIHH", data, coff)
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic != 0x20B:
        fail("not a PE32+ (x64) optional header")
    os_major, os_minor = struct.unpack_from("<HH", data, opt + 40)
    img_major, img_minor = struct.unpack_from("<HH", data, opt + 44)
    sub_major, sub_minor = struct.unpack_from("<HH", data, opt + 48)
    subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    ntds = struct.unpack_from("<I", data, opt + 108)[0]

    # Import directory (data dir index 1)
    imp_rva, imp_len = struct.unpack_from("<II", data, opt + 112 + 8)
    sections = []
    sec_off = opt + ohs
    for i in range(nsec):
        s = data[sec_off + i * 40 : sec_off + (i + 1) * 40]
        vsz, va, rsz, rp = struct.unpack_from("<IIII", s, 8)
        sections.append((va, max(vsz, rsz), rp))

    def r2o(rva):
        for va, sz, rp in sections:
            if va <= rva < va + sz:
                return rp + (rva - va)
        return None

    imports = {}
    if imp_rva:
        off = r2o(imp_rva)
        idx = 0
        while True:
            ilt, _ts, _fw, nrva, iat = struct.unpack_from("<IIIII", data, off + idx * 20)
            if nrva == 0 and ilt == 0:
                break
            no = r2o(nrva)
            dll = data[no : no + 64].split(b"\0")[0].decode(errors="replace")
            funcs = []
            t = ilt if ilt else iat
            to = r2o(t)
            j = 0
            while True:
                v = struct.unpack_from("<Q", data, to + j * 8)[0]
                if v == 0:
                    break
                if v & (1 << 63):
                    funcs.append(f"ordinal_{v & 0xffff}")
                else:
                    ho = r2o(v & 0x7FFFFFFF)
                    fn = data[ho + 2 : ho + 2 + 128].split(b"\0")[0].decode(errors="replace")
                    funcs.append(fn)
                j += 1
            imports[dll] = funcs
            idx += 1

    return {
        "machine": machine,
        "os_version": (os_major, os_minor),
        "image_version": (img_major, img_minor),
        "subsystem_version": (sub_major, sub_minor),
        "subsystem": subsystem,
        "imports": imports,
        "data_dir_count": ntds,
    }


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    target = sys.argv[1]
    allowlist_path = "tools/ref_imports.json"
    if "--allowlist" in sys.argv:
        allowlist_path = sys.argv[sys.argv.index("--allowlist") + 1]

    pe = parse_pe(target)

    ok = True
    if pe["machine"] != EXPECTED_MACHINE:
        print(f"FAIL: machine 0x{pe['machine']:X} != 0x{EXPECTED_MACHINE:X}")
        ok = False
    if pe["os_version"] != (EXPECTED_OS_MAJOR, EXPECTED_OS_MINOR):
        print(
            f"FAIL: OS version {pe['os_version']} != (6, 1) - "
            "Win7 loader contract broken (linker /osversion:6.1 missing?)"
        )
        ok = False
    if pe["subsystem"] != EXPECTED_SUBSYSTEM:
        print(f"FAIL: subsystem {pe['subsystem']} != NATIVE(1)")
        ok = False

    with open(allowlist_path) as f:
        ref = json.load(f)
    allow = set(ref["union"]) | set(ALLOWLIST_ADDITIONS.keys())

    print(f"PE: machine=0x{pe['machine']:X} OS={pe['os_version'][0]}.{pe['os_version'][1]} "
          f"subsystem={pe['subsystem']}")

    for dll, funcs in pe["imports"].items():
        if dll.lower() not in ALLOWED_DLLS:
            print(f"FAIL: unexpected import DLL '{dll}'")
            ok = False
            continue
        for fn in funcs:
            if fn not in allow:
                print(f"FAIL: import '{fn}' (from {dll}) is not in the Win7 allowlist")
                ok = False

    if not ok:
        print("verify_pe: GATE FAILED")
        return 1
    print(
        f"verify_pe: OK "
        f"({sum(len(v) for v in pe['imports'].values())} imports, all Win7-safe)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
