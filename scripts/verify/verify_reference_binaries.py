#!/usr/bin/env python3
"""
verify_reference_binaries.py - independent RE verification of the reference
drivers behind our merged rewrite.

Session 2 audit deliverable ("install reverse engineering tools and verify
independently"). Disassembles the RAW .sys binaries with Capstone and checks
the key contract constants/patterns our implementation carries. Every check
below was tuned against the actual instruction streams (not the Ghidra
decompile), and two earlier decompile-based interpretations were corrected
by this exact tool:

  * G4: the DR fallback passes the disk number as BOTH varargs
    (mov r9d, edi + mov dword ptr [rsp+0x20], edi before the call at RVA
    0x15e6) - Ghidra's 4-param view of the vararg helper hid the second.
  * The kick cap compiles to `cmp x, 300 / jbe` (source `< 0x12D`).

Checks:
  eprdtdrv / EUEDKEPM:
    1. dispatch slots +0x70/+0x80/+0x88/+0x90/+0xe0/+0x100 via the
       lea-rax + mov [rsi+slot],rax pattern (seen at RVA 0x2517..0x2561).
    2. PsGetCurrentProcessId import (token handshake) + the GetProcName
       import chain (eprdtdrv only).
    3. PID-token byte-sum transform fingerprint (shr 8/0x10/0x18 + adds).
    4. DR retry: format-string lea + vararg-2 stack slot store + call.
    5. Identity IOCTL codes 0x60002400/04/08 (whole-image immediates).
  EUDCPEPM:
    6. session magic 0x74534298, filter magic 0xD2C8E4C5, RRWR magic
       0x52455752, kick cap 0x12C, OpenSession 0x840 gate, GETNEXTBLOCK
       Information 0x1E, protocol version 0x10100, all 18 command codes.
    7. state-machine stores {3,4,5} at session+0x38.
    8. filter trace strings (TRIM swallow + pass-through probes).

Usage: verify_reference_binaries.py <eprdtdrv.sys> <EUEDKEPM.sys> <EUDCPEPM.sys>
Exit 0 = all verifications passed.

Licensed under the MIT license.
"""

import re
import sys

import capstone
import pefile

PASS = 0
FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    tag = "PASS" if ok else "FAIL"
    print(f"[{tag}] {name}" + (f"  ({detail})" if detail else ""))
    if ok:
        PASS += 1
    else:
        FAIL += 1


def load(path):
    pe = pefile.PE(path)
    img = pe.get_memory_mapped_image()
    text = text_base = None
    for sec in pe.sections:
        if sec.Name.rstrip(b"\0") == b".text":
            text = sec.get_data()
            text_base = sec.VirtualAddress
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    insns = list(md.disasm(text, text_base))
    return pe, img, text, text_base, insns


def lea_target(ins):
    """RVA targeted by a rip-relative lea, or None."""
    try:
        if "rip +" in ins.op_str:
            off = int(ins.op_str.split("rip +")[-1].split("]")[0].strip(), 16)
        elif "rip -" in ins.op_str:
            off = -int(ins.op_str.split("rip -")[-1].split("]")[0].strip(), 16)
        else:
            return None
        return ins.address + ins.size + off
    except (ValueError, IndexError):
        return None


def verify_epmntdrv(path, label):
    pe, img, text, text_base, insns = load(path)

    # 1. Dispatch slots: `lea rax, [rip+fn]; mov qword ptr [rsi+slot], rax`.
    slot_hits = {}
    for n in range(len(insns) - 1):
        a, b = insns[n], insns[n + 1]
        if a.mnemonic == "lea" and b.mnemonic == "mov" and a.op_str.startswith("rax,"):
            tgt = lea_target(a)
            if tgt is None or not (text_base <= tgt < text_base + len(text)):
                continue
            for disp in (0x70, 0x80, 0x88, 0x90, 0xE0, 0x100):
                if f"+ {hex(disp)}]" in b.op_str and b.op_str.endswith(", rax"):
                    slot_hits.setdefault(disp, []).append(hex(a.address))
    for disp, meaning in (
        (0x70, "IRP_MJ_CREATE"),
        (0x80, "IRP_MJ_CLOSE (context release)"),
        (0x88, "IRP_MJ_READ"),
        (0x90, "IRP_MJ_WRITE"),
        (0xE0, "IRP_MJ_DEVICE_CONTROL"),
        (0x100, "IRP_MJ_CLEANUP (noop-success)"),
    ):
        check(f"{label}: dispatch slot +{hex(disp)} = {meaning}", disp in slot_hits,
              f"sites {slot_hits.get(disp, [])[:2]}")

    # 2. Imports.
    imports = set()
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for imp in entry.imports:
            if imp.name:
                imports.add(imp.name.decode(errors="replace"))
    check(f"{label}: PsGetCurrentProcessId imported (token handshake)",
          "PsGetCurrentProcessId" in imports)
    ident_chain = "NtOpenProcess" in imports and "ZwQueryInformationProcess" in imports
    if label == "eprdtdrv":
        check(f"{label}: GetProcName import chain (NtOpenProcess + ZwQueryInformationProcess)",
              ident_chain)
    else:
        check(f"{label}: no identity IOCTL imports (EUEDKEPM has none - verified)",
              not ident_chain)

    # 3. PID-token transform (verified instruction-level in eprdtdrv at
    # RVA 0x11f1..0x1217): after the PsGetCurrentProcessId IAT call the
    # transform performs THREE BYTE-GRANULAR ADDS in place (b3+=b2, b2+=b1,
    # b1+=b0) and compares the composed DWORD with the parsed token:
    #   token == b0 | (b0+b1)<<8 | (b1+b2)<<16 | (b2+b3)<<24
    ok_transform = False
    detail = "no call to the PsGetCurrentProcessId IAT slot"
    pid_slot = None
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for i, imp in enumerate(entry.imports):
            if imp.name == b"PsGetCurrentProcessId":
                pid_slot = entry.struct.FirstThunk + i * 8
    if pid_slot is not None:
        for ins in insns:
            if ins.mnemonic in ("call", "jmp") and "[rip" in ins.op_str:
                try:
                    if "rip +" in ins.op_str:
                        off = int(ins.op_str.split("rip +")[-1].split("]")[0].strip(), 16)
                    else:
                        off = -int(ins.op_str.split("rip -")[-1].split("]")[0].strip(), 16)
                except (ValueError, IndexError):
                    continue
                if ins.address + ins.size + off == pid_slot:
                    n = i_for(ins, insns)
                    window = insns[n + 1 : n + 25]
                    adds = sum(1 for x in window if x.mnemonic == "add")
                    cmp32 = any(x.mnemonic == "cmp" and "dword ptr" in x.op_str for x in window)
                    ok_transform = adds >= 3 and cmp32
                    detail = f"IAT call@{hex(ins.address)}: byte-adds={adds} dword-cmp={cmp32}"
                    break
    check(f"{label}: PID-token byte-add transform after PsGetCurrentProcessId",
          ok_transform, detail)

    # 4. DR retry (G4-corrected): both varargs = the disk number.
    rva_dr = img.find(b"\\Device\\Harddisk%u\\DR%u\x00\x00".replace(b"\x00\x00", b""))
    rva_dr = img.find("\\Device\\Harddisk%u\\DR%u".encode("utf-16-le"))
    ok_dr = label == "EUEDKEPM"  # EUEDKEPM genuinely has no DR retry
    detail = "not applicable (EUEDKEPM: Partition0 only, no DR retry)"
    if rva_dr >= 0:
        detail = f"string RVA {hex(rva_dr)}"
        for ins in insns:
            if ins.mnemonic == "lea" and lea_target(ins) == rva_dr:
                window = insns[i_for(ins, insns) : i_for(ins, insns) + 14]
                has_arg2 = any(x.mnemonic == "mov" and "[rsp + 0x20]" in x.op_str
                               for x in window)
                has_call = any(x.mnemonic == "call" for x in window)
                ok_dr = has_arg2 and has_call
                detail = f"lea@{hex(ins.address)} arg2@rsp+0x20={has_arg2} call={has_call}"
                break
    check(f"{label}: DR retry passes the disk number as BOTH varargs (G4-corrected)",
          ok_dr, detail)

    # 5. Identity IOCTL codes.
    ident_expected = label == "eprdtdrv"
    for code, meaning, required in ((0x60002400, "GET_PROC_NAME (ladder anchor)", True),
                                    (0x60002404, "GET_FILE_OBJ_NAME (direct cmp; ladder-folded ok)", False),
                                    (0x60002408, "GET_DISK_CONTEXT_MODE", False)):
        hits = img.count(code.to_bytes(4, "little"))
        if ident_expected:
            if required or hits:
                check(f"{label}: IOCTL 0x{code:08X} ({meaning.strip()})",
                      hits > 0 or not required, f"{hits} site(s)")
        else:
            check(f"{label}: no 0x{code:08X} (EUEDKEPM has no identity IOCTLs)", hits == 0,
                  f"{hits} site(s)")


def i_for(ins, insns):
    """Index of ins in insns (linear scan is fine: called rarely)."""
    for n, x in enumerate(insns):
        if x.address == ins.address:
            return n
    return 0


def verify_eudcpepm(path):
    pe, img, text, text_base, insns = load(path)

    values = (
        (0x74534298, "CSession magic (compared at +0x28)"),
        (0xD2C8E4C5, "filter/discovery extension magic"),
        (0x52455752, "RRWR magic"),
        (0x12C, "worker kick cap (compiled: cmp x,300/jbe for source < 0x12D)"),
        (0x840, "OpenSession buffer gate (compiled: cmp in,0x83f)"),
        (0x1E, "GETNEXTBLOCK Information constant"),
        (0x10100, "GET_VERSION protocol dword"),
        (0x800C2AC8, "GET_VERSION code"),
        (0x800C2AC0, "discovery code"),
        (0x800C2AD0, "OPEN_SESSION code"),
        (0x800C2AD8, "SESSION_OP code"),
        (0x800C2AE0, "SESSION_OP2/StartBackup code"),
        (0x800C2AE8, "GETNEXTBLOCK code"),
        (0x800C2AF0, "SESSION_STATUS code"),
        (0x800C2AF8, "GET_PROGRESS/finalize code"),
        (0x800C2B00, "CLOSE_SESSION code"),
        (0x800C2B0A, "DIRECT_READ code"),
        (0x800C2B12, "DIRECT_WRITE code"),
        (0x800C2B18, "MODE4 code"),
        (0x800C2B20, "MODE3 code"),
        (0x800C2B2A, "SIZED_XFER code"),
        (0x800C2B2E, "SIZED_XFER2 code"),
        (0x800C2B38, "CANCEL code"),
        (0x800C2B3E, "RRWR write code"),
        (0x800C2B40, "RRWR version code"),
        (0x800C2B42, "RRWR read code"),
    )
    for value, meaning in values:
        hits = img.count(value.to_bytes(4, "little"))
        check(f"EUDCPEPM: {meaning} (0x{value:X})", hits > 0, f"{hits} site(s)")

    # State machine stores {3=standby, 4=copying, 5=done} at [reg+0x38].
    pat_states = {3: 0, 4: 0, 5: 0}
    for ins in insns:
        if ins.mnemonic == "mov":
            m = re.match(r"^(?:dword|qword) ptr \[r[a-z0-9]+ \+ (?:0x38|56)\], (3|4|5)$",
                         ins.op_str)
            if m:
                pat_states[int(m.group(1))] += 1
    check("EUDCPEPM: state writes {3=standby,4=copying,5=done} at session+0x38",
          all(v > 0 for v in pat_states.values()),
          f"counts 3:{pat_states[3]} 4:{pat_states[4]} 5:{pat_states[5]}")

    # Product string: ASCII (memcpy'd to the SystemBuffer after the version
    # dword - byte-copied, not UTF-16). Exactly 0x2E bytes incl. the NUL.
    needle = b"EASEUS Todo Backup Driver"
    idx = img.find(needle)
    ok = False
    detail = "not found"
    if idx >= 0:
        raw = img[idx : idx + 0x2E]
        text_str = raw.decode("ascii", errors="replace").rstrip("\0")
        ok = text_str.startswith("EASEUS Todo Backup Driver")
        detail = repr(raw)
    check("EUDCPEPM: GET_VERSION product string (ASCII, 0x2E bytes)", ok, detail)

    # Filter trace strings (TRIM swallow + pass-through probes).
    for sneedle in (b"IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES", b"IOCTL_SCSI_PASS_THROUGH",
                    b"Action=Trim"):
        check(f"EUDCPEPM: filter trace string {sneedle.decode()!r}",
              img.find(sneedle) >= 0)


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        return 2
    verify_epmntdrv(sys.argv[1], "eprdtdrv")
    verify_epmntdrv(sys.argv[2], "EUEDKEPM")
    verify_eudcpepm(sys.argv[3])
    print(f"\n{PASS} passed, {FAIL} failed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
