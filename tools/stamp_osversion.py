#!/usr/bin/env python3
"""
stamp_osversion.py - stamp the Win7 loader contract into the built driver's
PE optional header and refresh the PE checksum.

Why this exists: the modern WDK toolset always links kernel binaries with
OS version (10, 0) regardless of /osversion link flags (the toolset's own
link options override project AdditionalOptions). The reference drivers
(eprdtdrv family) declare (6, 1) - the load contract RDA preserves for a
single Win7 SP1 -> Win11 binary. This tool deterministically sets:

  - MajorOperatingSystemVersion / MinorOperatingSystemVersion = 6.1
  - MajorSubsystemVersion / MinorSubsystemVersion = 6.01 (NATIVE)
  - the PE checksum (recomputed after mutation)

It then re-verifies and prints the final header. Idempotent.

Usage: python tools/stamp_osversion.py <path-to-rda.sys>
Exit: 0 on success.
"""

import struct
import sys


def checksum(data):
    """Standard PE checksum (RFC-ish) as the Windows loader computes it."""
    # Checksum covers the whole file, with the CheckSum field itself zeroed.
    adjusted = bytearray(data)
    cksum_offset = struct.unpack_from("<I", adjusted, 0x3C)[0] + 4 + 20 + 64
    struct.pack_into("<I", adjusted, cksum_offset, 0)

    if len(adjusted) % 2:
        adjusted += b"\x00"

    total = 0
    for i in range(0, len(adjusted), 2):
        word = adjusted[i] | (adjusted[i + 1] << 8)
        total += word
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    total = total & 0xFFFF
    total += len(data)
    return total & 0xFFFFFFFF


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    path = sys.argv[1]
    data = bytearray(open(path, "rb").read())

    if data[:2] != b"MZ":
        print("FAIL: not a PE file")
        return 1

    lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if bytes(data[lfanew : lfanew + 4]) != b"PE\x00\x00":
        print("FAIL: bad PE signature")
        return 1

    coff = lfanew + 4
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic != 0x20B:
        print("FAIL: not PE32+")
        return 1

    # Optional header field offsets (PE32+):
    #   +40 OS version pair, +68 subsystem, +48 subsystem version pair,
    #   +64 checksum.
    struct.pack_into("<H", data, opt + 40, 6)  # MajorOperatingSystemVersion
    struct.pack_into("<H", data, opt + 42, 1)  # MinorOperatingSystemVersion
    struct.pack_into("<H", data, opt + 48, 6)  # MajorSubsystemVersion
    struct.pack_into("<H", data, opt + 50, 1)  # MinorSubsystemVersion
    struct.pack_into("<H", data, opt + 68, 1)  # IMAGE_SUBSYSTEM_NATIVE

    ck = checksum(bytes(data))
    struct.pack_into("<I", data, opt + 64, ck)

    open(path, "wb").write(bytes(data))

    verify_major, verify_minor = struct.unpack_from("<HH", data, opt + 40)
    sub = struct.unpack_from("<H", data, opt + 68)[0]
    print(f"stamped: OS {verify_major}.{verify_minor} subsystem {sub} checksum 0x{ck:08X}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
