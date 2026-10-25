#!/usr/bin/env python3
"""Build a tiny, deterministic native x64 PE for static-analysis verification.

No compiler or downloaded executable is needed. The emitted entry point writes
an innocuous debugger message, computes (7 * 3) + 17, and calls ExitProcess.
Ghidrama only reads this file; tests must never execute it.
"""
from pathlib import Path
import argparse
import struct


def build_fixture() -> bytes:
    result = bytearray(0xA00)
    result[:2] = b"MZ"
    struct.pack_into("<I", result, 0x3C, 0x80)
    result[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", result, 0x84, 0x8664, 3, 0, 0, 0, 0xF0, 0x0022)
    opt = 0x98
    struct.pack_into("<HBBIIIII", result, opt, 0x20B, 14, 0, 0x200, 0x400, 0, 0x1000, 0x1000)
    struct.pack_into("<QII", result, opt + 24, 0x140000000, 0x1000, 0x200)
    struct.pack_into("<HHHHHH", result, opt + 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<III", result, opt + 52, 0, 0x4000, 0x400)
    struct.pack_into("<HH", result, opt + 68, 3, 0x0100)
    struct.pack_into("<QQQQII", result, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    struct.pack_into("<II", result, opt + 112 + 8, 0x3000, 40)
    struct.pack_into("<II", result, opt + 112 + 12 * 8, 0x3050, 24)
    for index, (name, rva, raw, flags) in enumerate([
        (b".text", 0x1000, 0x400, 0x60000020),
        (b".rdata", 0x2000, 0x600, 0x40000040),
        (b".idata", 0x3000, 0x800, 0xC0000040),
    ]):
        struct.pack_into("<8sIIIIIIHHI", result, 0x188 + index * 40,
                         name, 0x200, rva, 0x200, raw, 0, 0, 0, 0, flags)

    code = bytearray()
    code += bytes.fromhex("48 83 ec 28")  # sub rsp, 0x28
    code += bytes.fromhex("48 8d 0d") + struct.pack("<i", 0x2000 - (0x1000 + len(code) + 7))
    code += bytes.fromhex("ff 15") + struct.pack("<i", 0x3050 - (0x1000 + len(code) + 6))
    code += bytes.fromhex("b9 07 00 00 00")
    code += b"\xe8" + struct.pack("<i", 0x1040 - (0x1000 + len(code) + 5))
    code += bytes.fromhex("89 c1")
    code += bytes.fromhex("ff 15") + struct.pack("<i", 0x3058 - (0x1000 + len(code) + 6))
    code += b"\xcc"
    result[0x400:0x400 + len(code)] = code
    result[0x440:0x447] = bytes.fromhex("6b c1 03 83 c0 11 c3")
    message = b"Ghidrama verification fixture: hello from a Windows PE!\0"
    result[0x600:0x600 + len(message)] = message
    struct.pack_into("<IIIII", result, 0x800, 0x3030, 0, 0, 0x3080, 0x3050)
    for offset in (0x830, 0x850):
        struct.pack_into("<QQQ", result, offset, 0x30A0, 0x30C0, 0)
    result[0x880:0x88D] = b"KERNEL32.dll\0"
    for raw, name in [(0x8A0, b"OutputDebugStringA"), (0x8C0, b"ExitProcess")]:
        result[raw:raw + 2] = b"\0\0"
        result[raw + 2:raw + 3 + len(name)] = name + b"\0"
    return bytes(result)


def build_x86_fixture() -> bytes:
    """Equivalent 32-bit PE using Windows stdcall imports and a cdecl helper."""
    result = bytearray(build_fixture())
    struct.pack_into("<HHIIIHH", result, 0x84, 0x14C, 3, 0, 0, 0, 0xE0, 0x0102)
    result[0x98:0x200] = b"\0" * (0x200 - 0x98)
    opt = 0x98
    struct.pack_into("<HBBIIIIII", result, opt, 0x10B, 14, 0, 0x200, 0x400, 0, 0x1000, 0x1000, 0x2000)
    struct.pack_into("<III", result, opt + 28, 0x400000, 0x1000, 0x200)
    struct.pack_into("<HHHHHH", result, opt + 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<III", result, opt + 52, 0, 0x4000, 0x400)
    struct.pack_into("<HH", result, opt + 68, 3, 0x0100)
    struct.pack_into("<IIIIII", result, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    struct.pack_into("<II", result, opt + 96 + 8, 0x3000, 40)
    struct.pack_into("<II", result, opt + 96 + 12 * 8, 0x3050, 12)
    for index, (name, rva, raw, flags) in enumerate([
        (b".text", 0x1000, 0x400, 0x60000020),
        (b".rdata", 0x2000, 0x600, 0x40000040),
        (b".idata", 0x3000, 0x800, 0xC0000040),
    ]):
        struct.pack_into("<8sIIIIIIHHI", result, 0x178 + index * 40,
                         name, 0x200, rva, 0x200, raw, 0, 0, 0, 0, flags)
    result[0x400:0x600] = b"\0" * 0x200
    code = bytearray(b"\x68" + struct.pack("<I", 0x402000))
    code += bytes.fromhex("ff 15") + struct.pack("<I", 0x403050)
    code += bytes.fromhex("6a 07")
    code += b"\xe8" + struct.pack("<i", 0x1040 - (0x1000 + len(code) + 5))
    code += bytes.fromhex("83 c4 04 50 ff 15") + struct.pack("<I", 0x403054) + b"\xcc"
    result[0x400:0x400 + len(code)] = code
    result[0x440:0x44B] = bytes.fromhex("8b 44 24 04 6b c0 03 83 c0 11 c3")
    for offset in (0x830, 0x850):
        result[offset:offset + 24] = b"\0" * 24
        struct.pack_into("<III", result, offset, 0x30A0, 0x30C0, 0)
    return bytes(result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", default=".runtime/ghidrama-fixture.exe")
    parser.add_argument("--arch", choices=["x64", "x86"], default="x64")
    args = parser.parse_args()
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(build_x86_fixture() if args.arch == "x86" else build_fixture())
    print(f"Created {path} ({path.stat().st_size} bytes). For static analysis only.")
