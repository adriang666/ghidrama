"""Verify the known binary used by live smoke tests is internally consistent."""
import importlib.util
from pathlib import Path
import struct

import pefile


def test_fixture_has_expected_machine_code_and_imports():
    source = Path(__file__).resolve().parents[1] / "scripts" / "make_fixture.py"
    spec = importlib.util.spec_from_file_location("make_fixture", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    blob = module.build_fixture()
    pe = pefile.PE(data=blob)
    assert pe.FILE_HEADER.Machine == 0x8664
    assert pe.OPTIONAL_HEADER.AddressOfEntryPoint == 0x1000
    assert [i.name for i in pe.DIRECTORY_ENTRY_IMPORT[0].imports] == [b"OutputDebugStringA", b"ExitProcess"]
    assert pe.get_data(0x1040, 7) == bytes.fromhex("6b c1 03 83 c0 11 c3")
    code = pe.get_data(0x1000, 36)
    assert 0x100B + struct.unpack_from("<i", code, 7)[0] == 0x2000
    assert 0x1011 + struct.unpack_from("<i", code, 13)[0] == 0x3050
    assert 0x101B + struct.unpack_from("<i", code, 23)[0] == 0x1040
    assert b"Ghidrama verification fixture" in blob


def test_x86_fixture_has_32_bit_header_and_thunks():
    source = Path(__file__).resolve().parents[1] / "scripts" / "make_fixture.py"
    spec = importlib.util.spec_from_file_location("make_fixture", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    pe = pefile.PE(data=module.build_x86_fixture())
    assert pe.FILE_HEADER.Machine == 0x14C
    assert pe.OPTIONAL_HEADER.Magic == 0x10B
    assert pe.OPTIONAL_HEADER.ImageBase == 0x400000
    assert [i.address for i in pe.DIRECTORY_ENTRY_IMPORT[0].imports] == [0x403050, 0x403054]
    assert pe.get_data(0x1040, 11) == bytes.fromhex("8b 44 24 04 6b c0 03 83 c0 11 c3")
