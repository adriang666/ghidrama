"""Exercise real bounded child processes, input provenance, and MCP byte routing."""
import hashlib
import importlib.util
import json
import sys
import threading
from pathlib import Path

import pefile
import pytest

from ghidrama import analysis
from ghidrama.config import settings
from ghidrama.store import Store
from ghidrama.unpacking import input_path, prepare_input, project_directory, sha256, upx_indicators


@pytest.fixture
def specimen(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    module_spec = importlib.util.spec_from_file_location("fixture_builder", Path(__file__).parents[1] / "scripts/make_fixture.py")
    builder = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(builder)
    plain = builder.build_fixture()
    packed = bytearray(plain)
    with pefile.PE(data=plain) as pe:
        offset = pe.sections[0].get_file_offset()
    packed[offset:offset + 8] = b"UPX0\0\0\0\0"
    # Distinguishable bytes at the entry point for the raw-memory routing test.
    packed[0x400:0x404] = b"PACK"
    store = Store()
    sample = store.create_sample("packed-fixture.exe", hashlib.sha256(packed).hexdigest(), len(packed), "x86_64")
    folder = store.sample_dir(sample["id"])
    (folder / "original.bin").write_bytes(packed)
    (folder / "original.bin").chmod(0o400)
    return sample, folder, plain


def fake_upx(monkeypatch, folder, body):
    # This test-only executable stands in for UPX, never for the specimen.
    tool = folder / "test-upx"
    tool.write_text(f"#!{sys.executable}\nimport os, sys, time\nfrom pathlib import Path\n"
                    "assert sys.argv[1:4] == ['-d', '--no-color', '--no-progress']\n"
                    "assert not any('API_KEY' in key for key in os.environ)\n"
                    "out = Path(sys.argv[sys.argv.index('-o') + 1])\n" + body)
    tool.chmod(0o700)
    monkeypatch.setattr(settings, "upx_path", tool)
    return tool


def test_plain_pe_needs_no_unpacker_and_preserves_original(specimen, monkeypatch):
    _, folder, plain = specimen
    path = folder / "original.bin"
    path.chmod(0o600)
    path.write_bytes(plain)
    monkeypatch.setattr(settings, "upx_path", folder / "missing")
    result = prepare_input(folder, sha256(path))
    assert result["status"] == "not_detected"
    assert result["analyzed_sha256"] == sha256(path)
    assert input_path(folder, result) == path
    assert upx_indicators(path) == []


def test_detection_includes_renamed_sections_with_pack_header(specimen):
    _, folder, plain = specimen
    assert upx_indicators(folder / "original.bin") == ["section UPX0"]
    path = folder / "renamed.bin"
    raw = bytearray(plain)
    raw[0x300:0x304] = b"UPX!"
    path.write_bytes(raw)
    assert upx_indicators(path) == ["UPX pack header"]


def test_unpack_validates_and_keeps_content_addressed_input(specimen, monkeypatch):
    sample, folder, plain = specimen
    fake_upx(monkeypatch, folder, f"out.write_bytes({plain!r})\nprint('UPX 5.2.1')\n")
    monkeypatch.setenv("OLLAMA_API_KEY", "must-not-reach-unpacker")
    result = prepare_input(folder, sample["sha256"])
    source = input_path(folder, result)
    assert source.read_bytes() == plain
    assert source.stat().st_mode & 0o777 == 0o400
    assert result["analyzed_sha256"] == hashlib.sha256(plain).hexdigest()
    assert result["tool_version"] == "5.2.1"
    assert sha256(folder / "original.bin") == sample["sha256"]
    assert project_directory(folder, source) != project_directory(folder, folder / "original.bin")
    assert prepare_input(folder, sample["sha256"]) == result
    assert not list(folder.glob("unpacking-*.bin"))


def test_missing_upx_and_changed_original_are_actionable(specimen, monkeypatch):
    sample, folder, _ = specimen
    monkeypatch.setattr(settings, "upx_path", folder / "missing")
    with pytest.raises(ValueError, match="GHIDRAMA_UPX_PATH"):
        prepare_input(folder, sample["sha256"])
    with pytest.raises(ValueError, match="recorded SHA-256"):
        prepare_input(folder, "0" * 64)


@pytest.mark.parametrize("body, message", [
    ("out.write_bytes(b'partial'); sys.exit(1)", "could not unpack"),
    ("out.write_bytes(b'not a PE')", "not a valid Windows PE"),
    ("out.write_bytes(Path(sys.argv[-1]).read_bytes())", "did not change"),
    ("out.write_bytes(b'x' * (2 * 1024 * 1024))", "output limit"),
])
def test_failed_or_oversized_unpack_never_publishes_output(specimen, monkeypatch, body, message):
    sample, folder, _ = specimen
    monkeypatch.setattr(settings, "max_unpacked_mb", 1)
    fake_upx(monkeypatch, folder, body)
    with pytest.raises(ValueError, match=message):
        prepare_input(folder, sample["sha256"])
    assert sha256(folder / "original.bin") == sample["sha256"]
    assert not list(folder.glob("unpack*-*.bin"))


def test_unpack_architecture_must_match(specimen, monkeypatch):
    sample, folder, plain = specimen
    raw = bytearray(plain)
    raw[0x84:0x86] = b"\x4c\x01"
    fake_upx(monkeypatch, folder, f"out.write_bytes({bytes(raw)!r})")
    with pytest.raises(ValueError, match="architecture"):
        prepare_input(folder, sample["sha256"])
    assert not list(folder.glob("unpack*-*.bin"))


def test_timeout_and_cancellation_terminate_process_and_clean_up(specimen, monkeypatch):
    sample, folder, _ = specimen
    fake_upx(monkeypatch, folder, "out.write_bytes(b'partial'); time.sleep(10)")
    monkeypatch.setattr(settings, "unpack_timeout", 1)
    processes = []
    with pytest.raises(ValueError, match="exceeded 1 seconds"):
        prepare_input(folder, sample["sha256"], on_process=processes.append)
    assert processes[0].poll() is not None
    cancelled = threading.Event()
    def cancel(process):
        processes.append(process)
        cancelled.set()
    with pytest.raises(InterruptedError, match="cancelled"):
        prepare_input(folder, sample["sha256"], on_process=cancel, cancel_check=cancelled.is_set)
    assert processes[-1].poll() is not None
    assert not list(folder.glob("unpack*-*.bin"))


def test_missing_derived_file_never_falls_back_to_packed_input(specimen):
    _, folder, _ = specimen
    with pytest.raises(ValueError, match="missing"):
        input_path(folder, {"status": "unpacked", "analyzed_sha256": "a" * 64})
    with pytest.raises(ValueError, match="invalid digest"):
        input_path(folder, {"status": "unpacked", "analyzed_sha256": "../../original"})
    assert input_path(folder, None) == folder / "original.bin"


@pytest.mark.asyncio
async def test_unpack_failure_stops_before_ghidra(specimen, monkeypatch):
    sample, folder, _ = specimen
    fake_upx(monkeypatch, folder, "sys.exit(1)")
    def unexpected_worker(*args, **kwargs):
        pytest.fail("Ghidra must not analyze failed UPX output")
    monkeypatch.setattr(analysis, "run_worker", unexpected_worker)
    manager = analysis.AnalysisManager()
    manager.submit(sample["id"])
    await manager.tasks[sample["id"]]
    assert Store().get_sample(sample["id"])["status"] == "failed"
    assert Store().get_sample(sample["id"])["analysis_revision"] == 0


@pytest.mark.asyncio
async def test_mcp_memory_reads_unpacked_bytes_and_reports_provenance(specimen, monkeypatch):
    from ghidrama.mcp_server import build_server
    sample, folder, plain = specimen
    fake_upx(monkeypatch, folder, f"out.write_bytes({plain!r})")
    provenance = prepare_input(folder, sample["sha256"])
    store = Store()
    store.save_analysis(sample["id"], {"revision": 1, "image_base": "0x140000000", "functions": [], "preprocessing": provenance})
    store.update_sample(sample["id"], status="ready")
    server = build_server(sample["id"], 1)
    result = await server.call_tool("read_memory_range", {"address": "0x140001000", "size": 4})
    payload = json.loads(result[0].text)
    with pefile.PE(data=plain) as pe:
        assert payload["bytes"] == pe.get_data(0x1000, 4).hex(" ")
    info = json.loads((await server.call_tool("get_program_info", {}))[0].text)
    assert info["program"]["preprocessing"] == provenance
    assert info["sha256"] == sample["sha256"]


def test_worker_uses_revision_source_for_decompile_and_annotation(specimen, monkeypatch):
    sample, folder, plain = specimen
    fake_upx(monkeypatch, folder, f"out.write_bytes({plain!r})")
    provenance = prepare_input(folder, sample["sha256"])
    store = Store()
    store.save_analysis(sample["id"], {"revision": 1, "functions": [], "preprocessing": provenance})
    install = folder / "ghidra" / "Ghidra"
    install.mkdir(parents=True)
    (install / "application.properties").write_text("application.version=test")
    monkeypatch.setattr(settings, "ghidra_install_dir", install.parent)
    commands = []
    class Process:
        returncode = 0
        def __init__(self, args, **kwargs):
            commands.append(args)
            Path(args[args.index("--output") + 1]).write_text('{}')
        def poll(self):
            return 0
    monkeypatch.setattr(analysis.subprocess, "Popen", Process)
    for action in ["function", "functions", "annotate"]:
        result = analysis._run_worker_process(store, sample["id"], action)
        assert commands[-1][commands[-1].index("--input-name") + 1] == input_path(folder, provenance).name
        if action == "annotate":
            assert result["preprocessing"] == provenance
