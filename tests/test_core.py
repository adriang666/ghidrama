from __future__ import annotations

import hashlib
import fcntl
import importlib.util
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ghidrama.analysis import inspect_pe, worker_environment, worker_slot
from ghidrama.config import settings
from ghidrama.store import Store, normalize_address


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    return tmp_path


def fixture_bytes():
    spec = importlib.util.spec_from_file_location("fixture_builder", Path(__file__).parents[1] / "scripts/make_fixture.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build_fixture()


def seed(store):
    sample = store.create_sample("fixture.exe", "a" * 64, 2560, "x86_64")
    store.save_analysis(sample["id"], {"sample_id": sample["id"], "revision": 1, "functions": [{"address": "0x140001000", "name": "entry", "size": 12, "signature": "void entry(void)", "comment": None}], "imports": [], "warnings": []})
    store.update_sample(sample["id"], status="ready")
    return store.get_sample(sample["id"])


def test_accepts_native_pe_and_rejects_managed_or_truncated(tmp_path):
    path = tmp_path / "fixture.exe"
    raw = bytearray(fixture_bytes())
    path.write_bytes(raw)
    assert inspect_pe(path)["architecture"] == "x86_64"
    struct.pack_into("<II", raw, 0x98 + 112 + 14 * 8, 0x2000, 72)
    path.write_bytes(raw)
    with pytest.raises(ValueError, match="Managed .NET"):
        inspect_pe(path)
    path.write_bytes(fixture_bytes()[:1024])
    with pytest.raises(ValueError, match="outside"):
        inspect_pe(path)
    path.write_bytes(b"not an executable")
    with pytest.raises(ValueError, match="not a valid"):
        inspect_pe(path)


def test_revision_cache_and_proposal_conflicts(data_dir):
    store = Store()
    sample = seed(store)
    function = {**store.get_function(sample["id"], "140001000"), "decompiled": "void entry(void) {}", "detail_loaded": True}
    store.save_function(sample["id"], 1, function)
    assert store.get_function(sample["id"], "0X140001000")["detail_loaded"]
    proposal = store.create_annotation(sample["id"], "140001000", "rename", "start_here", 1)
    assert proposal["old_value"] == "entry"
    with pytest.raises(ValueError, match="revision changed"):
        store.create_annotation(sample["id"], "140001000", "rename", "new_entry", 2)
    with pytest.raises(ValueError, match="valid function name"):
        store.create_annotation(sample["id"], "140001000", "rename", "bad;name", 1)
    analysis = store.get_analysis(sample["id"])
    analysis["revision"] = 2
    store.save_analysis(sample["id"], analysis)
    assert not store.get_function(sample["id"], "140001000").get("detail_loaded")
    assert (store.sample_dir(sample["id"]) / "artifacts/analysis-1.json").is_file()


def test_sample_path_and_large_address_validation(data_dir):
    store = Store()
    with pytest.raises(ValueError, match="identifier"):
        store.sample_dir("../../sensitive")
    assert normalize_address("ffffffffffffffff") == "0xffffffffffffffff"
    with pytest.raises(ValueError):
        normalize_address("10000000000000000")


def test_worker_environment_excludes_provider_secrets(data_dir, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "never-forward-this")
    monkeypatch.setenv("OLLAMA_API_KEY", "never-forward-this")
    monkeypatch.setenv("LANGSMITH_API_KEY", "never-forward-this")
    env = worker_environment(data_dir)
    assert not any("API_KEY" in key for key in env)
    assert env["PYTHON_DOTENV_DISABLED"] == "1"
    assert env["HOME"] != os.environ["HOME"]


def test_restart_marks_unfinished_jobs(data_dir):
    store = Store()
    sample = store.create_sample("queued.exe", "b" * 64, 100, "x86")
    store.recover_jobs()
    assert store.get_sample(sample["id"])["status"] == "failed"
    assert "interrupted" in store.get_sample(sample["id"])["error"]


def test_api_rejects_cross_site_invalid_and_oversize_uploads(data_dir, monkeypatch):
    from ghidrama.main import app
    monkeypatch.setattr(settings, "max_upload_mb", 1)
    with TestClient(app) as client:
        assert client.get("/api/health").status_code == 200
        blocked = client.post("/api/samples", headers={"Origin": "https://hostile.example"}, files={"file": ("x.exe", b"MZ")})
        assert blocked.status_code == 403
        assert client.post("/api/samples", headers={"Origin": "http://localhost:9999"}, files={"file": ("x.exe", b"MZ")}).status_code == 403
        assert client.post("/api/samples", files={"file": ("x.exe", b"not a PE")}).status_code == 400
        assert client.post("/api/samples", files={"file": ("x.exe", b"x" * (1024 * 1024 + 1))}).status_code == 413
        assert not Store().list_samples()
        assert not list((data_dir / "uploads").iterdir())


def test_api_annotation_requires_current_revision(data_dir):
    from ghidrama.main import app
    store = Store()
    sample = seed(store)
    with TestClient(app) as client:
        response = client.post(f"/api/samples/{sample['id']}/annotations", json={"address": "0x140001000", "kind": "rename", "value": "better_name", "expected_revision": 1})
        assert response.status_code == 201
        assert response.json()["status"] == "proposed"
        assert store.get_function(sample["id"], "0x140001000")["name"] == "entry"
        assert client.post(f"/api/samples/{sample['id']}/annotations", json={"address": "0x140001000", "kind": "comment", "value": "explain", "expected_revision": 9}).status_code == 400


def test_second_server_cannot_recover_another_servers_jobs(data_dir):
    from ghidrama.main import app
    store = Store()
    sample = store.create_sample("active.exe", "c" * 64, 100, "x86_64")
    with (data_dir / "server.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(RuntimeError, match="Another Ghidrama server"):
            with TestClient(app):
                pass
        assert store.get_sample(sample["id"])["status"] == "queued"


def test_worker_slot_limit_is_shared_across_processes(data_dir, monkeypatch):
    monkeypatch.setattr(settings, "max_workers", 1)
    store = Store()
    code = """
import sys
from ghidrama.analysis import worker_slot
from ghidrama.config import settings
from ghidrama.store import Store
settings.max_workers = 1
try:
    with worker_slot(Store(sys.argv[1]), timeout=0.15):
        print('acquired')
except ValueError:
    print('busy')
"""
    with worker_slot(store):
        blocked = subprocess.run([sys.executable, "-c", code, str(data_dir)], capture_output=True, text=True, timeout=10, check=True)
        assert blocked.stdout.strip() == "busy"
        with pytest.raises(InterruptedError, match="cancelled"):
            with worker_slot(store, cancel_check=lambda: True):
                pytest.fail("Cancelled work acquired a slot")
    available = subprocess.run([sys.executable, "-c", code, str(data_dir)], capture_output=True, text=True, timeout=10, check=True)
    assert available.stdout.strip() == "acquired"


def test_upload_length_rejected_before_multipart_parsing(data_dir, monkeypatch):
    from ghidrama.main import app
    monkeypatch.setattr(settings, "max_upload_mb", 1)
    with TestClient(app) as client:
        response = client.post("/api/samples", content=b"", headers={"content-length": str(3 * 1024 * 1024), "content-type": "multipart/form-data; boundary=not-parsed"})
        assert response.status_code == 413
        assert not (data_dir / "uploads").exists()
