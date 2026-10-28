"""Extraction lifecycle and real MCP rewrites with mocked cloud HTTP only."""
import asyncio
import json
import threading
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from ghidrama import agent, analysis, pseudocode
from ghidrama.config import settings
from ghidrama.providers import ProviderClient
from ghidrama.store import Store, utcnow


@pytest.fixture
def sample(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    store = Store()
    item = store.create_sample("fixture.exe", "a" * 64, 2560, "x86_64")
    function = {"address": "0x1000", "name": "entry", "size": 6, "signature": "int entry(void)",
                "decompiled": "int entry(void) { return 42; }", "detail_loaded": True,
                "disassembly": [], "callers": [], "callees": [], "comment": None}
    store.save_analysis(item["id"], {"sample_id": item["id"], "revision": 1, "functions": [function],
                                    "entry_point": "0x1000", "image_base": "0x1000", "warnings": [],
                                    "sections": [], "engine": {"name": "test-fixture"}})
    store.save_function(item["id"], 1, function)
    return store.update_sample(item["id"], status="ready")


def job_for(sample):
    return {"sample_id": sample["id"], "name": sample["name"], "sha256": sample["sha256"],
            "analysis_revision": 1, "status": "queued", "total": sample["function_count"],
            "processed": 0, "recovered": 0, "failed": 0, "truncated": 0, "characters": 0,
            "functions": [], "source_partial": False, "warnings": [], "error": None, "created_at": utcnow()}


def run_for(sample, scope="function"):
    return {"id": "b" * 32, "sample_id": sample["id"], "analysis_revision": 1, "mode": "pseudocode",
            "function_address": "0x1000" if scope == "function" else None, "question": "Rewrite the pseudocode.",
            "provider": "ollama", "model": "test-model", "status": "queued", "answer": "", "error": None,
            "events": [], "evidence": [], "usage": {"input_tokens": 0, "output_tokens": 0}, "created_at": utcnow()}


def test_extract_exports_captured_revision_and_reports_missing_functions(sample, monkeypatch):
    store = Store()
    original = store.get_analysis(sample["id"])
    original["functions"] += [{"address": "0x2000", "name": "unrecovered", "size": 2, "decompiled": None,
                               "decompile_error": "No flow recovered", "detail_loaded": True}]
    store.save_analysis(sample["id"], original)
    job = job_for(store.get_sample(sample["id"]))
    pseudocode.extract(job, threading.Event())
    assert job["status"] == "partial"
    assert (job["processed"], job["recovered"], job["failed"]) == (2, 1, 1)
    original["revision"] = 2
    original["functions"][0]["decompiled"] = "changed later"
    store.save_analysis(sample["id"], original)
    exported = "".join(pseudocode.export_text(job, store))
    assert "return 42" in exported and "changed later" not in exported
    assert "1/2 indexed functions recovered" in exported
    assert "Unavailable: No flow recovered" in exported
    assert "Analysis revision: 1" in exported


def test_batch_reuses_cache_and_rejects_stale_revisions(sample, monkeypatch):
    calls = []
    store = Store()
    original = store.get_analysis(sample["id"])
    original["functions"].append({"address": "0x2000", "name": "helper", "size": 4, "detail_loaded": False})
    store.save_analysis(sample["id"], original)
    def worker(store, sample_id, action, **kwargs):
        calls.append(kwargs["addresses"])
        assert action == "functions"
        return {"functions": [{"address": "0x2000", "name": "helper", "size": 4,
                                "decompiled": "void helper(void) {}", "detail_loaded": True}]}
    monkeypatch.setattr(analysis, "run_worker", worker)
    for _ in range(2):
        result = analysis.get_function_batch(sample["id"], ["0x1000", "0x2000"], 1)
        assert len(result) == 2 and result[1]["decompiled"]
    assert calls == [["0x2000"]]
    with pytest.raises(ValueError, match="Analysis changed"):
        analysis.get_function_batch(sample["id"], ["0x1000"], 2)


def test_extraction_character_limit_and_cancellation_are_explicit(sample, monkeypatch):
    monkeypatch.setattr(pseudocode, "MAX_CHARACTERS", 5)
    job = job_for(sample)
    pseudocode.extract(job, threading.Event())
    assert job["status"] == "failed" and "export limit" in job["error"]
    assert job["processed"] == 0
    cancelled = threading.Event()
    cancelled.set()
    job = job_for(sample)
    pseudocode.extract(job, cancelled)
    assert job["status"] == "cancelled" and job["processed"] == 0


@pytest.mark.asyncio
async def test_cancel_signals_active_extraction_and_joins_worker(sample, monkeypatch):
    entered = threading.Event()
    def batch(*args, cancel_check):
        entered.set()
        while not cancel_check():
            time.sleep(0.01)
        raise InterruptedError()
    monkeypatch.setattr(pseudocode, "get_function_batch", batch)
    await pseudocode.generate(sample["id"], pseudocode.GeneratePseudocode(expected_revision=1))
    assert await asyncio.to_thread(entered.wait, 2)
    from ghidrama.main import health
    assert pseudocode.active_jobs() == 1 and health()["active_jobs"] >= 1
    result = await asyncio.wait_for(pseudocode.cancel(sample["id"]), timeout=2)
    assert result["status"] == "cancelled"
    assert sample["id"] not in pseudocode._tasks
    assert pseudocode.active_jobs() == 0


@pytest.mark.asyncio
async def test_extraction_recovers_interruption(sample):
    job = job_for(sample)
    job["status"] = "running"
    pseudocode.PseudocodeStore().save(job)
    await pseudocode.startup()
    saved = pseudocode.PseudocodeStore().get(sample["id"])
    assert saved["status"] == "interrupted" and "restart" in saved["error"]


def test_api_revision_checks_and_unconfigured_provider(sample):
    from ghidrama.main import app
    with TestClient(app) as client:
        base = f"/api/samples/{sample['id']}/pseudocode"
        assert client.post(base, json={"expected_revision": 2}).status_code == 409
        assert client.get(base + "/download?revision=1").status_code == 409
        assert client.get("/api/samples/unknown/pseudocode").status_code == 404
        response = client.post(f"/api/samples/{sample['id']}/runs", json={
            "question": "Rewrite", "mode": "pseudocode", "provider": "ollama", "expected_revision": 2})
        assert response.status_code == 409
        response = client.post(f"/api/samples/{sample['id']}/runs", json={
            "question": "Rewrite", "mode": "pseudocode", "provider": "ollama", "expected_revision": 1})
        assert response.status_code == 400 and "API key" in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["ollama", "openrouter"])
@pytest.mark.parametrize("scope", ["function", "program"])
async def test_cloud_rewrite_uses_real_mcp_and_supported_provider_adapter(sample, provider, scope):
    answer = "## Readable pseudocode\nAI interpretation of entry at 0x1000. [E2]\n\n```c\nint entry() { return 42; }\n```\n\nOnly this function was inspected."
    requests = []
    def respond(request):
        payload = json.loads(request.content)
        requests.append(payload)
        assert (payload["max_tokens"] if provider == "openrouter" else payload["options"]["num_predict"]) == 12288
        assert request.extensions["timeout"]["read"] == 180
        assert "readable pseudocode rewrite" in payload["messages"][0]["content"]
        assert "return 42" in payload["messages"][-1]["content"]
        assert not any("api_key" in str(message) for message in payload["messages"])
        if provider == "openrouter":
            return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": answer}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 20, "completion_tokens": 10}})
        return httpx.Response(200, json={"message": {"role": "assistant", "content": answer}, "done_reason": "stop", "prompt_eval_count": 20, "eval_count": 10})
    run = run_for(sample, scope)
    run["provider"] = provider
    client = ProviderClient(provider, "test-only-key", "test-model", httpx.MockTransport(respond))
    await agent.execute_run(run, client, run["function_address"])
    assert run["status"] == "complete", run.get("error")
    assert run["max_output_tokens"] == 12288
    assert run["pseudocode_coverage"]["addresses"] == ["0x1000"]
    assert run["pseudocode_coverage"]["scope"] == ("function" if scope == "function" else "program_sketch")
    assert run["usage"] == {"input_tokens": 20, "output_tokens": 10}
    assert len(requests) == 1
    saved = agent.RunStore().get_evidence(run["id"], "E2")
    assert saved["decompiled"] == "int entry(void) { return 42; }"
    exported = agent.download_run(run["id"]).body.decode()
    assert "AI pseudocode interpretation" in exported and "Captured evidence" in exported
    assert "return 42" in exported and "test-only-key" not in exported


@pytest.mark.asyncio
async def test_rewrite_rejects_citations_without_decompilation_support(sample):
    class Model:
        async def chat(self, messages, tools, *, max_output_tokens=4096):
            return {"role": "assistant", "content": "Based on metadata [E1]\n```c\nreturn invented();\n```",
                    "tool_calls": [], "usage": {"input_tokens": 1, "output_tokens": 1}}
    run = run_for(sample)
    await agent.execute_run(run, Model(), "0x1000")
    assert run["status"] == "failed" and "pseudocode block" in run["error"]
    assert run["answer"] == ""


@pytest.mark.asyncio
async def test_missing_decompilation_never_calls_cloud(sample):
    store = Store()
    function = store.get_function(sample["id"], "0x1000")
    function.update(decompiled=None, decompile_error="unrecoverable")
    store.save_function(sample["id"], 1, function)
    class Model:
        async def chat(self, messages, tools, *, max_output_tokens=4096):
            pytest.fail("No cloud request should be made without selected function pseudocode")
    run = run_for(sample)
    await agent.execute_run(run, Model(), "0x1000")
    assert run["status"] == "failed" and "could not decompile" in run["error"]


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["ollama", "openrouter"])
async def test_truncated_cloud_rewrite_is_not_presented_as_complete(sample, provider):
    def respond(request):
        message = {"role": "assistant", "content": "Partial code [E2]\n```c\nint entry()"}
        return httpx.Response(200, json={"message": message, "done_reason": "length"} if provider == "ollama" else
                              {"choices": [{"message": message, "finish_reason": "length"}]})
    run = run_for(sample)
    await agent.execute_run(run, ProviderClient(provider, "test", "model", httpx.MockTransport(respond)), "0x1000")
    assert run["status"] == "failed" and "cut off" in run["error"]
    assert not run["answer"]
