"""One-click workflow integration: real MCP, mocked cloud responses and cached Ghidra."""
import asyncio
import io
import json
import zipfile

import httpx
import pytest
from fastapi import HTTPException

from ghidrama import agent, main, workflow
from ghidrama.config import settings
from ghidrama.providers import ProviderClient
from ghidrama.store import Store


@pytest.fixture
def sample(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    store = Store()
    sample = store.create_sample("workflow.exe", "a" * 64, 1024, "x86_64")
    function = {"address": "0x1000", "name": "entry", "size": 100, "decompiled": "void entry(void) {\n" + "/* recovered statement */\n" * 2600 + "return;\n}",
                "disassembly": [], "callers": [], "callees": [], "detail_loaded": True}
    analysis = {"sample_id": sample["id"], "revision": 1, "entry_point": "0x1000", "image_base": "0x1000",
                "functions": [function], "imports": [], "exports": [], "strings": [], "sections": [], "warnings": [],
                "preprocessing": {"status": "unpacked", "original_sha256": "a" * 64, "analyzed_sha256": "b" * 64}}
    store.save_analysis(sample["id"], analysis)
    store.save_function(sample["id"], 1, function)
    return store.update_sample(sample["id"], status="ready")


def mock_cloud(monkeypatch, provider="openrouter", rewrite_answer=None, truncated=False):
    requests = []
    calls = 0
    def respond(request):
        nonlocal calls
        body = json.loads(request.content)
        if request.url.path == "/api/show":
            return httpx.Response(200, json={"thinking": {"values": ["low", "high"]}})
        calls += 1
        requests.append(body)
        if calls == 1:
            message = {"content": "", "tool_calls": [{"id": "inspect", "type": "function", "function": {"name": "decompile_function", "arguments": {"address": "0x1000"}}}]}
        elif calls == 2:
            message = {"content": 'Entry routine [E2].\n```json\n[{"address":"0x1000","reason":"Entry behavior [E2]"}]\n```'}
        else:
            message = {"content": rewrite_answer if rewrite_answer is not None else "AI interpretation of entry [E1].\n```text\nentry(): return\n```"}
        if provider == "ollama":
            return httpx.Response(200, json={"message": message, "prompt_eval_count": 500, "eval_count": 100, "done_reason": "length" if calls > 2 and truncated else "stop"})
        return httpx.Response(200, json={"choices": [{"message": message, "finish_reason": "length" if calls > 2 and truncated else "stop"}], "usage": {"prompt_tokens": 500, "completion_tokens": 100}})
    client = ProviderClient(provider, "workflow-test-secret", "test-model", httpx.MockTransport(respond))
    monkeypatch.setattr(workflow, "configured_client", lambda *args: client)
    monkeypatch.setattr(agent, "configured_client", lambda *args: client)
    return client, requests


async def finish(sample, provider="openrouter"):
    job = await workflow.start(sample["id"], workflow.StartWorkflow(provider=provider, expected_revision=sample["analysis_revision"]))
    await asyncio.wait_for(asyncio.shield(workflow._tasks[sample["id"]]), 30)
    return workflow.WorkflowStore().get(job["id"])


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["openrouter", "ollama"])
async def test_complete_workflow_full_source_and_durable_export(sample, monkeypatch, provider):
    client, requests = mock_cloud(monkeypatch, provider)
    job = await finish(sample, provider)
    assert job["status"] == "complete", job
    assert len(requests) == 3 and len(job["run_ids"]) == 2
    assert job["tokens_reported"] == 1800
    assert "tools" not in requests[-1]
    assert "return;\\n}" in requests[-1]["messages"][-1]["content"]
    if provider == "ollama":
        assert client.thinking == "low" and requests[-1]["think"] == "low"
    result = workflow.download(job["id"])
    with zipfile.ZipFile(io.BytesIO(result.body)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        run_id = job["functions"][0]["run_id"]
        evidence = json.loads(archive.read(f"{run_id}/E1.json"))
        assert len(evidence["decompiled"]) > 24000 and not evidence["truncated"]
        assert manifest["preprocessing"]["analyzed_sha256"] == "b" * 64
        assert all(b"workflow-test-secret" not in archive.read(name) for name in archive.namelist())
    assert not workflow._tasks and not agent._tasks


@pytest.mark.asyncio
@pytest.mark.parametrize("answer,truncated", [("unsupported draft", False), ("cut off [E1]\n```text\nx()\n```", True)])
async def test_invalid_or_truncated_rewrite_is_not_complete(sample, monkeypatch, answer, truncated):
    _, requests = mock_cloud(monkeypatch, rewrite_answer=answer, truncated=truncated)
    job = await finish(sample)
    assert job["status"] == "failed" and len(requests) == 3
    item = job["functions"][0]
    run = agent.RunStore().get(item["run_id"])
    assert item["status"] == run["status"] == "failed"
    assert run["answer"] == answer and agent.RunStore().get_evidence(run["id"], "E1")


@pytest.mark.asyncio
async def test_budget_stops_before_cloud_rewrite(sample, monkeypatch):
    _, requests = mock_cloud(monkeypatch)
    monkeypatch.setattr(workflow, "TOKEN_LIMIT", 80_100)
    job = await finish(sample)
    assert len(requests) == 2 and job["status"] == "failed"
    assert "budget" in job["functions"][0]["error"]


@pytest.mark.asyncio
async def test_legacy_analysis_is_reprepared_before_cloud(sample, monkeypatch):
    mock_cloud(monkeypatch)
    store = Store()
    artifact = store.get_analysis(sample["id"])
    artifact.pop("preprocessing")
    store.save_analysis(sample["id"], artifact)
    submitted = []
    class Manager:
        def submit(self, sample_id):
            submitted.append(sample_id)
            artifact.update(revision=2, preprocessing={"status": "unpacked", "analyzed_sha256": "b" * 64})
            store.save_analysis(sample_id, artifact)
            store.save_function(sample_id, 2, artifact["functions"][0])
            store.update_sample(sample_id, status="ready")
    monkeypatch.setattr(main, "manager", Manager())
    job = await finish(sample)
    assert submitted == [sample["id"]] and job["analysis_revision"] == 2 and job["status"] == "complete"


@pytest.mark.asyncio
async def test_cancel_preserves_other_analysis_and_rejects_duplicate(sample, monkeypatch):
    mock_cloud(monkeypatch)
    Store().update_sample(sample["id"], status="analyzing")
    job = await workflow.start(sample["id"], workflow.StartWorkflow(provider="openrouter", expected_revision=1))
    await asyncio.sleep(0.02)
    with pytest.raises(HTTPException) as error:
        await workflow.start(sample["id"], workflow.StartWorkflow(provider="openrouter", expected_revision=1))
    assert error.value.status_code == 409
    with pytest.raises(HTTPException):
        await main.analyze_sample(sample["id"])
    result = await workflow.cancel(sample["id"])
    assert result["id"] == job["id"] and result["status"] == "cancelled"
    assert Store().get_sample(sample["id"])["status"] == "analyzing"


@pytest.mark.asyncio
async def test_stale_start_and_invalid_selection(sample, monkeypatch):
    mock_cloud(monkeypatch)
    with pytest.raises(HTTPException) as error:
        await workflow.start(sample["id"], workflow.StartWorkflow(provider="openrouter", expected_revision=2))
    assert error.value.status_code == 409
    for answer in ['```json\n[{"address":"0xdead"}]\n```', '```json\n[{"address":"0x1000"},{"address":"0x1000"}]\n```', '```json\n{"address":"0x1000"}\n```']:
        with pytest.raises(ValueError):
            workflow.selection(answer, sample["id"], 5)


@pytest.mark.asyncio
async def test_restart_retains_results_without_cloud_resumption(sample, monkeypatch):
    mock_cloud(monkeypatch)
    job = await finish(sample)
    job["status"] = "running"
    workflow.WorkflowStore().save(job)
    await workflow.startup()
    saved = workflow.WorkflowStore().get(job["id"])
    assert saved["status"] == "interrupted" and saved["run_ids"] == job["run_ids"]
    assert not workflow._tasks


@pytest.mark.asyncio
async def test_cancel_before_coroutine_starts(sample, monkeypatch):
    mock_cloud(monkeypatch)
    await workflow.start(sample["id"], workflow.StartWorkflow(provider="openrouter", expected_revision=1))
    assert (await workflow.cancel(sample["id"]))["status"] == "cancelled"


@pytest.mark.asyncio
async def test_investigator_cancel_stops_workflow_request(sample, monkeypatch):
    client, _ = mock_cloud(monkeypatch)
    original = client.chat
    entered = asyncio.Event()
    async def slow(messages, tools, **kwargs):
        if not tools:
            entered.set()
            await asyncio.sleep(30)
        return await original(messages, tools, **kwargs)
    monkeypatch.setattr(client, "chat", slow)
    job = await workflow.start(sample["id"], workflow.StartWorkflow(provider="openrouter", expected_revision=1))
    await asyncio.wait_for(entered.wait(), 15)
    current = workflow.WorkflowStore().get(job["id"])
    run = await agent.cancel_run(current["functions"][0]["run_id"])
    assert run["status"] == "cancelled"
    assert workflow.WorkflowStore().get(job["id"])["status"] == "cancelled"
    assert not workflow._tasks and not agent._tasks


@pytest.mark.asyncio
async def test_revision_change_during_rewrite_is_explicit(sample, monkeypatch):
    client, _ = mock_cloud(monkeypatch)
    original = client.chat
    async def change(messages, tools, **kwargs):
        response = await original(messages, tools, **kwargs)
        if not tools:
            Store().update_sample(sample["id"], analysis_revision=2)
        return response
    monkeypatch.setattr(client, "chat", change)
    job = await finish(sample)
    assert job["status"] == "failed" and "Analysis changed" in job["functions"][0]["error"]
