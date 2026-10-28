"""Regression tests for cumulative budgets, finalization and evidence retention."""
import json
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from ghidrama import agent
from ghidrama.budgets import BUDGETS, estimate_prompt_tokens, finishing_reason, request_size
from ghidrama.config import settings
from ghidrama.providers import ProviderClient
from ghidrama.store import Store


@pytest.fixture
def sample(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    store = Store()
    item = store.create_sample("budget-test.exe", "a" * 64, 1024, "x86_64")
    store.save_analysis(item["id"], {"sample_id": item["id"], "revision": 1, "entry_point": "0x1000",
        "functions": [{"address": "0x1000", "name": "entry", "size": 8}], "warnings": [], "sections": []})
    return store.update_sample(item["id"], status="ready")


def new_run(sample, budget="extended"):
    return {"id": uuid.uuid4().hex, "sample_id": sample["id"], "analysis_revision": 1,
        "question": "What functions were found?", "provider": "ollama", "model": "test/model", "mode": "investigation",
        "budget": budget, "limits": dict(BUDGETS[budget]), "status": "queued", "answer": "", "error": None,
        "events": [], "evidence": [], "usage": {"input_tokens": 0, "output_tokens": 0}, "created_at": agent.now()}


def response(content="", calls=None, input_tokens=12100):
    return {"role": "assistant", "content": content, "tool_calls": calls or [],
            "usage": {"input_tokens": input_tokens, "output_tokens": 45}}


def tool_call(index):
    return {"id": f"lookup-{index}", "type": "function", "function": {
        "name": "list_functions", "arguments": json.dumps({"query": f"lookup-{index}"})}}


def test_actual_failure_usage_fits_extended_budget():
    # Observed failure: 84,519 input + 311 output tokens after seven turns.
    progress = dict(used=84830, prompt_tokens=13000, turns=7, tools=12, seconds_left=550)
    assert finishing_reason(BUDGETS["extended"], **progress) is None
    assert "80,000" in finishing_reason(BUDGETS["standard"], **progress)


def test_pseudocode_reserves_its_larger_generation_and_time_allowance():
    progress = dict(used=160000, prompt_tokens=20000, turns=3, tools=5, seconds_left=550)
    assert finishing_reason(BUDGETS["extended"], **progress) is None
    assert "250,000" in finishing_reason(BUDGETS["extended"], **progress, output_tokens=12288)
    progress.update(used=1000, seconds_left=180)
    assert finishing_reason(BUDGETS["extended"], **progress) is None
    assert "time limit" in finishing_reason(BUDGETS["extended"], **progress, output_tokens=12288)


def test_prompt_estimate_uses_provider_usage_and_includes_tool_schemas():
    messages = [{"role": "user", "content": "x" * 3000}]
    tools = [{"description": "y" * 3000}]
    size = request_size(messages, tools)
    baseline = estimate_prompt_tokens(messages, tools)
    calibrated = estimate_prompt_tokens(messages, tools, previous_tokens=10000, previous_size=size)
    assert calibrated > baseline
    assert baseline > estimate_prompt_tokens(messages, [])


class ExploringModel:
    def __init__(self):
        self.requests = []

    async def chat(self, messages, tools, *, max_output_tokens=4096):
        self.requests.append((messages, tools, max_output_tokens))
        if not tools or len(self.requests) == 8:
            return response("One indexed function was found. Coverage is limited to the retrieved evidence. [E1]")
        return response(calls=[tool_call(len(self.requests))])


@pytest.mark.asyncio
async def test_extended_run_passes_old_80k_ceiling_and_finishes(sample):
    run, model = new_run(sample), ExploringModel()
    await agent.execute_run(run, model)
    assert run["status"] == "complete", run
    assert len(model.requests) == 8
    assert sum(run["usage"].values()) > 80000
    assert run["limits"]["total_tokens"] == 250000
    assert "One indexed function" in run["answer"]
    assert not run.get("limit_reason")


@pytest.mark.asyncio
async def test_standard_budget_winds_down_to_downloadable_partial_findings(sample):
    run, model = new_run(sample, "standard"), ExploringModel()
    await agent.execute_run(run, model)
    assert run["status"] == "partial", run
    assert run["answer_kind"] == "model"
    assert run["error"] is None
    assert "80,000" in run["limit_reason"]
    assert 1 < len(model.requests) < 8
    assert model.requests[-1][1] == []
    assert sum(run["usage"].values()) < 80000
    assert "Do not request any more tools" in model.requests[-1][0][-1]["content"]
    assert all(agent.RunStore().get_evidence(run["id"], item["id"]) is not None for item in run["evidence"])
    exported = agent.download_run(run["id"]).body.decode()
    assert "Status: partial" in exported and "One indexed function" in exported and "Captured evidence" in exported
    from ghidrama.main import report
    assert "Status: partial" in report(sample["id"]).body.decode()


@pytest.mark.asyncio
async def test_exhausted_budget_makes_no_model_request_and_labels_evidence_only(sample):
    run, model = new_run(sample), ExploringModel()
    run["limits"]["total_tokens"] = 100
    await agent.execute_run(run, model)
    assert not model.requests
    assert run["status"] == "partial" and run["answer_kind"] == "evidence_index"
    assert "No final model answer" in run["answer"]
    assert "not model findings" in run["answer"]
    assert agent.RunStore().get_evidence(run["id"], "E1")["function_count"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(("limit", "value", "notice"), [("model_turns", 2, "model-turn"), ("tool_calls", 2, "tool-call"), ("seconds", 94, "time limit")])
async def test_other_limits_reserve_a_final_answer(sample, limit, value, notice):
    run, model = new_run(sample), ExploringModel()
    run["limits"][limit] = value
    await agent.execute_run(run, model)
    assert run["status"] == "partial" and run["answer_kind"] == "model", run
    assert notice in run["limit_reason"]
    assert len(model.requests) == 1 and model.requests[0][1] == []


@pytest.mark.asyncio
async def test_model_cannot_execute_tools_during_finalization(sample):
    class Model:
        async def chat(self, messages, tools, *, max_output_tokens=4096):
            assert tools == []
            return response(calls=[tool_call(1)])
    run = new_run(sample)
    run["limits"]["model_turns"] = 2
    await agent.execute_run(run, Model())
    assert run["status"] == "partial" and run["answer_kind"] == "evidence_index"
    assert len(run["evidence"]) == 1


@pytest.mark.asyncio
async def test_finalization_still_repairs_invalid_citations(sample):
    class Model:
        calls = 0
        async def chat(self, messages, tools, *, max_output_tokens=4096):
            self.calls += 1
            assert tools == []
            return response("One function. [E999]" if self.calls == 1 else "One function. [E1]", input_tokens=100)
    run, model = new_run(sample), Model()
    run["limits"]["model_turns"] = 2
    await agent.execute_run(run, model)
    assert model.calls == 2 and run["status"] == "partial"
    assert "[E999]" not in run["answer"] and "[E1]" in run["answer"]


@pytest.mark.asyncio
async def test_unexpected_provider_usage_overshoot_stops_before_more_tools(sample):
    class Model:
        calls = 0
        async def chat(self, messages, tools, *, max_output_tokens=4096):
            self.calls += 1
            return response(calls=[tool_call(1)], input_tokens=300000)
    run, model = new_run(sample), Model()
    await agent.execute_run(run, model)
    assert model.calls == 1 and run["status"] == "partial"
    assert len(run["evidence"]) == 1
    assert "250,000-token budget" in run["limit_reason"]


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["ollama", "openrouter"])
async def test_provider_honors_output_allowance_and_omits_finalization_tools(provider):
    def respond(request):
        body = json.loads(request.content)
        assert "tools" not in body
        message = {"role": "assistant", "content": "Final findings [E1]"}
        if provider == "ollama":
            assert body["options"]["num_predict"] == 1024
            return httpx.Response(200, json={"message": message})
        assert body["max_tokens"] == 1024
        return httpx.Response(200, json={"choices": [{"message": message}]})
    client = ProviderClient(provider, "test-key", "test-model", httpx.MockTransport(respond))
    await client.chat([{"role": "user", "content": "Finish"}], [], max_output_tokens=1024)


def test_api_validates_budget_and_snapshots_server_limits(sample, monkeypatch):
    from ghidrama.main import app
    monkeypatch.setattr(agent, "configured_client", lambda *args: ProviderClient("ollama", "unused", "test-model"))
    async def complete(run, client, function_address=None):
        run["status"] = "complete"
        agent.RunStore().save(run)
    monkeypatch.setattr(agent, "execute_run", complete)
    with TestClient(app) as client:
        path = f"/api/samples/{sample['id']}/runs"
        body = {"question": "Inspect", "provider": "ollama", "expected_revision": 1}
        default = client.post(path, json=body)
        assert default.status_code == 202
        assert default.json()["budget"] == "extended"
        assert default.json()["limits"]["total_tokens"] == 250000
        deep = client.post(path, json={**body, "budget": "deep", "limits": {"total_tokens": 999999999}})
        assert deep.status_code == 202
        assert deep.json()["limits"] == BUDGETS["deep"]
        assert client.post(path, json={**body, "budget": "unlimited"}).status_code == 422
