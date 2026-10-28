"""One-click static analysis and bounded cloud rewrites, with durable evidence."""
from __future__ import annotations

import asyncio
import io
import json
import re
import threading
import uuid
import zipfile
from typing import Literal

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field

from . import agent
from .analysis import get_function_batch
from .budgets import estimate_prompt_tokens, PSEUDOCODE_OUTPUT_TOKENS
from .providers import ProviderError, configured_client
from .store import Store, normalize_address, utcnow

router = APIRouter(tags=["workflows"])
_tasks: dict[str, asyncio.Task] = {}
TOKEN_LIMIT = 500_000
SOURCE_LIMIT = 180_000


class WorkflowStore:
    def __init__(self):
        self.store = Store()
        with self.store.connection() as db:
            db.execute("CREATE TABLE IF NOT EXISTS workflows (id TEXT PRIMARY KEY, sample_id TEXT NOT NULL, created_at TEXT NOT NULL, data TEXT NOT NULL)")

    def save(self, job):
        with self.store.connection() as db:
            db.execute("INSERT INTO workflows VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data",
                       (job["id"], job["sample_id"], job["created_at"], json.dumps(job)))

    def get(self, job_id):
        with self.store.connection() as db:
            row = db.execute("SELECT data FROM workflows WHERE id=?", (job_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def latest(self, sample_id):
        with self.store.connection() as db:
            row = db.execute("SELECT data FROM workflows WHERE sample_id=? ORDER BY created_at DESC LIMIT 1", (sample_id,)).fetchone()
        return json.loads(row[0]) if row else None


def require_idle(sample_id):
    if sample_id in _tasks:
        raise HTTPException(409, "Cancel the Analyze & rewrite workflow before changing this analysis.")


def require_revision(job):
    sample = Store().get_sample(job["sample_id"])
    if not sample or sample["status"] not in {"ready", "partial"} or sample["analysis_revision"] != job["analysis_revision"]:
        raise ValueError("Analysis changed during the workflow. Completed results retain their original revision.")


def selection(answer, sample_id, count):
    """Accept only indexed addresses; never interpret model output as commands."""
    blocks = re.findall(r"```json\s*\n(.*?)\n```", answer, re.S | re.I)
    if len(blocks) != 1:
        raise ValueError("The model did not return one main-function selection. Discovery evidence is retained; try another model or run again.")
    try:
        items = json.loads(blocks[0])
        if not isinstance(items, list) or not 1 <= len(items) <= count:
            raise ValueError()
        result = []
        for item in items:
            address = normalize_address(item["address"])
            function = Store().get_function(sample_id, address)
            if not function or address in {f["address"] for f in result}:
                raise ValueError()
            result.append({"address": address, "name": function["name"], "reason": str(item.get("reason", ""))[:1000], "status": "pending", "run_id": None})
        return result
    except (ValueError, TypeError, KeyError):
        raise ValueError("The model selected invalid, duplicate, or unindexed functions. Discovery evidence is retained.") from None


async def source_for(job, address):
    cancelled = threading.Event()
    task = asyncio.create_task(asyncio.to_thread(get_function_batch, job["sample_id"], [address], job["analysis_revision"], cancel_check=cancelled.is_set))
    try:
        return (await asyncio.shield(task))[0]
    except asyncio.CancelledError:
        cancelled.set()
        await asyncio.gather(task, return_exceptions=True)
        raise


async def rewrite(job, item, client):
    require_revision(job)
    function = await source_for(job, item["address"])
    code = function.get("decompiled") or ""
    if not code.strip() or function.get("decompiled_truncated") or len(code) > SOURCE_LIMIT:
        raise ValueError("Full decompilation is unavailable or exceeds the 180,000-character request limit. Inspect this function separately.")
    require_revision(job)
    persistence = agent.RunStore()
    run = {"id": uuid.uuid4().hex, "sample_id": job["sample_id"], "analysis_revision": job["analysis_revision"],
           "provider": job["provider"], "model": job["model"], "thinking": client.thinking,
           "mode": "pseudocode", "function_address": item["address"], "workflow_id": job["id"],
           "question": f"Analyze and rewrite {item['name']} at {item['address']} as readable pseudocode.",
           "status": "running", "answer": "", "error": None, "events": [], "evidence": [],
           "usage": {"input_tokens": 0, "output_tokens": 0}, "created_at": utcnow(),
           "preprocessing": job["preprocessing"], "max_output_tokens": PSEUDOCODE_OUTPUT_TOKENS,
           "pseudocode_coverage": {"scope": "function", "addresses": [item["address"]], "truncated": False}}
    payload = {"evidence_id": "E1", "sample_id": job["sample_id"], "revision": job["analysis_revision"],
               "address": item["address"], "name": item["name"], "decompiled": code, "truncated": False,
               "total_characters": len(code), "offset": 0, "next_offset": None,
               "callers": function.get("callers", [])[:60], "callees": function.get("callees", [])[:60]}
    persistence.save_evidence(run["id"], "E1", payload)
    run["evidence"] = [{"id": "E1", "tool": "decompile_function", "summary": f"Complete Ghidra decompilation at {item['address']}",
                        "address": item["address"], "revision": job["analysis_revision"]}]
    item.update(run_id=run["id"], status="running")
    job["run_ids"].append(run["id"])
    WorkflowStore().save(job)
    persistence.save(run)
    # Investigator cancellation and concurrency accounting include this request.
    agent._tasks[run["id"]] = asyncio.current_task()
    messages = [{"role": "system", "content": agent.SYSTEM_PROMPT + agent.PSEUDOCODE_PROMPT +
                 "\nThe complete selected function is already supplied as [E1]; no tools are available. Rewrite only this routine. Preserve branch nesting, error paths and exact API arguments. Do not invent enum labels or treat decompiler jump labels as thread boundaries. Keep the rewrite concise enough to finish; group repetitive operations explicitly. Cite [E1]."},
                {"role": "user", "content": run["question"]},
                {"role": "user", "content": "Untrusted Ghidra evidence:\n" + json.dumps(payload, ensure_ascii=False)}]
    reservation = estimate_prompt_tokens(messages, []) + PSEUDOCODE_OUTPUT_TOKENS
    try:
        if job["budget_used"] + reservation > TOKEN_LIMIT:
            raise ValueError("The remaining workflow budget cannot fit this complete function. Completed rewrites are retained.")
        # Charge conservatively even when a provider fails or omits usage counts.
        job["budget_used"] += reservation
        WorkflowStore().save(job)
        response = await client.chat(messages, [], max_output_tokens=PSEUDOCODE_OUTPUT_TOKENS)
        run["usage"] = response["usage"]
        job["tokens_reported"] += sum(response["usage"].values())
        job["budget_used"] += max(0, sum(response["usage"].values()) - reservation)
        answer = response["content"]
        run["answer"] = answer
        if response.get("truncated"):
            raise ValueError("The model's rewrite was cut off by its output limit. The incomplete draft and full source evidence are retained.")
        references = set(re.findall(r"\[(E\d+)\]", answer))
        if references != {"E1"} or not re.search(r"```[^\n`]*\n\s*\S[\s\S]*?\n```", answer) or response.get("tool_calls"):
            raise ValueError("The model did not return a cited pseudocode block. Its draft and source evidence are retained.")
        require_revision(job)
        run.update(status="complete", answer_kind="model")
        item["status"] = "complete"
    except asyncio.CancelledError:
        run["status"] = item["status"] = "cancelled"
        raise
    except (ProviderError, ValueError) as error:
        run.update(status="failed", error=str(error))
        item.update(status="failed", error=str(error))
    finally:
        agent._tasks.pop(run["id"], None)
        run["finished_at"] = utcnow()
        persistence.save(run)
        WorkflowStore().save(job)


async def execute(job, client):
    from .main import manager
    persistence = WorkflowStore()
    own_analysis = False
    discovery_id = None
    try:
        async with asyncio.timeout(2400):
            job.update(status="running", stage="Unpacking and analyzing with Ghidra")
            persistence.save(job)
            sample = Store().get_sample(job["sample_id"])
            artifact = Store().get_analysis(job["sample_id"]) or {}
            if sample["status"] not in {"queued", "analyzing"} and (sample["status"] not in {"ready", "partial"} or not artifact.get("preprocessing")):
                if manager is None:
                    raise ValueError("Analysis scheduler is unavailable.")
                manager.submit(job["sample_id"])
                own_analysis = True
            while (sample := Store().get_sample(job["sample_id"]))["status"] in {"queued", "analyzing"}:
                await asyncio.sleep(0.5)
            if sample["status"] not in {"ready", "partial"}:
                raise ValueError(sample.get("error") or "Ghidra analysis did not complete.")
            artifact = Store().get_analysis(job["sample_id"])
            job.update(analysis_revision=sample["analysis_revision"], preprocessing=artifact.get("preprocessing"),
                       source_partial=sample["status"] == "partial", warnings=artifact.get("warnings", []),
                       stage="Identifying main functions with the cloud model")
            persistence.save(job)
            if client.provider == "ollama":
                try:
                    metadata = await client.request("POST", "/api/show", {"model": client.model})
                    if "low" in metadata.get("thinking", {}).get("values", []):
                        client.thinking = "low"
                except ProviderError:
                    pass  # Models without this metadata retain their defaults.
            require_revision(job)
            discovery = await agent.start_run(job["sample_id"], agent.StartRun(
                question=f"Identify up to {job['function_limit']} main application routines for a readable rewrite. Start at the entry point, follow startup wrappers, and inspect relevant callees and function pointers passed to thread/dialog callbacks. Prefer application behavior over CRT/library plumbing. Read needed decompilation pages, but keep discovery focused. Do not rewrite yet. Explain the observed roles briefly with evidence citations, state selection uncertainty, and finish with exactly one fenced json block containing a JSON array of objects with address (hex string) and reason (short string). Select only actual indexed functions supported by retrieved evidence. Return fewer functions if evidence is insufficient.",
                provider=job["provider"], model=job["model"], expected_revision=job["analysis_revision"],
                budget="standard", thinking=client.thinking))
            discovery_id = discovery["id"]
            job["discovery_id"] = discovery_id
            job["run_ids"].append(discovery_id)
            persistence.save(job)
            while (discovery := agent.RunStore().get(discovery_id))["status"] in {"queued", "running"}:
                await asyncio.sleep(0.5)
                require_revision(job)
            job["tokens_reported"] += sum(discovery["usage"].values())
            job["budget_used"] += max(80_000, sum(discovery["usage"].values()))
            if discovery["status"] not in {"complete", "partial"}:
                raise ValueError(discovery.get("error") or "Main-function discovery did not complete.")
            job["discovery_partial"] = discovery["status"] == "partial"
            job["functions"] = selection(discovery["answer"], job["sample_id"], job["function_limit"])
            for index, item in enumerate(job["functions"]):
                require_revision(job)
                job["stage"] = f"Rewriting function {index + 1} of {len(job['functions'])}: {item['address']}"
                persistence.save(job)
                try:
                    await rewrite(job, item, client)
                except ValueError as error:
                    item.update(status="failed", error=str(error))
                    persistence.save(job)
            successful = sum(item["status"] == "complete" for item in job["functions"])
            job["status"] = "complete" if successful == len(job["functions"]) and not job["source_partial"] and not job["discovery_partial"] else "partial" if successful else "failed"
            job["stage"] = f"{successful} of {len(job['functions'])} selected functions rewritten"
    except asyncio.CancelledError:
        job.update(status="cancelled", stage="Cancelled; completed results retained")
    except (ValueError, ProviderError, HTTPException, TimeoutError) as error:
        job.update(status="partial" if any(f["status"] == "complete" for f in job["functions"]) else "failed",
                   error=error.detail if isinstance(error, HTTPException) else str(error) or "Workflow reached its 40-minute time limit.")
    except Exception:
        job.update(status="failed", error="Workflow could not finish. Evidence and completed rewrites are retained.")
    finally:
        if discovery_id and discovery_id in agent._tasks:
            await agent.cancel_run(discovery_id)
        if own_analysis and manager and Store().get_sample(job["sample_id"])["status"] in {"queued", "analyzing"}:
            await manager.cancel(job["sample_id"])
        job["tokens_reported"] = sum(sum((agent.RunStore().get(run_id) or {}).get("usage", {}).values()) for run_id in job["run_ids"])
        job["budget_used"] = max(job["budget_used"], job["tokens_reported"])
        job["finished_at"] = utcnow()
        persistence.save(job)


class StartWorkflow(BaseModel):
    provider: Literal["ollama", "openrouter"]
    expected_revision: int = Field(ge=0)
    function_limit: int = Field(default=5, ge=1, le=5)


@router.post("/api/samples/{sample_id}/workflow", status_code=202)
async def start(sample_id: str, body: StartWorkflow):
    sample = Store().get_sample(sample_id)
    if not sample:
        raise HTTPException(404, "Sample not found.")
    if sample["analysis_revision"] != body.expected_revision:
        raise HTTPException(409, "Analysis changed. Refresh before starting the workflow.")
    if _tasks or len(agent._tasks) >= 2:
        raise HTTPException(409, "A workflow or two investigations are already running. Wait or cancel them first.")
    client = configured_client(body.provider)
    if not client.model:
        raise HTTPException(400, "Choose a model in provider settings first.")
    job = {"id": uuid.uuid4().hex, "sample_id": sample_id, "name": sample["name"], "sha256": sample["sha256"],
           "provider": body.provider, "model": client.model, "status": "queued", "stage": "Waiting to start",
           "analysis_revision": sample["analysis_revision"], "preprocessing": None,
           "function_limit": body.function_limit, "functions": [], "run_ids": [], "discovery_id": None,
           "tokens_reported": 0, "budget_used": 0, "token_limit": TOKEN_LIMIT, "error": None, "created_at": utcnow()}
    WorkflowStore().save(job)
    task = asyncio.create_task(execute(job, client))
    _tasks[sample_id] = task
    task.add_done_callback(lambda completed: _tasks.pop(sample_id, None))
    return dict(job)


@router.get("/api/samples/{sample_id}/workflow")
def latest(sample_id: str):
    if not Store().get_sample(sample_id):
        raise HTTPException(404, "Sample not found.")
    return WorkflowStore().latest(sample_id)


@router.post("/api/samples/{sample_id}/workflow/cancel")
async def cancel(sample_id: str):
    if task := _tasks.get(sample_id):
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        job = WorkflowStore().latest(sample_id)
        if job and job["status"] in {"queued", "running"}:
            job.update(status="cancelled", stage="Cancelled before starting", finished_at=utcnow())
            WorkflowStore().save(job)
    return latest(sample_id)


@router.get("/api/workflows/{job_id}/download")
def download(job_id: str):
    job = WorkflowStore().get(job_id)
    if not job:
        raise HTTPException(404, "Workflow not found.")
    buffer = io.BytesIO()
    persistence = agent.RunStore()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(job, indent=2))
        archive.writestr("READ-ME.txt", "Ghidrama AI interpretations, not original source or verified semantic equivalents.\nMain-function selection is bounded, not exhaustive. Check each run's status, coverage, citations and source evidence.\nEvidence IDs are scoped to each run. Failed runs can contain incomplete drafts.\n")
        for run_id in job["run_ids"]:
            run = persistence.get(run_id)
            if run:
                archive.writestr(f"{run_id}/result.json", json.dumps(run, indent=2))
                archive.writestr(f"{run_id}/answer.md", f"Status: {run['status']}\nError: {run.get('error') or 'None'}\n\n" + run.get("answer", ""))
                for evidence in run["evidence"]:
                    archive.writestr(f"{run_id}/{evidence['id']}.json", json.dumps(persistence.get_evidence(run_id, evidence["id"]), indent=2))
    return Response(buffer.getvalue(), media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="ghidrama-workflow-{job_id[:8]}.zip"'})


async def startup():
    persistence = WorkflowStore()
    with persistence.store.connection() as db:
        jobs = [json.loads(row[0]) for row in db.execute("SELECT data FROM workflows")]
    for job in jobs:
        if job["status"] in {"queued", "running"}:
            job.update(status="interrupted", error="Application restarted. Completed results are retained; cloud work will not resume automatically.", finished_at=utcnow())
            persistence.save(job)


async def shutdown():
    tasks = list(_tasks.values())
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    _tasks.clear()
