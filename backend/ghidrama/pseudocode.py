"""Local, cancellable pseudocode extraction with explicit revision and coverage."""
from __future__ import annotations

import asyncio
import json
import threading
import time

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from .analysis import get_function_batch
from .store import Store, normalize_address, utcnow

router = APIRouter(prefix="/api/samples/{sample_id}/pseudocode", tags=["pseudocode"])
MAX_SECONDS = 900
MAX_CHARACTERS = 20_000_000
_tasks: dict[str, tuple[asyncio.Task, threading.Event]] = {}


class PseudocodeStore:
    def __init__(self):
        self.store = Store()
        with self.store.connection() as db:
            db.execute("CREATE TABLE IF NOT EXISTS pseudocode_jobs (sample_id TEXT PRIMARY KEY, data TEXT NOT NULL)")

    def get(self, sample_id: str) -> dict | None:
        with self.store.connection() as db:
            row = db.execute("SELECT data FROM pseudocode_jobs WHERE sample_id=?", (sample_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def save(self, job: dict):
        with self.store.connection() as db:
            db.execute("INSERT INTO pseudocode_jobs VALUES (?,?) ON CONFLICT(sample_id) DO UPDATE SET data=excluded.data",
                       (job["sample_id"], json.dumps(job)))

    def recover(self):
        with self.store.connection() as db:
            jobs = [json.loads(row[0]) for row in db.execute("SELECT data FROM pseudocode_jobs")]
        for job in jobs:
            if job["status"] in {"queued", "running"}:
                job.update(status="interrupted", error="Extraction was interrupted by a restart. Generate again to reuse cached functions.", finished_at=utcnow())
                self.save(job)


def extract(job: dict, cancelled: threading.Event):
    persistence = PseudocodeStore()
    store = persistence.store
    deadline = time.monotonic() + MAX_SECONDS
    job["status"] = "running"
    persistence.save(job)
    try:
        sample = store.get_sample(job["sample_id"])
        if not sample or sample["analysis_revision"] != job["analysis_revision"] or sample["status"] not in {"ready", "partial"}:
            raise ValueError("Analysis changed before pseudocode extraction started. Generate again against the current analysis.")
        functions = store.list_functions(job["sample_id"])
        for offset in range(0, len(functions), 4):
            if cancelled.is_set():
                raise InterruptedError("Extraction cancelled.")
            if time.monotonic() >= deadline:
                raise TimeoutError("Extraction reached its 15-minute limit. Generate again to reuse cached functions.")
            batch = get_function_batch(job["sample_id"], [f["address"] for f in functions[offset:offset + 4]],
                                       job["analysis_revision"], cancel_check=cancelled.is_set)
            for function in batch:
                code = function.get("decompiled") or ""
                if job["characters"] + len(code) > MAX_CHARACTERS:
                    raise ValueError("Pseudocode reached the 20-million-character export limit. Remaining functions can be inspected individually.")
                recovered = bool(code.strip())
                job["functions"].append({"address": function["address"], "name": function["name"],
                                         "available": recovered, "truncated": bool(function.get("decompiled_truncated")),
                                         "error": function.get("decompile_error") if not recovered else None})
                job["processed"] += 1
                job["recovered"] += int(recovered)
                job["failed"] += int(not recovered)
                job["truncated"] += int(bool(function.get("decompiled_truncated")))
                job["characters"] += len(code)
            persistence.save(job)
        job["status"] = "partial" if job["failed"] or job["truncated"] or job["source_partial"] else "complete"
    except InterruptedError:
        job["status"] = "cancelled"
    except (ValueError, TimeoutError) as error:
        job["status"] = "partial" if job["recovered"] else "failed"
        job["error"] = str(error)[-2000:]
    except Exception:
        job["status"] = "partial" if job["recovered"] else "failed"
        job["error"] = "Pseudocode extraction could not finish. Completed functions are retained; retry or inspect individual functions."
    finally:
        if cancelled.is_set():
            job["status"] = "cancelled"
        job["finished_at"] = utcnow()
        persistence.save(job)


def require_sample(sample_id: str) -> dict:
    sample = Store().get_sample(sample_id)
    if not sample:
        raise HTTPException(404, "Sample not found.")
    return sample


class GeneratePseudocode(BaseModel):
    expected_revision: int = Field(ge=1)


@router.get("")
def get_pseudocode(sample_id: str):
    require_sample(sample_id)
    return PseudocodeStore().get(sample_id)


@router.post("", status_code=202)
async def generate(sample_id: str, body: GeneratePseudocode):
    sample = require_sample(sample_id)
    if sample["status"] not in {"ready", "partial"}:
        raise HTTPException(409, "Wait for analysis to finish before extracting pseudocode.")
    if sample["analysis_revision"] != body.expected_revision:
        raise HTTPException(409, "Analysis revision changed. Refresh before generating pseudocode.")
    if sample_id in _tasks:
        raise HTTPException(409, "Pseudocode extraction is already running for this executable.")
    if len(_tasks) >= 2:
        raise HTTPException(429, "Two pseudocode extractions are already running. Wait or cancel one.")
    analysis = Store().get_analysis(sample_id)
    if not analysis or not analysis.get("functions"):
        raise HTTPException(409, "Ghidra did not identify any functions to decompile.")
    job = {"sample_id": sample_id, "analysis_revision": body.expected_revision, "name": sample["name"],
           "sha256": sample["sha256"], "preprocessing": analysis.get("preprocessing"), "status": "queued", "total": len(analysis["functions"]),
           "processed": 0, "recovered": 0, "failed": 0, "truncated": 0, "characters": 0, "functions": [],
           "source_partial": sample["status"] == "partial", "warnings": analysis.get("warnings", []),
           "created_at": utcnow(), "error": None}
    PseudocodeStore().save(job)
    cancelled = threading.Event()
    task = asyncio.create_task(asyncio.to_thread(extract, job, cancelled))
    _tasks[sample_id] = (task, cancelled)
    task.add_done_callback(lambda completed: _tasks.pop(sample_id, None))
    # Return a snapshot: the worker thread will now mutate its own job object.
    return {**job, "functions": list(job["functions"])}


@router.post("/cancel")
async def cancel(sample_id: str):
    require_sample(sample_id)
    if active := _tasks.get(sample_id):
        active[1].set()
        await active[0]
    return PseudocodeStore().get(sample_id)


def comment(value: object) -> str:
    return str(value).replace("*/", "* /").replace("\n", " ").replace("\r", " ")


def export_text(job: dict, store: Store):
    """Stream captured revision caches; never use current-revision function lookup."""
    preprocessing = job.get("preprocessing") or {}
    yield (f"/* Ghidrama: Ghidra C-like pseudocode (not original source; may not compile)\n"
           f" * Sample: {comment(job['name'])}\n * SHA-256: {job['sha256']}\n"
           f" * Analyzed SHA-256: {preprocessing.get('analyzed_sha256', job['sha256'])}\n"
           f" * UPX preprocessing: {preprocessing.get('status', 'not recorded')}\n"
           f" * Analysis revision: {job['analysis_revision']}\n * Extraction status: {job['status']}\n"
           f" * Coverage: {job['recovered']}/{job['total']} indexed functions recovered; "
           f"{job['failed']} failed; {job['truncated']} truncated; {job['total'] - job['processed']} not processed\n"
           f" * Source analysis partial: {job['source_partial']}\n"
           f" * Note: {comment(job.get('error') or 'Review against the disassembly.')}\n */\n\n")
    for warning in job.get("warnings", []):
        yield f"/* Analysis warning: {comment(warning)} */\n"
    for function in job["functions"]:
        address = normalize_address(function["address"])
        yield f"\n/* {comment(function['name'])} at {address} */\n"
        if not function["available"]:
            yield f"/* Unavailable: {comment(function.get('error') or 'Ghidra could not decompile this function.')} */\n"
            continue
        path = store.sample_dir(job["sample_id"]) / "artifacts" / f"function-{job['analysis_revision']}-{address[2:]}.json"
        if not path.is_file():
            yield "/* Cached pseudocode is missing for this function. */\n"
            continue
        detail = json.loads(path.read_text())
        yield (detail.get("decompiled") or "") + "\n"
        if function["truncated"]:
            yield "/* This function's pseudocode was truncated by the extraction limit. */\n"


@router.get("/download")
def download(sample_id: str, revision: int):
    require_sample(sample_id)
    persistence = PseudocodeStore()
    job = persistence.get(sample_id)
    if not job or job["analysis_revision"] != revision:
        raise HTTPException(409, "This pseudocode export is no longer the selected extraction. Refresh and download again.")
    if not job["processed"]:
        raise HTTPException(409, "No pseudocode has been extracted yet.")
    return StreamingResponse(export_text(job, persistence.store), media_type="text/plain; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="ghidrama-{sample_id[:8]}-rev{revision}.c"'})


async def startup():
    PseudocodeStore().recover()


def active_jobs() -> int:
    return sum(not task.done() for task, _ in _tasks.values())


async def shutdown():
    active = list(_tasks.values())
    for _, cancelled in active:
        cancelled.set()
    if active:
        await asyncio.gather(*(task for task, _ in active), return_exceptions=True)
    _tasks.clear()
