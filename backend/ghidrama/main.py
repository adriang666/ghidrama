"""HTTP application for the local Ghidrama workbench."""
from __future__ import annotations

import asyncio
import fcntl
import hashlib
import importlib.util
import os
import shutil
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .analysis import AnalysisManager, apply_annotation, get_function_detail, inspect_pe
from .config import settings
from .store import Store


manager: AnalysisManager | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global manager
    store = Store()
    # The local scheduler owns recovery and cancellation for this data directory.
    # Reject multiple API processes instead of letting one recover another's jobs.
    with (store.data_dir / "server.lock").open("a") as server_lock:
        try:
            fcntl.flock(server_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Another Ghidrama server is already using this data directory. Run one API process per data directory.") from None
        try:
            store.recover_jobs()
            manager = AnalysisManager()
            from . import agent, pseudocode, workflow
            await agent.startup()
            await pseudocode.startup()
            await workflow.startup()
            try:
                yield
            finally:
                await workflow.shutdown()
                await agent.shutdown()
                await pseudocode.shutdown()
                await manager.shutdown()
        finally:
            fcntl.flock(server_lock, fcntl.LOCK_UN)


app = FastAPI(title="Ghidrama", version="0.1.0", lifespan=lifespan)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)


@app.middleware("http")
async def browser_boundary(request: Request, call_next):
    # Reject obviously oversized uploads before the multipart parser creates its
    # spooled files. The upload handler also enforces the actual file-byte limit.
    if request.method == "POST" and request.url.path == "/api/samples":
        declared_length = request.headers.get("content-length")
        if declared_length is not None:
            try:
                length = int(declared_length)
            except ValueError:
                return JSONResponse({"detail": "Invalid Content-Length."}, status_code=400)
            if length < 0:
                return JSONResponse({"detail": "Invalid Content-Length."}, status_code=400)
            if length > (settings.max_upload_mb + 1) * 1024 * 1024:
                return JSONResponse({"detail": f"Upload exceeds the {settings.max_upload_mb} MB limit."}, status_code=413)
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        origin = request.headers.get("origin")
        if request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse({"detail": "Cross-site requests are not allowed."}, status_code=403)
        if origin:
            parsed = urlparse(origin)
            allowed = {f"{request.url.scheme}://{request.url.netloc}", "http://localhost:5173", "http://127.0.0.1:5173"}
            if parsed.scheme not in {"http", "https"} or origin not in allowed:
                return JSONResponse({"detail": "Only requests from this workbench are allowed."}, status_code=403)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    if request.url.path.startswith("/api"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(ValueError)
async def bad_value(request: Request, error: ValueError):
    return JSONResponse({"detail": str(error)}, status_code=400)


def require_sample(sample_id: str) -> dict:
    sample = Store().get_sample(sample_id)
    if not sample:
        raise HTTPException(404, "Sample not found.")
    return sample


@app.get("/api/health")
def health():
    from . import pseudocode, workflow
    java = bool((settings.java_home and (settings.java_home / "bin/java").is_file()) or shutil.which("java"))
    pyghidra = importlib.util.find_spec("pyghidra") is not None
    return {"status": "ok", "ghidra_available": settings.ghidra_available and java and pyghidra, "ghidra_version": settings.ghidra_version, "upx_available": settings.upx_executable is not None, "max_unpacked_mb": settings.max_unpacked_mb, "java_available": java, "pyghidra_available": pyghidra, "active_jobs": (manager.active_jobs if manager else 0) + pseudocode.active_jobs() + len(workflow._tasks), "max_upload_mb": settings.max_upload_mb}


@app.get("/api/samples")
def list_samples():
    return Store().list_samples()


@app.post("/api/samples", status_code=202)
async def upload_sample(file: UploadFile = File(...)):
    store = Store()
    staging = store.data_dir / "uploads"
    staging.mkdir(exist_ok=True, mode=0o700)
    temporary = staging / uuid.uuid4().hex
    digest = hashlib.sha256()
    size = 0
    limit = settings.max_upload_mb * 1024 * 1024
    try:
        with temporary.open("xb") as out:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > limit:
                    raise HTTPException(413, f"Upload exceeds the {settings.max_upload_mb} MB limit.")
                digest.update(chunk)
                out.write(chunk)
        if not size:
            raise HTTPException(400, "The uploaded file is empty.")
        metadata = await asyncio.to_thread(inspect_pe, temporary)
        name = (file.filename or "sample.exe").replace("\\", "/").rsplit("/", 1)[-1][:200]
        name = "".join(c for c in name if c.isprintable()) or "sample.exe"
        sample = store.create_sample(name, digest.hexdigest(), size, metadata["architecture"])
        original = store.sample_dir(sample["id"]) / "original.bin"
        temporary.replace(original)
        original.chmod(0o400)
        if manager is None:
            store.update_sample(sample["id"], status="failed", error="Analysis scheduler is unavailable.")
        else:
            manager.submit(sample["id"])
        return store.get_sample(sample["id"])
    finally:
        temporary.unlink(missing_ok=True)
        await file.close()


@app.get("/api/samples/{sample_id}")
def sample_details(sample_id: str):
    return require_sample(sample_id)


@app.post("/api/samples/{sample_id}/analyze", status_code=202)
async def analyze_sample(sample_id: str):
    require_sample(sample_id)
    from .workflow import require_idle
    require_idle(sample_id)
    if not manager:
        raise HTTPException(503, "Analysis scheduler is unavailable.")
    manager.submit(sample_id)
    return Store().get_sample(sample_id)


@app.post("/api/samples/{sample_id}/cancel")
async def cancel_sample(sample_id: str):
    require_sample(sample_id)
    return await manager.cancel(sample_id) if manager else Store().get_sample(sample_id)


@app.get("/api/samples/{sample_id}/analysis")
def sample_analysis(sample_id: str):
    require_sample(sample_id)
    analysis = Store().get_analysis(sample_id)
    if not analysis:
        raise HTTPException(409, "Analysis results are not available yet.")
    return analysis


@app.get("/api/samples/{sample_id}/functions")
def list_functions(sample_id: str, q: str = ""):
    require_sample(sample_id)
    return Store().list_functions(sample_id, q[:256])


@app.get("/api/samples/{sample_id}/functions/{address}")
async def function_details(sample_id: str, address: str):
    require_sample(sample_id)
    if not Store().get_function(sample_id, address):
        raise HTTPException(404, "Function not found.")
    return await asyncio.to_thread(get_function_detail, sample_id, address)


class AnnotationProposal(BaseModel):
    address: str
    kind: Literal["rename", "comment"]
    value: str = Field(max_length=8000)
    expected_revision: int = Field(ge=1)


@app.get("/api/samples/{sample_id}/annotations")
def annotations(sample_id: str):
    require_sample(sample_id)
    return Store().list_annotations(sample_id)


@app.post("/api/samples/{sample_id}/annotations", status_code=201)
def propose_annotation(sample_id: str, proposal: AnnotationProposal):
    require_sample(sample_id)
    return Store().create_annotation(sample_id, **proposal.model_dump())


@app.post("/api/samples/{sample_id}/annotations/{annotation_id}/apply")
async def commit_annotation(sample_id: str, annotation_id: str):
    require_sample(sample_id)
    from .workflow import require_idle
    require_idle(sample_id)
    if not Store().get_annotation(sample_id, annotation_id):
        raise HTTPException(404, "Annotation not found.")
    return await asyncio.to_thread(apply_annotation, sample_id, annotation_id)


@app.get("/api/samples/{sample_id}/report")
def report(sample_id: str):
    sample = require_sample(sample_id)
    store = Store()
    analysis = store.get_analysis(sample_id)
    if not analysis:
        raise HTTPException(409, "Analyze this sample before exporting a report.")
    lines = [f"# Ghidrama analysis: {sample['name']}", "", f"SHA-256: `{sample['sha256']}`", f"Architecture: {sample['architecture']}", f"Analysis revision: {sample['analysis_revision']}", f"Status: {sample['status']}", f"Engine: Ghidra {analysis.get('engine', {}).get('version', 'unknown')}", "", "## Analysis warnings", ""]
    preprocessing = analysis.get("preprocessing", {})
    if preprocessing.get("status") == "unpacked":
        lines[-2:-2] = ["## UPX unpacking", "", f"Analyzed the unpacked PE using UPX {preprocessing.get('tool_version', 'unknown')}. Original upload preserved.",
                       f"Analyzed SHA-256: `{preprocessing['analyzed_sha256']}`",
                       f"Size: {preprocessing['original_size']} → {preprocessing['analyzed_size']} bytes", ""]
    lines.extend(f"- {w}" for w in analysis.get("warnings", []))
    if not analysis.get("warnings"):
        lines.append("No analysis warnings recorded.")
    lines += ["", "## Functions", "", "| Address | Name | Size |", "| --- | --- | --- |"]
    lines.extend(f"| `{f['address']}` | {f['name'].replace('|', '/')} | {f['size']} |" for f in analysis.get("functions", []))
    lines += ["", "## Imports", ""]
    lines.extend(f"- {i.get('library', '')}: `{i['name']}`" for i in analysis.get("imports", []))
    lines += ["", "## Reviewed annotations", ""]
    lines.extend(f"- {a['status']}: {a['kind']} at `{a['address']}`: {a['old_value']!r} → {a['value']!r}" for a in store.list_annotations(sample_id))
    from .agent import list_sample_runs
    runs = list_sample_runs(sample_id)
    lines += ["", "## Investigations", ""]
    for run in runs:
        if run.get("status") in {"complete", "partial"}:
            lines += [f"### {run['question']}", "", f"Provider: {run['provider']} / {run['model']}", f"Status: {run['status']}",
                      f"Analysis revision: {run.get('analysis_revision', 'unavailable')}", f"Limit notice: {run.get('limit_reason') or 'None'}",
                      "", run.get("answer") or "", "", "Evidence:", ""]
            for evidence in run.get("evidence", []):
                lines.append(f"- [{evidence['id']}] {evidence.get('tool', '')} at `{evidence.get('address') or 'program'}`; analysis revision {evidence.get('revision', run.get('analysis_revision', 'unavailable'))}: {evidence.get('summary', '')}")
            lines.append("")
    return Response("\n".join(lines) + "\n", media_type="text/markdown; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="ghidrama-{sample_id[:8]}.md"'})


from .agent import router as agent_router
from .pseudocode import router as pseudocode_router
from .workflow import router as workflow_router
app.include_router(agent_router)
app.include_router(pseudocode_router)
app.include_router(workflow_router)

frontend = Path(os.getenv("GHIDRAMA_FRONTEND_DIR", str(Path(__file__).resolve().parents[2] / "frontend/dist"))).resolve()
if (frontend / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=frontend / "assets"), name="assets")


@app.get("/{path:path}", include_in_schema=False)
def frontend_app(path: str):
    if path.startswith("api/"):
        raise HTTPException(404, "API endpoint not found.")
    candidate = (frontend / path).resolve()
    if candidate.is_relative_to(frontend) and candidate.is_file():
        return FileResponse(candidate)
    if (frontend / "index.html").is_file():
        return FileResponse(frontend / "index.html")
    return JSONResponse({"service": "Ghidrama", "message": "The API is running. Build the frontend or start its development server.", "docs": "/docs"})
