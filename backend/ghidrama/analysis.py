"""Bounded Ghidra subprocess execution and durable analysis job management."""
from __future__ import annotations

import asyncio
import contextlib
import fcntl
import json
import os
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

from .config import settings
from .store import Store, normalize_address


def inspect_pe(path: Path) -> dict:
    import pefile

    try:
        pe = pefile.PE(str(path), fast_load=True)
        try:
            architecture = {0x14C: "x86", 0x8664: "x86_64"}.get(pe.FILE_HEADER.Machine)
            if not architecture:
                raise ValueError("This release supports native Windows x86 and x64 PE files.")
            if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 14 and pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress:
                raise ValueError("Managed .NET executables need a managed-code analyzer and are not supported in this release.")
            if not pe.sections or len(pe.sections) > 96:
                raise ValueError("The PE section table is missing or exceeds the supported limit.")
            size = path.stat().st_size
            for section in pe.sections:
                if section.SizeOfRawData and section.PointerToRawData + section.SizeOfRawData > size:
                    raise ValueError("The executable contains a section outside the uploaded file.")
            return {"architecture": architecture, "image_base": hex(pe.OPTIONAL_HEADER.ImageBase), "entry_point": hex(pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint)}
        finally:
            pe.close()
    except pefile.PEFormatError as error:
        raise ValueError("The upload is not a valid Windows PE executable.") from error


def worker_environment(sample_dir: Path) -> dict[str, str]:
    private_home = sample_dir / "worker-home"
    private_home.mkdir(exist_ok=True, mode=0o700)
    env = {
        "HOME": str(private_home), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "PATH": os.defpath, "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
        "PYTHONUNBUFFERED": "1", "GHIDRAMA_DATA_DIR": str(settings.data_dir),
        "PYTHON_DOTENV_DISABLED": "1", "GHIDRAMA_PARENT_PID": str(os.getpid()),
        "JAVA_TOOL_OPTIONS": f"-Xmx{settings.worker_memory_mb}m -XX:ActiveProcessorCount=2 -Djava.awt.headless=true",
    }
    if settings.ghidra_install_dir:
        env["GHIDRA_INSTALL_DIR"] = str(settings.ghidra_install_dir)
    if settings.java_home:
        env["JAVA_HOME"] = str(settings.java_home)
        env["PATH"] = str(settings.java_home / "bin") + os.pathsep + os.defpath
    return env


def _kill(process: subprocess.Popen):
    if process.poll() is None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()


@contextlib.contextmanager
def project_lock(store: Store, sample_id: str, timeout: float = 130, cancel_check=None):
    path = store.sample_dir(sample_id) / "project.lock"
    with path.open("a") as lock:
        deadline = time.monotonic() + timeout
        while True:
            if cancel_check and cancel_check():
                raise InterruptedError("Operation was cancelled while waiting for the project.")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise ValueError("This project is busy. Please retry after its current operation finishes.")
                time.sleep(0.1)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


@contextlib.contextmanager
def worker_slot(store: Store, timeout: float = 120, cancel_check=None):
    """Share the JVM concurrency budget across API and MCP processes.

    Advisory locks disappear automatically if an owning process dies. Every
    launcher uses the same data directory and configured number of slots.
    """
    folder = store.data_dir / "worker-slots"
    folder.mkdir(exist_ok=True, mode=0o700)
    with contextlib.ExitStack() as stack:
        slots = [stack.enter_context((folder / f"slot-{index}.lock").open("a")) for index in range(max(1, settings.max_workers))]
        deadline = time.monotonic() + timeout
        while True:
            if cancel_check and cancel_check():
                raise InterruptedError("Operation was cancelled while waiting for an analysis worker.")
            for slot in slots:
                try:
                    fcntl.flock(slot, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    continue
                try:
                    yield
                finally:
                    fcntl.flock(slot, fcntl.LOCK_UN)
                return
            if time.monotonic() >= deadline:
                raise ValueError("All Ghidra workers are busy. Retry after the current analysis or decompilation finishes.")
            time.sleep(0.1)


def run_worker(store: Store, sample_id: str, action: str, *, address: str | None = None, addresses: list[str] | None = None, annotation: dict | None = None, preprocessing: dict | None = None, on_process=None, cancel_check=None) -> dict:
    with worker_slot(store, cancel_check=cancel_check):
        if cancel_check and cancel_check():
            raise InterruptedError("Operation was cancelled.")
        return _run_worker_process(store, sample_id, action, address=address, addresses=addresses, annotation=annotation, preprocessing=preprocessing, on_process=on_process, cancel_check=cancel_check)


def _run_worker_process(store: Store, sample_id: str, action: str, *, address: str | None = None, addresses: list[str] | None = None, annotation: dict | None = None, preprocessing: dict | None = None, on_process=None, cancel_check=None) -> dict:
    if not settings.ghidra_available:
        raise ValueError("Ghidra is not configured. Set GHIDRA_INSTALL_DIR and JAVA_HOME, then restart the server.")
    folder = store.sample_dir(sample_id)
    if any(part.startswith(".") for part in folder.parts):
        raise ValueError("Ghidra project paths cannot contain hidden folders. Set GHIDRAMA_DATA_DIR to an absolute path without dot-prefixed directory names, then restart.")
    from .unpacking import input_path
    if preprocessing is None:
        preprocessing = (store.get_analysis(sample_id) or {}).get("preprocessing")
    source = input_path(folder, preprocessing)
    output = folder / f"result-{uuid.uuid4().hex}.json"
    args = [sys.executable, "-m", "ghidrama.ghidra_worker", "--sample-dir", str(folder), "--input-name", source.name, "--action", action, "--output", str(output), "--timeout", str(settings.analysis_timeout)]
    if address:
        args += ["--address", normalize_address(address)]
    if addresses:
        if len(addresses) > 4:
            raise ValueError("A decompilation batch may contain at most four functions.")
        args += ["--addresses", *[normalize_address(item) for item in addresses]]
    proposal = None
    if annotation:
        proposal = folder / f"proposal-{uuid.uuid4().hex}.json"
        proposal.write_text(json.dumps(annotation))
        args += ["--proposal", str(proposal)]
    timeout = settings.analysis_timeout + 60 if action == "analyze" else 180 if action == "functions" else 120
    log_path = folder / "worker.log"
    try:
        with log_path.open("wb") as log:
            process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, env=worker_environment(folder), cwd=folder, start_new_session=True)
            if on_process:
                on_process(process)
            try:
                deadline = time.monotonic() + timeout
                while process.poll() is None:
                    if cancel_check and cancel_check():
                        raise InterruptedError("Analysis was cancelled.")
                    if time.monotonic() > deadline:
                        raise TimeoutError(f"Ghidra exceeded the {timeout}-second operation limit.")
                    time.sleep(0.1)
            finally:
                _kill(process)
        if process.returncode != 0 or not output.is_file():
            tail = log_path.read_text(errors="replace")[-1800:]
            raise ValueError("Ghidra could not complete the operation. " + tail)
        result = json.loads(output.read_text())
        if result.get("error"):
            raise ValueError(result["error"])
        if action in {"analyze", "annotate"} and preprocessing:
            result["preprocessing"] = preprocessing
        return result
    finally:
        output.unlink(missing_ok=True)
        if proposal:
            proposal.unlink(missing_ok=True)


def get_function_detail(sample_id: str, address: str, cancel_check=None) -> dict:
    store = Store()
    sample = store.get_sample(sample_id)
    if not sample or sample["status"] not in {"ready", "partial"}:
        raise ValueError("Wait for analysis to complete before opening a function.")
    function = store.get_function(sample_id, address)
    if not function:
        raise ValueError("Function not found.")
    if function.get("detail_loaded"):
        return function
    with project_lock(store, sample_id, cancel_check=cancel_check):
        sample = store.get_sample(sample_id)
        if sample["status"] not in {"ready", "partial"}:
            raise ValueError("The project is being analyzed. Retry when it finishes.")
        function = store.get_function(sample_id, address)
        if function.get("detail_loaded"):
            return function
        function = run_worker(store, sample_id, "function", address=address, cancel_check=cancel_check)
        function["analysis_revision"] = sample["analysis_revision"]
        store.save_function(sample_id, sample["analysis_revision"], function)
        return function


def get_function_batch(sample_id: str, addresses: list[str], revision: int, cancel_check=None) -> list[dict]:
    """Reuse revision caches and one JVM for up to four missing functions."""
    if not 1 <= len(addresses) <= 4:
        raise ValueError("A decompilation batch must contain one to four functions.")
    store = Store()
    with project_lock(store, sample_id, timeout=200, cancel_check=cancel_check):
        sample = store.get_sample(sample_id)
        if not sample or sample["status"] not in {"ready", "partial"} or sample["analysis_revision"] != revision:
            raise ValueError("Analysis changed during pseudocode extraction. Generate again against the current analysis.")
        functions = [store.get_function(sample_id, address) for address in addresses]
        if any(function is None for function in functions):
            raise ValueError("A requested function is no longer in the analysis.")
        missing = [function["address"] for function in functions if not function.get("detail_loaded")]
        if missing:
            result = run_worker(store, sample_id, "functions", addresses=missing, cancel_check=cancel_check)
            for function in result["functions"]:
                function["analysis_revision"] = revision
                store.save_function(sample_id, revision, function)
            functions = [store.get_function(sample_id, address) for address in addresses]
        for function in functions:
            # Index artifacts may themselves contain details (for example, older
            # imports). The exporter always reads a separate revision cache.
            store.save_function(sample_id, revision, function)
        return functions


def apply_annotation(sample_id: str, annotation_id: str) -> dict:
    store = Store()
    with project_lock(store, sample_id):
        sample = store.get_sample(sample_id)
        annotation = store.get_annotation(sample_id, annotation_id)
        if not sample or not annotation:
            raise ValueError("Annotation not found.")
        if annotation["status"] == "applied":
            return annotation
        if sample["status"] not in {"ready", "partial"}:
            raise ValueError("Wait for analysis to finish before applying changes.")
        if sample["analysis_revision"] != annotation["expected_revision"]:
            raise ValueError("Analysis revision changed. Create a new proposal against the current revision.")
        analysis = run_worker(store, sample_id, "annotate", annotation=annotation)
        analysis.update(sample_id=sample_id, revision=sample["analysis_revision"] + 1)
        store.save_analysis(sample_id, analysis)
        store.mark_annotation_applied(annotation_id, analysis["revision"])
        return store.get_annotation(sample_id, annotation_id)


class AnalysisManager:
    def __init__(self):
        self.tasks: dict[str, asyncio.Task] = {}
        self.cancelled: set[str] = set()
        self.processes: dict[str, subprocess.Popen] = {}
        self.semaphore = asyncio.Semaphore(max(1, settings.max_workers))

    def submit(self, sample_id: str):
        if sample_id in self.tasks and not self.tasks[sample_id].done():
            raise ValueError("This sample already has an active analysis job.")
        self.cancelled.discard(sample_id)
        Store().update_sample(sample_id, status="queued", error=None)
        self.tasks[sample_id] = asyncio.create_task(self._run(sample_id))

    def _analyze(self, sample_id: str):
        store = Store()
        with project_lock(store, sample_id, timeout=settings.analysis_timeout + 120, cancel_check=lambda: sample_id in self.cancelled):
            if sample_id in self.cancelled:
                return
            store.update_sample(sample_id, status="analyzing", error=None)
            sample = store.get_sample(sample_id)
            from .unpacking import prepare_input
            preprocessing = prepare_input(store.sample_dir(sample_id), sample["sha256"],
                                          on_process=lambda p: self.processes.__setitem__(sample_id, p),
                                          cancel_check=lambda: sample_id in self.cancelled)
            analysis = run_worker(store, sample_id, "analyze", preprocessing=preprocessing, on_process=lambda p: self.processes.__setitem__(sample_id, p), cancel_check=lambda: sample_id in self.cancelled)
            if sample_id in self.cancelled:
                return
            analysis.update(sample_id=sample_id, revision=sample["analysis_revision"] + 1)
            store.save_analysis(sample_id, analysis)
            store.update_sample(sample_id, status="partial" if analysis.get("partial") else "ready", error=None)

    async def _run(self, sample_id: str):
        try:
            async with self.semaphore:
                await asyncio.to_thread(self._analyze, sample_id)
        except InterruptedError:
            Store().update_sample(sample_id, status="cancelled", error=None)
        except Exception as error:
            if sample_id not in self.cancelled:
                Store().update_sample(sample_id, status="failed", error=str(error)[-3000:])
        finally:
            self.processes.pop(sample_id, None)
            if sample_id in self.cancelled:
                Store().update_sample(sample_id, status="cancelled", error=None)

    async def cancel(self, sample_id: str):
        task = self.tasks.get(sample_id)
        if not task or task.done():
            return Store().get_sample(sample_id)
        self.cancelled.add(sample_id)
        process = self.processes.get(sample_id)
        if process:
            await asyncio.to_thread(_kill, process)
        Store().update_sample(sample_id, status="cancelled", error=None)
        return Store().get_sample(sample_id)

    async def shutdown(self):
        for sample_id, task in self.tasks.items():
            if not task.done():
                await self.cancel(sample_id)
        if self.tasks:
            await asyncio.gather(*self.tasks.values(), return_exceptions=True)

    @property
    def active_jobs(self) -> int:
        return sum(not task.done() for task in self.tasks.values())
