"""Static UPX preprocessing with immutable, revision-scoped input provenance."""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

from .config import settings


def sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def upx_indicators(path: Path) -> list[str]:
    """Recognize ordinary UPX PEs; this is a hint, decompression validates it."""
    import pefile

    with pefile.PE(str(path), fast_load=True) as pe:
        names = [section.Name.rstrip(b"\0").decode("ascii", errors="replace") for section in pe.sections]
        indicators = [f"section {name}" for name in names if name in {"UPX0", "UPX1", "UPX2"}]
        # The UPX pack header is normally in the PE headers. Also catches renamed sections.
        with path.open("rb") as source:
            if b"UPX!" in source.read(min(pe.OPTIONAL_HEADER.SizeOfHeaders, 65536)):
                indicators.append("UPX pack header")
    return indicators


def input_path(folder: Path, preprocessing: dict | None) -> Path:
    if preprocessing and preprocessing.get("status") == "unpacked":
        digest = preprocessing.get("analyzed_sha256", "")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("The unpacked analysis input has an invalid digest.")
        path = folder / f"unpacked-{digest}.bin"
        if not path.is_file():
            raise ValueError("The unpacked analysis input is missing. Retry analysis to recover it.")
        return path
    return folder / "original.bin"


def project_directory(folder: Path, source: Path) -> Path:
    # Keep pre-UPX projects and annotations intact. Never import unpacked bytes
    # into a project which already contains the packed loader.
    return folder / ("project" if source.name == "original.bin" else f"project-{source.stem}")


def prepare_input(folder: Path, expected_sha256: str, *, on_process=None, cancel_check=None) -> dict:
    from .analysis import _kill, inspect_pe

    original = folder / "original.bin"
    if cancel_check and cancel_check():
        raise InterruptedError("Unpacking was cancelled.")
    original_hash = sha256(original)
    if original_hash != expected_sha256:
        raise ValueError("The original upload no longer matches its recorded SHA-256.")
    metadata = inspect_pe(original)
    indicators = upx_indicators(original)
    provenance = {"status": "not_detected", "original_sha256": original_hash,
                  "original_size": original.stat().st_size, "analyzed_sha256": original_hash,
                  "analyzed_size": original.stat().st_size, "indicators": indicators}
    if not indicators:
        return provenance
    executable = settings.upx_executable
    if executable is None:
        raise ValueError("UPX packing detected, but UPX is unavailable. Install UPX, set GHIDRAMA_UPX_PATH, restart the server, then retry analysis. The original upload is preserved.")
    limit = max(1, settings.max_unpacked_mb) * 1024 * 1024
    timeout = max(1, settings.unpack_timeout)
    output = folder / f"unpacking-{uuid.uuid4().hex}.bin"
    log_path = folder / "upx.log"
    args = [sys.executable, "-m", "ghidrama.upx_worker", "--upx", str(executable),
            "--input", str(original), "--output", str(output), "--max-bytes", str(limit), "--timeout", str(timeout)]
    env = {"PATH": os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
           "PYTHONPATH": str(Path(__file__).resolve().parents[1]), "PYTHON_DOTENV_DISABLED": "1",
           "GHIDRAMA_PARENT_PID": str(os.getpid())}
    try:
        with log_path.open("wb") as log:
            log_path.chmod(0o600)
            process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, cwd=folder,
                                       env=env, start_new_session=True)
            try:
                if on_process:
                    on_process(process)
                deadline = time.monotonic() + timeout
                while process.poll() is None:
                    if cancel_check and cancel_check():
                        raise InterruptedError("Unpacking was cancelled.")
                    if time.monotonic() >= deadline:
                        raise ValueError(f"UPX unpacking exceeded {timeout} seconds. The original upload is preserved.")
                    if log_path.stat().st_size > 128 * 1024:
                        raise ValueError("UPX produced excessive diagnostic output. The original upload is preserved.")
                    time.sleep(0.05)
            finally:
                _kill(process)
        if cancel_check and cancel_check():
            raise InterruptedError("Unpacking was cancelled.")
        with log_path.open("rb") as log:
            log.seek(max(0, log_path.stat().st_size - 4096))
            diagnostic = log.read(4096).decode("utf-8", errors="replace")
        if process.returncode != 0 or not output.is_file():
            detail = " ".join(diagnostic.split())[-1200:]
            raise ValueError(f"UPX could not unpack this file (output limit {settings.max_unpacked_mb} MB). Modified or corrupt UPX files may need manual unpacking. Original preserved. {detail}")
        if not 0 < output.stat().st_size <= limit:
            raise ValueError(f"UPX output exceeds the {settings.max_unpacked_mb} MB limit or is empty. Original preserved.")
        try:
            unpacked = inspect_pe(output)
        except ValueError as error:
            raise ValueError(f"UPX produced invalid output: {error} Original upload preserved.") from error
        if unpacked["architecture"] != metadata["architecture"]:
            raise ValueError("UPX output architecture does not match the upload. Original preserved.")
        digest = sha256(output)
        if digest == original_hash:
            raise ValueError("UPX did not change the packed input. Original preserved.")
        destination = folder / f"unpacked-{digest}.bin"
        if destination.exists():
            if sha256(destination) != digest:
                raise ValueError("A saved unpacked file no longer matches its SHA-256.")
        else:
            output.chmod(0o400)
            output.replace(destination)
        version = re.search(r"\bUPX\s+(\d[\w.+-]*)", diagnostic)
        provenance.update(status="unpacked", tool="UPX", tool_version=version.group(1) if version else "unknown",
                          analyzed_sha256=digest, analyzed_size=destination.stat().st_size)
        return provenance
    finally:
        output.unlink(missing_ok=True)
