"""Durable metadata and immutable-revision analysis artifacts."""
from __future__ import annotations

import json
import os
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import settings


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_address(value: str) -> str:
    if not re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]{1,16}", value):
        raise ValueError("Address must be a hexadecimal address of at most 64 bits.")
    return hex(int(value, 16))


class Store:
    def __init__(self, data_dir: Path | str | None = None):
        self.data_dir = Path(data_dir or settings.data_dir).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db_path = self.data_dir / "state.db"
        with self.connection() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS samples (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, sha256 TEXT NOT NULL,
                size INTEGER NOT NULL, architecture TEXT NOT NULL, status TEXT NOT NULL,
                created_at TEXT NOT NULL, error TEXT, function_count INTEGER NOT NULL DEFAULT 0,
                analysis_revision INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS annotations (
                id TEXT PRIMARY KEY, sample_id TEXT NOT NULL REFERENCES samples(id),
                address TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL,
                old_value TEXT, status TEXT NOT NULL, created_at TEXT NOT NULL,
                expected_revision INTEGER NOT NULL, applied_revision INTEGER
            );
            """)
        os.chmod(self.db_path, 0o600)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.db_path, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def sample_dir(self, sample_id: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{32}", sample_id):
            raise ValueError("Invalid sample identifier.")
        return self.data_dir / "samples" / sample_id

    def create_sample(self, name: str, sha256: str, size: int, architecture: str, sample_id: str | None = None) -> dict:
        sample_id = sample_id or uuid.uuid4().hex
        self.sample_dir(sample_id).mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.connection() as db:
            db.execute("INSERT INTO samples(id,name,sha256,size,architecture,status,created_at) VALUES (?,?,?,?,?,'queued',?)", (sample_id, name, sha256, size, architecture, utcnow()))
        return self.get_sample(sample_id)

    def get_sample(self, sample_id: str) -> dict | None:
        with self.connection() as db:
            row = db.execute("SELECT * FROM samples WHERE id=?", (sample_id,)).fetchone()
        return dict(row) if row else None

    def list_samples(self) -> list[dict]:
        with self.connection() as db:
            return [dict(r) for r in db.execute("SELECT * FROM samples ORDER BY created_at DESC")]

    def update_sample(self, sample_id: str, **changes: Any) -> dict:
        allowed = {"status", "error", "function_count", "analysis_revision", "architecture"}
        if not changes or set(changes) - allowed:
            raise ValueError("Unsupported sample update.")
        with self.connection() as db:
            db.execute(f"UPDATE samples SET {','.join(key + '=?' for key in changes)} WHERE id=?", (*changes.values(), sample_id))
        return self.get_sample(sample_id)

    def recover_jobs(self) -> None:
        with self.connection() as db:
            db.execute("UPDATE samples SET status='failed', error='Analysis was interrupted by a server restart. Retry analysis to continue.' WHERE status IN ('queued','analyzing')")

    def get_analysis(self, sample_id: str) -> dict | None:
        sample = self.get_sample(sample_id)
        if not sample or not sample["analysis_revision"]:
            return None
        path = self.sample_dir(sample_id) / "artifacts" / f"analysis-{sample['analysis_revision']}.json"
        if not path.is_file():
            return None
        return json.loads(path.read_text())

    def save_analysis(self, sample_id: str, analysis: dict) -> None:
        folder = self.sample_dir(sample_id) / "artifacts"
        folder.mkdir(exist_ok=True)
        revision = int(analysis["revision"])
        destination = folder / f"analysis-{revision}.json"
        temporary = destination.with_suffix(f".{uuid.uuid4().hex}.tmp")
        temporary.write_text(json.dumps(analysis, ensure_ascii=False))
        os.chmod(temporary, 0o600)
        temporary.replace(destination)
        self.update_sample(sample_id, analysis_revision=revision, function_count=len(analysis.get("functions", [])))

    def list_functions(self, sample_id: str, query: str = "") -> list[dict]:
        analysis = self.get_analysis(sample_id)
        if not analysis:
            return []
        query = query.casefold()
        return [{k: f.get(k) for k in ("address", "name", "size", "signature", "comment")} for f in analysis.get("functions", []) if query in f.get("name", "").casefold() or query in f["address"].casefold()]

    def get_function(self, sample_id: str, address: str) -> dict | None:
        address = normalize_address(address)
        analysis = self.get_analysis(sample_id)
        if not analysis:
            return None
        cache = self.sample_dir(sample_id) / "artifacts" / f"function-{analysis['revision']}-{address[2:]}.json"
        if cache.is_file():
            return json.loads(cache.read_text())
        return next((dict(f) for f in analysis.get("functions", []) if normalize_address(f["address"]) == address), None)

    def save_function(self, sample_id: str, revision: int, function: dict) -> None:
        address = normalize_address(function["address"])
        path = self.sample_dir(sample_id) / "artifacts" / f"function-{revision}-{address[2:]}.json"
        temporary = path.with_suffix(f".{uuid.uuid4().hex}.tmp")
        temporary.write_text(json.dumps(function, ensure_ascii=False))
        temporary.replace(path)

    def list_annotations(self, sample_id: str) -> list[dict]:
        with self.connection() as db:
            return [dict(r) for r in db.execute("SELECT * FROM annotations WHERE sample_id=? ORDER BY created_at DESC", (sample_id,))]

    def get_annotation(self, sample_id: str, annotation_id: str) -> dict | None:
        with self.connection() as db:
            row = db.execute("SELECT * FROM annotations WHERE id=? AND sample_id=?", (annotation_id, sample_id)).fetchone()
        return dict(row) if row else None

    def create_annotation(self, sample_id: str, address: str, kind: str, value: str, expected_revision: int) -> dict:
        sample = self.get_sample(sample_id)
        if not sample or sample["analysis_revision"] != expected_revision:
            raise ValueError("Analysis revision changed. Refresh before proposing a change.")
        function = self.get_function(sample_id, address)
        if not function:
            raise ValueError("Function does not exist at that address.")
        if kind not in {"rename", "comment"}:
            raise ValueError("Unsupported annotation kind.")
        if kind == "rename" and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", value):
            raise ValueError("Use a valid function name (letters, digits and underscores; maximum 128 characters).")
        if len(value) > 8000:
            raise ValueError("Comment must be at most 8,000 characters.")
        annotation_id = uuid.uuid4().hex
        with self.connection() as db:
            db.execute("INSERT INTO annotations(id,sample_id,address,kind,value,old_value,status,created_at,expected_revision) VALUES (?,?,?,?,?,?,'proposed',?,?)", (annotation_id, sample_id, normalize_address(address), kind, value, function.get("name" if kind == "rename" else "comment"), utcnow(), expected_revision))
        return self.get_annotation(sample_id, annotation_id)

    def mark_annotation_applied(self, annotation_id: str, revision: int):
        with self.connection() as db:
            db.execute("UPDATE annotations SET status='applied', applied_revision=? WHERE id=?", (revision, annotation_id))
