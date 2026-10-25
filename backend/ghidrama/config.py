"""Configuration shared by the API and isolated analysis processes."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _optional_path(name: str) -> Path | None:
    value = os.environ.get(name)
    return Path(value).expanduser().resolve() if value else None


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.getenv("GHIDRAMA_DATA_DIR", "./data")).expanduser().resolve())
    ghidra_install_dir: Path | None = field(default_factory=lambda: _optional_path("GHIDRA_INSTALL_DIR"))
    java_home: Path | None = field(default_factory=lambda: _optional_path("JAVA_HOME"))
    max_upload_mb: int = field(default_factory=lambda: int(os.getenv("GHIDRAMA_MAX_UPLOAD_MB", "100")))
    analysis_timeout: int = field(default_factory=lambda: int(os.getenv("GHIDRAMA_ANALYSIS_TIMEOUT", "600")))
    worker_memory_mb: int = field(default_factory=lambda: int(os.getenv("GHIDRAMA_WORKER_MEMORY_MB", "2048")))
    max_workers: int = field(default_factory=lambda: int(os.getenv("GHIDRAMA_MAX_WORKERS", "2")))
    allowed_hosts: list[str] = field(default_factory=lambda: os.getenv("GHIDRAMA_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1],testserver").split(","))

    @property
    def ghidra_available(self) -> bool:
        return bool(self.ghidra_install_dir and (self.ghidra_install_dir / "Ghidra/application.properties").is_file())

    @property
    def ghidra_version(self) -> str | None:
        if not self.ghidra_available:
            return None
        for line in (self.ghidra_install_dir / "Ghidra/application.properties").read_text().splitlines():
            if line.startswith("application.version="):
                return line.partition("=")[2]
        return None


settings = Settings()
