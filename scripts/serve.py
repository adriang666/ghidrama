#!/usr/bin/env python3
"""Start the local workbench with environment settings loaded before imports."""
from pathlib import Path
import os

from dotenv import load_dotenv
import uvicorn

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")
os.chdir(ROOT)
port = int(os.getenv("GHIDRAMA_PORT", "8000"))
if not 1 <= port <= 65535:
    raise SystemExit("GHIDRAMA_PORT must be between 1 and 65535")

if __name__ == "__main__":
    uvicorn.run("ghidrama.main:app", host="127.0.0.1", port=port)
