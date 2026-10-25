#!/usr/bin/env python3
"""Check a local Ghidrama installation without calling a model provider."""
from pathlib import Path
import importlib.metadata
import os
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except ImportError:
    pass

failures = []
for package in ["ghidrama", "pyghidra", "mcp", "langgraph", "fastapi"]:
    try:
        print(f"{package}: {importlib.metadata.version(package)}")
    except importlib.metadata.PackageNotFoundError:
        failures.append(f"{package} is not installed in this Python environment")
install = Path(os.environ.get("GHIDRA_INSTALL_DIR", "/nonexistent"))
props = install / "Ghidra" / "application.properties"
if props.is_file():
    for line in props.read_text().splitlines():
        if line.startswith(("application.version=", "application.java.min=")):
            print(f"Ghidra {line}")
else:
    failures.append("GHIDRA_INSTALL_DIR must point to an extracted Ghidra release")
java = Path(os.environ.get("JAVA_HOME", "/nonexistent")) / "bin" / "java"
if java.is_file():
    version = subprocess.run([str(java), "-version"], capture_output=True, text=True)
    print(version.stderr.splitlines()[0] if version.stderr else version.stdout.strip())
    if version.returncode:
        failures.append("Java did not start")
else:
    failures.append("JAVA_HOME must point to JDK 21 or a release-compatible JDK")
if not (ROOT / "frontend" / "dist" / "index.html").is_file():
    failures.append("Frontend is not built; run pnpm build in frontend")
for failure in failures:
    print(f"NEEDS ATTENTION: {failure}")
if not failures:
    print("Local prerequisites are ready. No cloud credentials were read or sent.")
sys.exit(bool(failures))
