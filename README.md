# Ghidrama

A local reverse engineering workbench for native Windows executables, powered by Ghidra, with a web interface and an MCP-driven LLM analyst. Use an Ollama Cloud API key or an OpenRouter API key. No OpenAI subscription or API key is required.

This release is for a single analyst on a trusted local machine. It performs **static analysis**: uploaded executables are never launched. The interface displays real Ghidra results; it does not substitute generated demonstrations when analysis or a model provider is unavailable.

## What is implemented

- Native x86/x64 PE EXE/DLL upload, format validation, SHA-256 identity, persistent analysis jobs, cancellation, and failure recovery.
- Real Ghidra projects through PyGhidra in separate worker processes. Per-project file locks serialize access across the API and MCP processes.
- Functions, lazy decompilation, instructions, strings, imports, exports, sections, and direct caller/callee relationships.
- A React workbench with function search, code navigation, a call graph, investigation history, evidence links, and Markdown report download.
- Direct Ollama Cloud and OpenRouter integration, model discovery, connection testing, encrypted saved credentials, and provider-independent tool calls.
- A LangGraph investigation workflow using the official MCP client to call a real sample-scoped MCP stdio server. Tool schemas, argument validation, bounded output, run limits, and cancellation are enforced by application code.
- Reviewed function renames and comments, applied to the actual Ghidra project, with an audit record and revision checks.

The local release uses SQLite and filesystem artifacts, and a bounded local process queue. PostgreSQL, Redis/Celery, shared-user identity, external MCP access, Windows debugging, managed .NET decompilation, PDB upload workflows, advanced type editing, and automated unpacking are future extensions. Containers improve packaging; they do not turn this release into a hostile multi-tenant malware service.

## Prerequisites

- Linux, or Windows with WSL2. macOS is not validated.
- Python 3.11 or 3.12 with venv support (3.12 is validated).
- Node.js 22+ and pnpm (lockfile created with pnpm 11.25.0).
- Extracted **Ghidra 12.1.3** and **JDK 21**. PyGhidra 3.1.0 is pinned to that tested combination. Other Ghidra releases may require different Java/PyGhidra versions.
- A provider key and a model supporting tool calls, only if you want LLM investigations. Ordinary analysis works without cloud access.

Start with about 8 GB of available memory for two modest analysis jobs, and adjust the worker count/memory for larger binaries. Cloud inference does not require a local GPU.

## Local setup

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip install --no-deps -e .
cp .env.example .env
```

Edit `.env` to point `GHIDRA_INSTALL_DIR` at the extracted Ghidra directory and `JAVA_HOME` at JDK 21. Use an absolute path for `GHIDRAMA_DATA_DIR` if you may start the server from different directories. Do not put provider keys in this file: enter them in the web interface.

```bash
cd frontend
corepack enable
pnpm install --frozen-lockfile
pnpm build
cd ..
.venv/bin/python scripts/doctor.py
./scripts/start.sh
```

Open **http://127.0.0.1:8000**. The backend serves the built interface from the same origin. Keep one API process: do not run multiple Uvicorn workers against this local queue.

If your OS Python lacks venv support, install its `python3-venv` package or use a complete Python distribution. This workspace may already contain an installed `.venv` and a built `frontend/dist`; in that case, run `./scripts/start.sh` directly.

For UI development, start the backend as above, then run `pnpm dev` inside `frontend`. Vite listens on loopback and proxies `/api` to port 8000.

## Use the workbench

1. Upload an EXE or DLL. Its analysis status changes from queued to analyzing and then ready, partial, or failed. A partial result is explicitly labelled.
2. Select a function to retrieve its decompilation and references. Large functions can take longer on the first request; later requests use the revision-specific cache.
3. Open provider settings. Choose Ollama Cloud or OpenRouter, enter the API key, select a tool-capable model, and save. The key is not returned by any read endpoint or saved in browser storage. The Ollama connection test sends a very short model request, which may consume account usage.
4. Ask a question, optionally scoped to the selected function. Starting an investigation sends your question and selected analysis evidence to the chosen cloud provider. Original binary files are not uploaded to the provider.
5. Follow evidence markers to inspect the supporting Ghidra data. A citation proves where evidence came from; it is not a guarantee that the model interpreted it correctly.
6. Propose a name or comment, review it, and apply. Changes require the expected analysis revision and update the underlying Ghidra project. To undo, propose the old value recorded in the audit history.

Ollama Cloud currently does not provide enforced structured outputs. Ghidrama validates arguments and tool results itself. OpenRouter requests require support for requested parameters and ask for providers with data collection disabled. Routing controls do not make cloud processing local. Use only specimens whose content you are permitted to send to the selected service.

## Configuration

| Variable | Meaning |
| --- | --- |
| `GHIDRA_INSTALL_DIR` | Extracted Ghidra release directory |
| `JAVA_HOME` | Compatible JDK directory |
| `GHIDRAMA_DATA_DIR` | Persistent database, binaries, project files, artifacts and credential encryption key |
| `GHIDRAMA_FRONTEND_DIR` | Optional override for the built frontend directory |
| `GHIDRAMA_MAX_UPLOAD_MB` | Maximum executable size; example configuration uses 50 MB |
| `GHIDRAMA_ANALYSIS_TIMEOUT` | Worker timeout in seconds; default 600 |
| `GHIDRAMA_WORKER_MEMORY_MB` | Java heap budget per analysis worker; default 2048 |
| `GHIDRAMA_MAX_WORKERS` | Concurrent analysis jobs; default 2 |
| `GHIDRAMA_PORT` | Local launcher port; default 8000 |

The loopback host restrictions and same-origin checks are intentional. There is no user login in this local release. Do not expose it to a LAN or the Internet, or place it behind a public reverse proxy. A shared deployment needs authentication, project-level authorization, separate worker hosts, and OS-enforced isolation before exposure.

## Docker / WSL2 packaging

Docker and Compose are optional. Set the host `GHIDRA_INSTALL_DIR` in `.env`, then:

```bash
docker compose up --build
```

The image includes Java and builds the interface. Your existing Ghidra release is mounted read-only. Persistent data lives in the `ghidrama-data` volume; the port is published only on `127.0.0.1`. Docker packaging must be validated on the deployment machine; the development host may not have Docker installed.

## Verify

```bash
.venv/bin/python -m pytest -q
cd frontend && pnpm build
```

Provider tests use explicit mocked HTTP responses; they do not consume paid inference or prove a particular cloud model's quality. MCP integration tests start the real stdio server. The live Ghidra smoke test is separate from the fast test suite.

Generate a known small native Windows executable for manual validation:

```bash
.venv/bin/python scripts/make_fixture.py
```

With the server running, exercise upload, real analysis, decompilation, reviewed changes and report download automatically:

```bash
.venv/bin/python scripts/smoke.py
```

This creates a clearly named verification sample and does not call a model provider. Generate the 32-bit variant with `scripts/make_fixture.py .runtime/ghidrama-x86-fixture.exe --arch x86`.

Upload `.runtime/ghidrama-fixture.exe`. Expected facts: AMD64, image base `0x140000000`, entry point `0x140001000`, helper function at `0x140001040`, and `KERNEL32.dll` imports `OutputDebugStringA` and `ExitProcess`. The helper computes `argument * 3 + 17`. The script emits deterministic machine code and PE headers, never downloads or runs an executable.

## Data and operations

All local state lives under `GHIDRAMA_DATA_DIR`. Stop the server before copying this directory for a consistent backup. Preserve its `.provider-key` together with the database if saved provider keys must remain decryptable; keep the backup private. The encryption key is separate from the database, with restrictive filesystem permissions. This protects a database-only disclosure; it does not protect against compromise of the machine or full data directory.

Original files are immutable inputs; derived analysis revisions and function caches are separate. Interrupted analysis jobs are marked with an actionable failure and can be retried. Do not open an active project in Ghidra Desktop while the service owns it. Binary strings, symbols and model output are untrusted content. Worker subprocesses receive a restricted environment and resource limits, but local subprocesses are **not** a security sandbox: use a dedicated VM for untrusted specimens.

## Layout

```text
backend/ghidrama/   API, persistence, Ghidra workers, providers, LangGraph and MCP
frontend/          React + TypeScript workbench
scripts/           Local launcher, prerequisite check and deterministic PE fixture
tests/             API, provider, MCP and safety regression tests
docs/              Architecture and verification notes
```
