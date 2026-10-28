# Ghidrama

A local reverse engineering workbench for native Windows executables, powered by Ghidra, with a web interface and an MCP-driven LLM analyst. Use an Ollama Cloud API key or an OpenRouter API key. No OpenAI subscription or API key is required.

This release is for a single analyst on a trusted local machine. It performs **static analysis**: uploaded executables are never launched. The interface displays real Ghidra results; it does not substitute generated demonstrations when analysis or a model provider is unavailable.

## What is implemented

- Native x86/x64 PE EXE/DLL upload, format validation, SHA-256 identity, persistent analysis jobs, cancellation, and failure recovery.
- Real Ghidra projects through PyGhidra in separate worker processes. Per-project file locks serialize access across the API and MCP processes.
- Functions, lazy decompilation, instructions, strings, imports, exports, sections, and direct caller/callee relationships.
- A React workbench with function search, code navigation, a call graph, investigation history, evidence links, and Markdown report download.
- A Pseudocode workspace with cancellable extraction of all indexed functions, a revision-labelled `.c` export, and cloud-assisted function rewrites or program sketches.
- An **Analyze & rewrite** workflow: prepare the binary with UPX/Ghidra, discover up to five main routines with the configured cloud model, and generate separate readable rewrites with full captured source evidence and a ZIP export.
- Direct Ollama Cloud and OpenRouter integration, model discovery, connection testing, encrypted saved credentials, and provider-independent tool calls.
- A LangGraph investigation workflow using the official MCP client to call a real sample-scoped MCP stdio server. Tool schemas, argument validation, bounded output, run limits, and cancellation are enforced by application code.
- Reviewed function renames and comments, applied to the actual Ghidra project, with an audit record and revision checks.

The local release uses SQLite and filesystem artifacts, and a bounded local process queue. PostgreSQL, Redis/Celery, shared-user identity, external MCP access, Windows debugging, managed .NET decompilation, PDB upload workflows, advanced type editing, and unpackers beyond UPX are future extensions. Containers improve packaging; they do not turn this release into a hostile multi-tenant malware service.

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

For the automated path, upload an executable, open **Analyze & rewrite**, and click **Unpack, analyze & rewrite**. Choose a configured provider and up to 1, 3, or 5 main functions. The workflow can wait for an in-progress analysis; it re-prepares older analyses without preprocessing provenance. It never executes the specimen. Starting the workflow authorizes sending decompiled evidence to the selected provider and can consume cloud usage.

Main-function discovery has an 80,000-token investigation budget. Each selected function is then supplied in full to a separate rewrite request (maximum 180,000 source characters and 12,288 output tokens). The shared 500,000-token admission budget uses conservative estimates plus reported usage; it is not an exact billing cap. There are no automatic retries of failed rewrites. Ollama models advertising `low` thinking use that setting for this workflow, without changing saved provider settings. Other models keep their defaults.

Follow progress, cancel, inspect each answer and evidence, or download the results ZIP. Completed work survives cancellation, failure, and application restart. A restart does not automatically resume cloud spending. Running again starts a new cloud workflow and reuses revision-specific local decompilation caches. Selection is bounded, and inferred names and control flow require review: a successful workflow does not verify semantic equivalence or reconstruct the entire program.

1. Upload an EXE or DLL. Its analysis status changes from queued to analyzing and then ready, partial, or failed. A partial result is explicitly labelled.
2. Select a function to retrieve its decompilation and references. Large functions can take longer on the first request; later requests use the revision-specific cache.
3. Open provider settings. Choose Ollama Cloud or OpenRouter, enter the API key, select a tool-capable model, and save. The key is not returned by any read endpoint or saved in browser storage. The Ollama connection test sends a very short model request, which may consume account usage.
4. Ask a question, optionally scoped to the selected function. Starting an investigation sends your question and selected analysis evidence to the chosen cloud provider. Original binary files are not uploaded to the provider.
5. Follow evidence markers to inspect the supporting Ghidra data. A citation proves where evidence came from; it is not a guarantee that the model interpreted it correctly.
6. Propose a name or comment, review it, and apply. Changes require the expected analysis revision and update the underlying Ghidra project. To undo, propose the old value recorded in the audit history.

Ollama Cloud currently does not provide enforced structured outputs. Ghidrama validates arguments and tool results itself. OpenRouter requests require support for requested parameters and ask for providers with data collection disabled. Routing controls do not make cloud processing local. Use only specimens whose content you are permitted to send to the selected service.

## UPX unpacking

Uploads and analysis retries automatically check native x86/x64 PEs for standard UPX section names or a UPX pack header. When detected, Ghidrama runs the locally installed UPX tool with `-d` into a separate file before importing it into Ghidra. The uploaded executable is never launched. The original remains unchanged; the overview and reports show the original and analyzed SHA-256 hashes, sizes, and UPX version. Ghidra imports, raw-memory evidence, pseudocode, and cloud investigation tools all use the unpacked input for that revision. An older analysis with UPX sections offers **Unpack and reanalyze**.

Install the official [UPX release](https://github.com/upx/upx/releases) for your host and set `GHIDRAMA_UPX_PATH` to its executable, or put `upx` on `PATH`, then restart Ghidrama. The local installation in this workspace uses UPX 5.2.1. `scripts/doctor.py` and `/api/health` report availability. For Docker, mount a compatible UPX executable read-only inside the container and set the container's `GHIDRAMA_UPX_PATH` to that path; UPX is not bundled in the base image.

Unpacking has a 30-second timeout, a 256 MB output-file limit, and a 1 GB process address-space limit. Cancellation terminates the unpacker and removes incomplete output. Missing UPX, invalid output, or decompression failure stops analysis with an actionable error; it does not silently analyze the packed loader. Modified UPX stubs, removed signatures, other packers, and nested packing may need manual unpacking. Detection is a heuristic, not proof that an executable is unpacked. Unpacked bytes and Ghidra projects are kept by content hash, and earlier analysis revisions and evidence remain intact.

## Pseudocode and cloud rewrites

After uploading an EXE or DLL and waiting for analysis, open **Pseudocode**:

1. Select a function to view Ghidra's C-like pseudocode immediately. This uses local Ghidra and needs no model key.
2. Choose **Extract all functions** to decompile the indexed program in the background. Progress shows recovered, unavailable, and truncated functions. **Cancel extraction** stops the job while retaining completed batches. **Download pseudocode (.c)** exports the captured revision with addresses, coverage, and failure notices. It is reconstructed pseudocode, not the original source or a guaranteed compilable C program.
3. Choose **Rewrite selected function** for clearer names and structure, **Create program sketch** for an outline of the program's main logic, or **Analyze selected pseudocode** for an explanation. These buttons prepare a request in the Investigator.
4. Choose Ollama Cloud or OpenRouter, check the model and function context, then send the request. Rewrites retrieve real decompiler evidence through MCP, retain the original Ghidra output, and cite captured source evidence. Review the model's interpretation and uncertain names/types against that evidence. Completed answers and exact evidence can be downloaded from the Investigator and revisited in its history.

Local extraction covers functions in Ghidra's index; undiscovered or packed code may be absent. A job is limited to 15 minutes plus completion of its current bounded batch and 20 million exported pseudocode characters. Run extraction again to reuse completed function caches. Analysis changes require a new extraction; existing downloads identify their captured revision.

For large routines, the model can page through decompiled C with `decompile_function` character offsets (up to 24,000 characters per page). Pseudocode runs allow up to 12,288 generated tokens per response and 180 seconds per provider call; these remain inside the selected cumulative run budget, with the larger response reserved before further exploration. Ordinary investigations retain the 4,096-token response allowance.

A cloud **program sketch** covers the routines the model inspects within the existing investigation limits, rather than rewriting every function in a large executable. The interface reports how many functions supplied decompiler evidence. Truncated source is flagged, and responses cut off by a provider's output limit are reported as failures. Cloud requests only start when sent from the Investigator. Model results remain interpretations, not proof of semantic equivalence or recovered original source.

## Investigation budgets

The Investigator's **Run budget** selector controls cumulative input and output usage across all model calls. Each call sends the conversation again, so this total can be much larger than the model's context window. The default is **Extended**.

| Budget | Cumulative tokens | Model turns | Tool calls | Time |
| --- | ---: | ---: | ---: | ---: |
| Standard | 80,000 | 12 | 32 | 4 minutes |
| Extended (default) | 250,000 | 24 | 64 | 10 minutes |
| Deep | 500,000 | 40 | 100 | 15 minutes |

Larger budgets may use more provider credits. These are application limits, not changes to the provider's context window or account quota. Usage is reported by the provider; estimates reserve room for a final answer and one citation correction. Tokenization and provider accounting vary, so the cumulative token target is not an exact billing cap.

As a run approaches a limit, Ghidrama stops offering tools and requests a final, cited answer from the captured evidence. Such results are labelled **partial**, can be downloaded, and remain in history. If there is not enough room for another model call, the result is explicitly labelled as an evidence index, with no claim that a model answer was produced. Time and context-size stops also retain captured evidence. Select **Use question again** to prepare a new question under the selected budget; check the current function context and provider before sending. Existing failed runs are preserved and never automatically retried.

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
| `GHIDRAMA_UPX_PATH` | Optional absolute UPX executable path; otherwise searches PATH |
| `GHIDRAMA_MAX_UNPACKED_MB` | Maximum unpacked PE file size; default 256 MB |
| `GHIDRAMA_UNPACK_TIMEOUT` | UPX wall-clock and CPU limit in seconds; default 30 |
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
