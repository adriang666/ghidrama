# Architecture

Ghidrama separates browser interaction, analysis, and model access. FastAPI serves the built React interface and same-origin APIs. Original uploaded PE files are stored as read-only inputs under a SHA-256-identified sample record. A local asynchronous queue owns analysis jobs; JVM processes perform actual Ghidra operations.

## Ghidra access

Each sample has a persistent Ghidra project, a cross-process project lock, immutable exported analysis revisions, and revision-specific function detail caches. Initial analysis exports the index and PE metadata. Opening a function lazily invokes the Ghidra decompiler and records instructions and direct call relationships. A global file-lock slot pool limits all worker processes, including lazy decompilation invoked by MCP.

Workers receive a restricted environment, a private home directory, Java heap/CPU/file limits and operation deadlines. They inherit neither provider API keys nor tracing credentials. Linux parent-death signals prevent detached JVMs if an owning API/MCP process exits. There is no OS network sandbox in this release.

Function addresses are hexadecimal strings, not JavaScript numbers. PE import/export addresses come from the immutable original header; Ghidra references retain their address-space information. Revisions change after analysis or reviewed annotation changes. A proposal checks its expected revision before changing the real Ghidra database transactionally. Original executable bytes never change.

## Investigation workflow

1. The API validates the sample, selected function, provider configuration and concurrent-run limit.
2. The run starts a sample/revision-scoped MCP stdio server through the official MCP client. The server exposes only typed read tools.
3. A LangGraph state graph alternates model requests and validated MCP tool calls, followed by citation-format verification. It permits one citation correction attempt.
4. Exact tool results receive evidence IDs and are retained independently from the mutable current analysis view. The UI can open these captured snapshots even after annotations advance the project revision.
5. JSON-only run state, events, evidence and token counts are saved locally. An application restart marks unfinished investigations interrupted, with evidence retained; it does not silently resume paid requests.

The default Extended budget allows 24 model turns, 64 tool calls, 600 seconds and 250,000 reported cumulative input/output tokens. Standard retains 12 turns / 32 tools / 240 seconds / 80,000 tokens; Deep allows 40 turns / 100 tools / 900 seconds / 500,000 tokens. Each run stores its selected profile and immutable limit snapshot. The context payload still has a separate 180,000-character bound. Two investigations may run at once. Tool calls are schema-checked, outputs are paginated/bounded, repeated identical calls are limited, and cancellation propagates to MCP and active Ghidra work.

The model APIs are called directly by provider adapters. MCP is the analysis-tool protocol, not a proxy for model inference. Ollama Cloud and OpenRouter credentials are encrypted in SQLite with a separate, mode-0600 encryption key. Only masked provider configuration reaches the browser. Private provider continuation fields are retained only in internal run state; they are not shown as an activity trace.

Before each model call, the agent estimates the next prompt size (including tool schemas), calibrated to the previous provider-reported input-token count. It reserves room for an answer and one citation repair, and limits requested output tokens to the remaining estimated allowance. Approaching token, tool, turn, or time limits switches to a no-tools finalization request. Verified results at that boundary are marked partial; a hard limit with no viable request retains a clearly labelled application-generated evidence index. Exact evidence is neither truncated nor replaced by a summary to satisfy the cumulative budget. Estimates may differ from provider billing; this is not a hard monetary cap. Model transport, credential, and invalid-citation failures remain explicit errors. No run is automatically resumed or retried against a paid provider.

## Pseudocode workflow

The Pseudocode workspace reads the current function's local Ghidra decompilation. Program extraction is an explicit background job persisted in `pseudocode_jobs`. Up to two extraction jobs run concurrently, using the existing cross-process worker slots and project locks. Each batch decompiles at most four missing functions in one JVM; revision-specific detail caches are shared with the Decompiler and MCP tools. Progress distinguishes recovered, failed, truncated, and unprocessed functions. Cancellation joins the worker thread and terminates active subprocess work via the existing cancellation checks. Restart recovery marks interrupted jobs; it never starts cloud requests.

The `.c` download streams only the captured revision's cached bodies, with a SHA-256, coverage header, and any missing-code notices. A later annotation or reanalysis cannot silently replace those bodies with a new revision. Extraction is bounded by 15 minutes between batches and 20 million pseudocode characters. Analysis remains an index of discoverable functions, not a guarantee of complete source recovery.

Cloud rewrites use the existing agent pipeline with `mode=pseudocode`. The selected function, or the program entry point (first indexed function as fallback), is decompiled through real MCP before inference. A rewrite requires a nonempty code block and a citation to captured decompilation evidence; this validates provenance and format, not semantic equivalence. Coverage records the function addresses actually retrieved, and truncated evidence is flagged. Provider output-limit truncation fails the rewrite instead of publishing incomplete code as complete. Ollama Cloud and OpenRouter use the same workflow. Program sketches stay within the existing tool/context/time limits; they do not promise a full rewrite of every function. Downloads include the answer and exact captured evidence, and the UI preserves the original Ghidra output for comparison.

## Boundaries

The built-in UI/API is bound to loopback. Allowed-host and origin checks reduce cross-site access, and generated Markdown cannot fetch external images. LLM tools cannot change annotations, run code, execute specimens, or choose another sample. These restrictions are enforced by the exposed API/tool surface, not solely by prompts.

Evidence citations establish provenance, not semantic correctness. The verifier checks citation IDs; analysts must assess whether the cited instructions support the conclusion. Binary strings, symbols, comments and tool content are untrusted data throughout.

The local release intentionally uses SQLite and a bounded process queue. A shared deployment needs authentication/authorization, a server database and durable distributed queue, separated analysis machines, and stronger isolation before network exposure. See the README for the scope of the current implementation.

## UPX preprocessing

Analysis validates the immutable original hash, detects ordinary UPX sections/header, and invokes UPX in a separate, cancellable process before Ghidra import. The launcher strips credentials, sets CPU/address-space/file-size limits, and uses an explicit output file; samples are never executed. Output must be a valid native PE with the original architecture. Derived files are read-only and named by SHA-256. The analysis artifact captures preprocessing provenance, and all later Ghidra operations select that revision’s source and content-specific project. Legacy/original projects remain in `project/`. MCP memory reads resolve the same source as the decompiler. Pseudocode jobs and investigation runs snapshot the provenance for downloads even after later reanalysis.
# One-click workflow orchestration

`workflow.py` persists workflow history in SQLite and orchestrates existing analysis jobs, one bounded MCP investigation for main-function selection, and separate fixed-context cloud rewrites. A workflow snapshots the configured provider/model and records original/analyzed hashes and the analysis revision. Selected addresses must exist in the function index. Rewrites send complete cached Ghidra source (up to 180,000 characters), retain exact evidence in `agent_evidence`, and appear in normal investigation history. Evidence citations and output completeness are checked; semantics are not automatically verified.

One workflow runs at a time. It has a 40-minute wall limit and a shared 500,000-token admission budget (estimates/reservations plus provider usage). Discovery reserves at least 80,000 tokens. Failed/oversized functions do not discard completed results, and provider failures are not automatically retried. Cancellation joins local decompilation work and stops the active cloud task; analysis already running before the workflow is not cancelled on its behalf. Analysis/annotation mutation endpoints reject changes while a workflow owns that sample. Restarts mark unfinished workflows interrupted without repeating cloud calls. ZIP exports contain public run records, answers and exact evidence; private provider reasoning and credentials are excluded.
