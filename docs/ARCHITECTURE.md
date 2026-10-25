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

Default limits are 12 model turns, 32 tool calls, 240 seconds, 80,000 reported cumulative tokens and a bounded context payload. Two investigations may run at once. Tool calls are schema-checked, outputs are paginated/bounded, repeated identical calls are limited, and cancellation propagates to MCP and active Ghidra work.

The model APIs are called directly by provider adapters. MCP is the analysis-tool protocol, not a proxy for model inference. Ollama Cloud and OpenRouter credentials are encrypted in SQLite with a separate, mode-0600 encryption key. Only masked provider configuration reaches the browser. Private provider continuation fields are retained only in internal run state; they are not shown as an activity trace.

## Boundaries

The built-in UI/API is bound to loopback. Allowed-host and origin checks reduce cross-site access, and generated Markdown cannot fetch external images. LLM tools cannot change annotations, run code, execute specimens, or choose another sample. These restrictions are enforced by the exposed API/tool surface, not solely by prompts.

Evidence citations establish provenance, not semantic correctness. The verifier checks citation IDs; analysts must assess whether the cited instructions support the conclusion. Binary strings, symbols, comments and tool content are untrusted data throughout.

The local release intentionally uses SQLite and a bounded process queue. A shared deployment needs authentication/authorization, a server database and durable distributed queue, separated analysis machines, and stronger isolation before network exposure. See the README for the scope of the current implementation.
