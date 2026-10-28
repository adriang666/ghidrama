# Ghidrama implementation contracts

Local, single-analyst first release. Python FastAPI backend under backend/ghidrama, React/TypeScript/Vite frontend under frontend. All API paths prefixed /api. Browser uses same origin; Vite proxies /api to 127.0.0.1:8000. Backend serves frontend/dist in production. No fabricated analysis or model results. Original binaries never execute. SQLite metadata, actual Ghidra projects, bounded subprocess analysis. Use real installed PyGhidra or headless Ghidra.

## Shared backend interfaces (coordinate changes)

Core agent owns config.py, store.py, analysis.py, ghidra_worker.py, main.py and backend core tests. Agent integration agent owns providers.py, agent.py, mcp_server.py, and integration tests. Root owns packaging, runtime setup, scripts, docs, and cross-component verification. Frontend agent owns all frontend files.

`config.settings` exposes data_dir: Path, ghidra_install_dir: Path|None, java_home: Path|None, max_upload_mb: int. `store.Store` default constructor uses settings and exposes get_sample(id)->dict|None, list_samples()->list[dict], get_analysis(sample_id)->dict|None (JSON artifact), get_function(sample_id, address)->dict|None, list_functions(sample_id, query='')->list[dict]. Additional persistence methods to be coordinated. Sample dict: id, name, sha256, size, architecture, status (queued/analyzing/ready/partial/failed/cancelled), created_at, error|null, function_count, analysis_revision. Analysis dict: sample_id, revision, image_base, entry_point, architecture, format, functions, imports, exports, strings, sections, engine, warnings. Function dict: address (hex string), name, size, signature, decompiled (string|null), disassembly (list of {address,bytes,mnemonic,operands}), callers (list of {address,name}), callees (list of {address,name}), comment|null. Strings: {address,value}; imports/exports: {address,name,library?}; sections: {name,address,size,permissions}. Full-address strings throughout.

## HTTP API

- GET /api/health -> {status,ghidra_available,ghidra_version,active_jobs}
- GET /api/samples -> Sample[]
- POST /api/samples (multipart field file) -> Sample (202)
- POST /api/samples/{id}/analyze -> Sample (202); POST .../cancel -> Sample
- GET /api/samples/{id} -> Sample
- GET /api/samples/{id}/analysis -> Analysis, exclude large function bodies if useful but documented
- GET /api/samples/{id}/functions?q= -> FunctionSummary[]
- GET /api/samples/{id}/functions/{address} -> Function
- GET /api/samples/{id}/report -> downloadable Markdown
- GET /api/providers -> [{id:'ollama'|'openrouter',configured,model,base_url}]
- PUT /api/providers/{id} body {api_key?: string,model: string} -> masked ProviderInfo
- POST /api/providers/{id}/test -> {ok,message}
- GET /api/providers/{id}/models -> [{id,name}]
- POST /api/samples/{id}/runs body {question,provider,model?,function_address?,mode?:'investigation'|'pseudocode',expected_revision?,budget?:'standard'|'extended'|'deep'} -> Run (202)
- GET /api/samples/{id}/runs -> Run[]
- GET /api/runs/{id} -> Run
- POST /api/runs/{id}/cancel -> Run
- GET /api/runs/{id}/download -> completed answer and exact captured evidence as Markdown
- GET /api/samples/{id}/pseudocode -> latest local extraction job or null
- POST /api/samples/{id}/pseudocode body {expected_revision} -> extraction job (202)
- POST /api/samples/{id}/pseudocode/cancel -> extraction job after cancellation
- GET /api/samples/{id}/pseudocode/download?revision=N -> captured Ghidra pseudocode as a `.c` attachment with coverage and failure notices
- Extraction job: {sample_id,analysis_revision,status:'queued'|'running'|'complete'|'partial'|'failed'|'cancelled'|'interrupted',total,processed,recovered,failed,truncated,characters,functions:[{address,name,available,truncated,error?}],source_partial,warnings,error,created_at,finished_at?}. Two extraction jobs maximum; four functions per JVM batch, existing global worker slots, 15-minute limit between batches, 20-million-character export limit.
- Runs also preserve mode, function_address, analysis_revision and optional pseudocode_coverage:{scope:'function'|'program_sketch',addresses,total_functions,truncated}. Existing runs without mode are ordinary investigations. Cloud rewrites require captured decompilation citations and a code block; the verifier does not prove semantic equivalence.
- Run: {id,sample_id,question,provider,model,status:'queued'|'running'|'complete'|'partial'|'failed'|'cancelled',answer,error,events:[{type,message,tool?,arguments?,evidence_id?}],created_at,evidence:[{id,address?,tool,summary}],usage:{input_tokens,output_tokens}}. Answer references [E1], [E2], etc. No hidden reasoning.
- GET /api/samples/{id}/annotations -> Annotation[]
- POST /api/samples/{id}/annotations body {address,kind:'rename'|'comment',value,expected_revision} -> annotation proposal
- POST /api/samples/{id}/annotations/{annotation_id}/apply -> Annotation (status applied; revision increments)
- Annotation: {id,sample_id,address,kind,value,old_value,status:'proposed'|'applied',created_at}

Agent integration exposes `router: APIRouter` with above provider/run endpoints (paths prefixed /api in router itself) and `shutdown()` async cleanup. Core main includes it. Integration can own SQLite provider/run tables via separate module with own connections to data_dir/state.db. MCP server runs as stdio subprocess `python -m ghidrama.mcp_server --sample-id ID` with only read tools scoped to that sample. Agent MUST call tools through genuine MCP client, not dispatch locally while claiming MCP. MCP server uses Store to read analysis. Use LangGraph StateGraph for bounded tool loop. Run budgets: Standard 80k tokens / 12 turns / 32 tools / 4min; Extended (default) 250k / 24 / 64 / 10min; Deep 500k / 40 / 100 / 15min. Persist budget and limits:{total_tokens,model_turns,tool_calls,seconds} on the run. Usage is cumulative across requests, with estimates reserving a final answer; finalization offers no tools. Limited results use status partial, limit_reason, and answer_kind:model|evidence_index. Exact evidence is retained; partial results are downloadable and included in reports. Provider-account/context limits remain independent; cancellation is supported. Persist JSON-only run state. Provider credentials encrypted at rest (key outside DB, file mode 0600), never returned/logged/in subprocess env.

Frontend: polished dark professional analyst workbench, teal accents, no dashboard filler. Top header with product mark/upload/provider settings; sample browser and functions left; overview/decompiler/disassembly/strings/imports/graph center; agent panel right, collapsible for narrow screens. Real empty states and availability/setup feedback. File upload, polling progress, select sample/function, search, readable code, ask agent, provider settings, evidence navigation, report download, annotation review. Client never persists credentials. Built-in illustrative/demo values prohibited except fixture explicitly uploaded by tests.

UPX preprocessing: `/api/health` includes `upx_available` and `max_unpacked_mb`. Analysis may include `preprocessing:{status:unpacked|not_detected,original_sha256,original_size,analyzed_sha256,analyzed_size,indicators,tool?,tool_version?}`; absent means legacy analysis. Uploads/retries unpack detected UPX before Ghidra import; failure stops the job. Original SHA on Sample always identifies the upload. MCP `get_program_info.program.preprocessing` identifies the analyzed bytes; memory reads and all Ghidra operations resolve the captured source. Pseudocode jobs and runs snapshot optional preprocessing provenance for exports.

`decompile_function(address, offset=0, limit=24000)` returns character pages with `offset`, `total_characters`, `next_offset`, and `source_truncated`; `truncated` labels an excerpt or an upstream-truncated source. Negative/out-of-range offsets and limits outside 1–24000 are rejected. Pseudocode runs record `max_output_tokens:12288`, ordinary investigations 4096; reservation and provider time allowances account for the selected mode while respecting cumulative limits.

Optional `StartRun.thinking` selects an Ollama boolean or named level (`low`, `medium`, `high`, `max`). The API checks `/api/show` for model-advertised values, applies the override only to that run, and records it. Omission preserves the provider default; OpenRouter overrides are rejected.
