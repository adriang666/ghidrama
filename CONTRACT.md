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
- POST /api/samples/{id}/runs body {question,provider,model?,function_address?} -> Run (202)
- GET /api/samples/{id}/runs -> Run[]
- GET /api/runs/{id} -> Run
- POST /api/runs/{id}/cancel -> Run
- Run: {id,sample_id,question,provider,model,status:'queued'|'running'|'complete'|'failed'|'cancelled',answer,error,events:[{type,message,tool?,arguments?,evidence_id?}],created_at,evidence:[{id,address?,tool,summary}],usage:{input_tokens,output_tokens}}. Answer references [E1], [E2], etc. No hidden reasoning.
- GET /api/samples/{id}/annotations -> Annotation[]
- POST /api/samples/{id}/annotations body {address,kind:'rename'|'comment',value,expected_revision} -> annotation proposal
- POST /api/samples/{id}/annotations/{annotation_id}/apply -> Annotation (status applied; revision increments)
- Annotation: {id,sample_id,address,kind,value,old_value,status:'proposed'|'applied',created_at}

Agent integration exposes `router: APIRouter` with above provider/run endpoints (paths prefixed /api in router itself) and `shutdown()` async cleanup. Core main includes it. Integration can own SQLite provider/run tables via separate module with own connections to data_dir/state.db. MCP server runs as stdio subprocess `python -m ghidrama.mcp_server --sample-id ID` with only read tools scoped to that sample. Agent MUST call tools through genuine MCP client, not dispatch locally while claiming MCP. MCP server uses Store to read analysis. Use LangGraph StateGraph for bounded tool loop. Max 12 iterations, max 32 tools, max 4min total; cancellation. Persist JSON-only run state. Provider credentials encrypted at rest (key outside DB, file mode 0600), never returned/logged/in subprocess env.

Frontend: polished dark professional analyst workbench, teal accents, no dashboard filler. Top header with product mark/upload/provider settings; sample browser and functions left; overview/decompiler/disassembly/strings/imports/graph center; agent panel right, collapsible for narrow screens. Real empty states and availability/setup feedback. File upload, polling progress, select sample/function, search, readable code, ask agent, provider settings, evidence navigation, report download, annotation review. Client never persists credentials. Built-in illustrative/demo values prohibited except fixture explicitly uploaded by tests.
