# Verification record

Validated on 25 October 2026 on the local Linux development host.

## Installed and tested

- Python 3.12, Ghidra 12.1.3, JDK 21.0.12.1, PyGhidra 3.1.0.
- MCP Python SDK 1.30.0 and LangGraph 1.2.17.
- React/TypeScript/Vite production build with pnpm 11.25.0. Exact Python and JavaScript dependency versions are recorded in `requirements.lock` and `frontend/pnpm-lock.yaml`.

## Checks completed

- **24 automated tests pass.** Tests cover native PE validation, managed/truncated file rejection, address/path checks, revision caches, stale annotations, interrupted jobs, same-origin restrictions, upload limits, single-server ownership and global cross-process worker limits.
- Provider tests verify encrypted storage, atomic first-use key creation, masked responses, sanitized errors, tool-call message conversion and private continuation fields. They use mocked provider HTTP responses.
- Agent tests use the **real MCP stdio transport and server** with controlled model responses. They verify scope/revision checks, pagination bounds, actual tool use, evidence snapshots, citation repair, cancellation and persisted run state.
- Python dependency consistency check passes. TypeScript compilation and the production frontend build pass.
- Live HTTP smoke test uploaded a real native x64 PE, ran Ghidra, verified its header entry point, IAT imports, strings, helper decompilation, machine instructions and caller. A reviewed rename and comment persisted in the actual Ghidra project, and the report contained its file hash.
- A separate real x86 PE fixture was analyzed and decompiled correctly. Both fixtures compute `input * 3 + 17` in a helper function.
- Live cancellation stopped an analysis job and recorded its cancelled state.
- Browser verification covered file upload through the file chooser, successful analysis, decompiler navigation, call relationships, provider settings, a reviewed rename that advanced the analysis revision, and the 390-pixel responsive layout. Temporary viewport overrides were reset.
- The final application was restarted using `scripts/start.sh`, and its health endpoint reports the installed Ghidra and Java as available.

## Limits of this verification

- No real cloud inference request was made: the user has not supplied a provider API key. Model availability, account limits and analysis quality should be checked with the chosen model after configuration. Mocked responses are confined to tests and are not presented as live investigations.
- Docker/Compose packaging is supplied but was not executed because Docker is unavailable on this host.
- The corpus is small and deliberately understandable; these checks do not establish accuracy on packed, obfuscated, huge, or unusual executables.
- This is a local single-analyst release. It has no shared-user authentication or hardened multi-tenant sandbox. Native process limits are not a substitute for a VM boundary when inspecting hostile specimens.

The two fixture builders and HTTP smoke script are included so the real analysis checks can be repeated. Development-only failed/cancelled samples are archived outside the visible workbench.

## Pseudocode extension

- `tests/test_pseudocode.py` exercises extraction coverage, immutable revision exports, cache reuse, revision conflicts, cancellation, restart recovery, provider configuration errors, and real MCP transport with both Ollama Cloud and OpenRouter HTTP responses mocked.
- Function rewrites and program sketches must include a code block and cite decompiler evidence. Tests reject metadata-only citations, unavailable selected functions, and provider-truncated output. These checks validate format and provenance, not semantic equivalence.
- The local installation passed the full 38-test suite and the production frontend build. A fresh, clearly labelled `ghidrama-pseudocode-check.exe` fixture passed real Ghidra analysis and batch extraction: two of two indexed functions recovered, with the expected `argument * 3 + 17` logic in the C export and usable cached assembly.
- Browser checks verified the Pseudocode view, function selection, export coverage, prepared rewrite requests, and program scope when opening a closed Investigator panel. Cloud model quality remains untested against live accounts; no paid inference was used during verification.

## Investigation budget regression

- The observed failure exhausted the old 80,000 cumulative-token cap after seven calls (84,519 input and 311 output tokens), despite a checkpoint of only about 35,000 characters. No provider context-window failure was recorded.
- `tests/test_budgets.py` reproduces an investigation exceeding 80,000 tokens and completing under Extended; verifies Standard finalization, provider output allowances, citation repair, time/turn/tool limits, exhausted-budget and overshoot handling, and immutable server-selected limits. Model responses are mocked; source evidence passes through the real local MCP transport.
- Partial findings and evidence-only results remain downloadable and included in sample reports. Historical runs and provider credentials are unchanged. Tests do not retry the user's failed request against a live model.

## UPX preprocessing verification (2026-10-27)

- Installed official UPX 5.2.1 for Linux amd64 locally. Release archive SHA-256 `402162aad30af47e60dbd767fb2e64ca394ace9727ba1f40283641f1d1b91657` matched the GitHub release asset digest.
- Full regression suite: **66 passed**. New tests cover native PE passthrough, section/header detection, child credential isolation, immutable originals, content-addressed outputs, missing UPX, corrupt/unchanged/oversized output, architecture mismatch, timeout/cancellation and cleanup, failure before Ghidra, missing derived input, revision source routing, and MCP memory/provenance.
- Production frontend build passed. Local doctor and live health endpoint report UPX available.
- Existing user-uploaded Rufus 4.15 reanalyzed through the UI: original **1,989,992 bytes**, unpacked **5,422,952 bytes**. Original SHA-256 remains `84c8a437f8af89257524478489e5c85f1edf25f761d299e2bcde46ac0afbe106`; unpacked SHA-256 is `5cfec8255ad5a11883fafdf54ee064e44d218de6ab80b94375bc5b57b34c5325`.
- Ghidra revision 2 finished ready without warnings: **2,709 functions, 345 imports, 5,371 strings**, versus 1 function / 6 imports / 36 strings in the packed revision. Entry point changed from the packed loader to `0x1400f2f30`.
- Live API decompilation, report provenance, and real MCP stdio `get_program_info`, `read_memory_range`, and `decompile_function` verified against the unpacked PE. Original project and revision-1 artifact remain present. No uploaded executable was run and no live cloud inference was used.

## Configured-cloud Rufus rewrites (2026-10-27)

The user authorized actual cloud analysis of the unpacked Rufus file. Ollama Cloud `glm-5.3-flash` completed five function-scoped rewrites for 0x140039150 (startup), 0x1400356b0 (dialog), 0x140031e30 (preflight), 0x140011ac0 (format/deploy), and 0x140031220 (scan). All 233,447 available recovered-C characters across those routines were captured without gaps at revision 2. A local bundle retains unedited cloud answers, exact evidence, original recovered C, reviewed high-level pseudocode and correction notes. Reviews found and corrected several model control-flow/message-label mistakes; no semantic-equivalence claim is made. Neither packed nor unpacked specimen was executed.

Large-function work exposed the fixed 24,000-character decompilation excerpt and 4,096-token generation cap. Added bounded character paging; pseudocode now reserves a 12,288-token generation allowance and up to 180 seconds per provider request inside the existing cumulative budget. Full suite after those changes: 68 passed. Ollama `/api/show` reported model thinking values low/high/max with default max. An optional per-run override is validated against advertised metadata; the final dialog/preflight/format/scan runs used low. Targeted agent/provider/budget/pseudocode suite after that change: 43 passed. Failed and partial attempts remain in history. Provider-reported usage across this task's discovery and all attempts: 857,096 input + 51,664 output = 908,760 tokens.

## One-click workflow verification (2026-10-28)

- Full regression suite: **81 passed**. Production TypeScript/Vite build passed.
- New workflow tests use real MCP transport and mocked cloud HTTP for both Ollama and OpenRouter. They verify full-source rewrites beyond the old 24,000-character excerpt, valid address selection, shared budget admission, legacy reanalysis, cancellation before start and during a cloud request, duplicate prevention, revision changes, incomplete/uncited output, restart recovery, and ZIP provenance/evidence without credentials.
- No additional live cloud inference was needed for this feature verification. Existing Rufus analysis, prior cloud answers, provider settings, and specimen files were preserved. The workflow labels generated text as an AI interpretation and does not claim verified semantic equivalence.
