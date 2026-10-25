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
