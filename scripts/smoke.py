#!/usr/bin/env python3
"""Exercise the running local API and real Ghidra with a known benign fixture.

Creates one clearly named validation sample and two reviewed annotations.
Never calls a model provider and never executes the specimen.
"""
import argparse
import time

import httpx

from make_fixture import build_fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--skip-annotations", action="store_true")
    args = parser.parse_args()
    with httpx.Client(base_url=args.url, timeout=180) as client:
        health = client.get("/api/health").raise_for_status().json()
        assert health["ghidra_available"], f"Ghidra is not ready: {health}"
        created = client.post("/api/samples", files={"file": ("ghidrama-fixture.exe", build_fixture(), "application/octet-stream")}).raise_for_status().json()
        sample_id = created["id"]
        print(f"Uploaded fixture: {sample_id}", flush=True)
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            sample = client.get(f"/api/samples/{sample_id}").raise_for_status().json()
            if sample["status"] in {"ready", "partial", "failed", "cancelled"}:
                break
            time.sleep(0.5)
        assert sample["status"] == "ready", sample
        print("Ghidra analysis ready.", flush=True)
        analysis = client.get(f"/api/samples/{sample_id}/analysis").raise_for_status().json()
        assert analysis["entry_point"] == "0x140001000"
        assert {i["name"] for i in analysis["imports"]} >= {"OutputDebugStringA", "ExitProcess"}
        assert analysis["exports"] == []
        assert any("Ghidrama verification fixture" in s["value"] for s in analysis["strings"])
        function = client.get(f"/api/samples/{sample_id}/functions/0x140001040").raise_for_status().json()
        assert "* 3" in function["decompiled"] and "0x11" in function["decompiled"], function
        assert any(i["mnemonic"] == "IMUL" for i in function["disassembly"]), function
        assert any(f["address"] == "0x140001000" for f in function["callers"])
        print("Verified entry point, imports, string, decompilation, assembly and caller.", flush=True)
        if not args.skip_annotations:
            for kind, value in [("rename", "calculate_value"), ("comment", "Verified test fixture: computes input * 3 + 17.")]:
                sample = client.get(f"/api/samples/{sample_id}").raise_for_status().json()
                proposal = client.post(f"/api/samples/{sample_id}/annotations", json={"address": "0x140001040", "kind": kind, "value": value, "expected_revision": sample["analysis_revision"]}).raise_for_status().json()
                applied = client.post(f"/api/samples/{sample_id}/annotations/{proposal['id']}/apply").raise_for_status().json()
                assert applied["status"] == "applied"
            updated = client.get(f"/api/samples/{sample_id}/functions/0x140001040").raise_for_status().json()
            assert updated["name"] == "calculate_value"
            assert "input * 3 + 17" in updated["comment"]
            print("Verified reviewed rename and comment persist in the Ghidra project.", flush=True)
        report = client.get(f"/api/samples/{sample_id}/report").raise_for_status()
        assert created["sha256"] in report.text
        bad = client.post("/api/samples", files={"file": ("not-a-pe.exe", b"not an executable")})
        assert bad.status_code == 400
        cross_site = client.post(f"/api/samples/{sample_id}/analyze", headers={"Origin": "https://untrusted.example"})
        assert cross_site.status_code == 403
        providers = client.get("/api/providers").raise_for_status().json()
        assert {p["id"] for p in providers} == {"ollama", "openrouter"}
        assert all("api_key" not in p for p in providers)
        print("Verified report, invalid-upload rejection, cross-origin protection and masked provider settings.")
        print(f"PASS. Open {args.url} and select ghidrama-fixture.exe. No cloud inference was used.")


if __name__ == "__main__":
    main()
