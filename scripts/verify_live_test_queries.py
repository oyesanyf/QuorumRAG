#!/usr/bin/env python3
"""End-to-end live HTTP `/api/query` verification suite for QuorumRAG v0.6.16.

Spawns a real `quorumrag` release daemon against an isolated corpus containing
homonym clusters, noisy ChatGPT export markers, and forensic distractors, then
executes real live queries over HTTP (`POST /api/query`) to confirm:
  1. "WHO IS ANGELA DAVIS" -> 3-cluster homonym disambiguation, clean formatting,
     zero pretraining biography backfill, zero distractor bleed.
  2. "who is michael chen" -> general 2-cluster homonym disambiguation (zero
     hardcoded entity rules).
  3. Phase A (Default-Off Forensics): `GET /api/artemis/status` and
     `GET /api/v1/artemis/status` return HTTP 403 Forbidden by default, and
     `"WHAT PROCESS IS USING DNS TRAFFIC"` skips forensic/`artemis://` sources
     with an explicit disabled-forensics notice.
  4. Phase B (Explicit User Opt-In Forensics): after enabling forensics via
     `POST /api/settings` (`{"forensics_enabled": true}`) and
     `POST /api/v1/artemis/config` (`{"enabled": true, "local_collection_enabled": true}`),
     `"WHAT PROCESS IS USING DNS TRAFFIC"` (`bypass_cache=true`) harvests live OS
     DNS telemetry into a structured Markdown DNS summary table with zero raw JSON
     and zero static Python drift.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def http_json(port: int, method: str, path: str, payload: dict | None = None, timeout: float = 90.0) -> tuple[int, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        body_bytes = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json; charset=utf-8"} if body_bytes is not None else {}
        conn.request(method, path, body=body_bytes, headers=headers)
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8", errors="replace")
        parsed = json.loads(raw) if raw.strip() else {}
        return resp.status, parsed
    finally:
        conn.close()


def require(cond: bool, msg: str) -> None:
    if not cond:
        raise RuntimeError(f"E2E Verification Failure: {msg}")


def seed_corpus(corpus_dir: Path) -> None:
    (corpus_dir / "Women_Race_Class_Summary.txt").write_text(
        "**:::Women Race Class Summary\n"
        'entity["book","Women, Race & Class","Angela Davis 1981"] is a landmark critical theory work by '
        'entity["people","Angela Davis","American political activist and scholar"], first published in 1981.\n'
        "Across thirteen chapters, Angela Davis analyzes the historical intersectionality of race, gender, labor, "
        "abolitionist organizing, reproductive justice, and working-class solidarity in American history.\n"
        'Hi! It looks like you mentioned "zrubrics" - could you clarify what you mean?\n',
        encoding="utf-8",
    )

    (corpus_dir / "Castiglione_Lease_Agreement_2015.txt").write_text(
        "SIMPLE MONTH TO MONTH YEAR LEASE AGREEMENT\n"
        "This lease agreement is entered into between Firldeal (Angela Davis) Breure (landlord and lessor) "
        "and Aerial McDougle (tenant) for the residential dwelling unit located at 2913 Castiglione St., "
        "New Orleans, LA 70119. Monthly rent is $725.00 payable on the first day of each month. "
        "Call 911 in case of emergency. No subletting allowed without written landlord approval. "
        "Renters insurance is strongly recommended for personal property protection.\n",
        encoding="utf-8",
    )

    (corpus_dir / "Ava_Davis_Hope_St_Lease.txt").write_text(
        "RESIDENTIAL LEASE AGREEMENT\n"
        "Entered into between Angela Davis (lessor) and Ava Davis (tenant, not related) for the residential "
        "property at 1967 Hope St., New Orleans, LA. Security deposit and monthly rental covenants apply "
        "under Louisiana residential landlord-tenant rules.\n",
        encoding="utf-8",
    )

    (corpus_dir / "Unity_Ministry_Steward_Board.txt").write_text(
        "Computer Manuscript Assistance & Ministry Notes\n"
        "Reverend Angela Davis serves as an ordained Unity minister and STEWARD board participant leading "
        "contemplative spiritual teaching, metaphysical balance workshops, and community stewardship outreach.\n",
        encoding="utf-8",
    )

    (corpus_dir / "Zrubrics_Clarification.txt").write_text(
        "Zrubrics Clarification rubric scoring worksheet for classroom grading criteria and Davis scale templates.\n",
        encoding="utf-8",
    )

    (corpus_dir / "C2_Traffic_Detection_Adequacy.txt").write_text(
        "def get_dns_query_sysmon():\n"
        "    # TODO: Process the results to flag any unusual DNS activity.\n"
        "    return get_sysmon_events([22])\n",
        encoding="utf-8",
    )

    (corpus_dir / "Michael_Chen_Cardiology_Roster.txt").write_text(
        "St. Jude Medical Center Department Roster\n"
        "Dr. Michael Chen, MD is an attending physician and clinical cardiologist overseeing patient cardiac "
        "catheterization and arrhythmia diagnosis protocols since 2019.\n",
        encoding="utf-8",
    )

    (corpus_dir / "Michael_Chen_Security_Architect.txt").write_text(
        "Platform Security Engineering Biography\n"
        "Michael Chen is a CISSP principal security architect and distributed systems software engineer "
        "designing zero-trust Kubernetes service meshes and HSM key rotation infrastructure in Austin, TX.\n",
        encoding="utf-8",
    )


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="Verify live QuorumRAG HTTP test queries")
    parser.add_argument("--bin", required=True, help="Path to compiled quorumrag binary")
    parser.add_argument("--port", type=int, default=3045, help="HTTP port for isolated daemon")
    parser.add_argument("--p2p-port", type=int, default=3046, help="P2P port for isolated daemon")
    args = parser.parse_args()

    bin_path = Path(args.bin).resolve()
    require(bin_path.is_file(), f"Binary does not exist: {bin_path}")

    with tempfile.TemporaryDirectory(prefix="quorumrag_e2e_", ignore_cleanup_errors=True) as tmp_root:
        tmp_path = Path(tmp_root)
        data_dir = tmp_path / "data"
        corpus_dir = tmp_path / "corpus"
        data_dir.mkdir(parents=True, exist_ok=True)
        corpus_dir.mkdir(parents=True, exist_ok=True)
        seed_corpus(corpus_dir)

        child_env = os.environ.copy()
        child_env["QUORUM_SHOW_CONSOLE"] = "1"
        child_env["QUORUM_ISOLATED_WATCH_DIR"] = "1"
        child_env["QUORUM_DISABLE_OLLAMA_AUTOINSTALL"] = "1"

        print(f"[E2E 1/5] Indexing test corpus with {bin_path.name}...")
        reindex_log_path = tmp_path / "reindex.log"
        reindex_cmd = [
            str(bin_path),
            "--data-dir",
            str(data_dir),
            "reindex",
            "--path",
            str(corpus_dir),
            "--full",
        ]
        with open(reindex_log_path, "w", encoding="utf-8", errors="replace") as rlog_f:
            reindex_proc = subprocess.Popen(
                reindex_cmd,
                env=child_env,
                stdin=subprocess.DEVNULL,
                stdout=rlog_f,
                stderr=subprocess.STDOUT,
            )
            reindex_rc = reindex_proc.wait(timeout=120)
        reindex_out = reindex_log_path.read_text(encoding="utf-8", errors="replace")
        require(
            reindex_rc == 0,
            f"reindex failed ({reindex_rc}):\n{reindex_out}",
        )

        print(f"[E2E 2/5] Starting live QuorumRAG daemon on 127.0.0.1:{args.port}...")
        daemon_log_path = tmp_path / "daemon.log"
        daemon_cmd = [
            str(bin_path),
            "--host",
            "127.0.0.1",
            "--port",
            str(args.port),
            "--p2p-port",
            str(args.p2p_port),
            "--data-dir",
            str(data_dir),
            "--watch-dir",
            str(corpus_dir),
            "--no-browser",
            "--local-only",
            "--no-p2p-watcher",
        ]
        daemon_log_f = open(daemon_log_path, "w", encoding="utf-8", errors="replace")
        proc = subprocess.Popen(
            daemon_cmd,
            env=child_env,
            stdin=subprocess.DEVNULL,
            stdout=daemon_log_f,
            stderr=subprocess.STDOUT,
        )
        try:
            ready = False
            for _ in range(60):
                if proc.poll() is not None:
                    daemon_log_f.flush()
                    out_log = daemon_log_path.read_text(encoding="utf-8", errors="replace")
                    raise RuntimeError(f"Daemon exited early with code {proc.returncode}:\n{out_log}")
                try:
                    code, _ = http_json(args.port, "GET", "/api/health", timeout=2.0)
                    if code == 200:
                        ready = True
                        break
                except Exception:
                    pass
                time.sleep(0.5)
            require(ready, f"Daemon on 127.0.0.1:{args.port} did not become healthy within 30s")

            # Nimble-9B Status & Non-Intrusive UI Asset Check (v0.6.16)
            print("\n[E2E 2b/5] Verifying live GET /api/models/nimble/status & non-intrusive /assets/app.js...")
            st_nim, nim_status = http_json(args.port, "GET", "/api/models/nimble/status", timeout=15.0)
            require(st_nim == 200, f"HTTP {st_nim} on GET /api/models/nimble/status: {nim_status}")
            require(
                nim_status.get("fallback_model_tag")
                in ("qwen2.5:1.5b", "qwen2.5:3b", "qwen2.5:7b", "qwen2.5:14b", "qwen2.5:32b"),
                f"Expected memory-fitted fallback_model_tag on /api/models/nimble/status, got: {nim_status}",
            )
            require(
                isinstance(nim_status.get("installed_models"), list),
                f"Expected installed_models array on /api/models/nimble/status, got: {nim_status}",
            )
            ui_conn = http.client.HTTPConnection("127.0.0.1", args.port, timeout=15.0)
            try:
                ui_conn.request("GET", "/assets/app.js")
                ui_resp = ui_conn.getresponse()
                app_js_body = ui_resp.read().decode("utf-8", errors="replace")
                require(ui_resp.status == 200, f"Expected HTTP 200 on /assets/app.js, got {ui_resp.status}")
                require(
                    "nimble-settings-card-slot" in app_js_body
                    and "chatStream.parentElement.insertBefore(card" not in app_js_body,
                    "Expected #nimble-guidance-card to be confined to Settings and never injected into chatStream",
                )
            finally:
                ui_conn.close()

            # Query 1: WHO IS ANGELA DAVIS
            print("\n[E2E 3/5] Querying live HTTP /api/query: 'WHO IS ANGELA DAVIS'...")
            st1, q1 = http_json(args.port, "POST", "/api/query", {"prompt": "WHO IS ANGELA DAVIS"})
            require(st1 == 200, f"HTTP {st1} on WHO IS ANGELA DAVIS: {q1}")
            ans1 = q1.get("synthesis_prompt", "")
            print("=== [LIVE /api/query RESPONSE: WHO IS ANGELA DAVIS] ===")
            print(ans1)
            print("=== [END RESPONSE] ===")
            require(
                "multiple distinct individuals" in ans1 or "distinct contexts" in ans1,
                "Missing upfront homonym disambiguation banner on WHO IS ANGELA DAVIS",
            )
            require(
                "### Academic Scholarship, Published Works & Critical Theory" in ans1,
                "Missing Academic Scholarship cluster section",
            )
            require(
                "### Residential Property Leasing & Real Estate Management" in ans1,
                "Missing Residential Property Leasing cluster section",
            )
            require(
                "### Religious Ministry, Spiritual Teaching & Organizational Stewardship" in ans1,
                "Missing Religious Ministry cluster section",
            )
            require(
                "\n|---|---|---|---|\n" in ans1,
                "Expected intact multi-line Markdown cluster summary table in WHO IS ANGELA DAVIS",
            )
            require("Born as Angela Yvonne Davis" not in ans1, "Pretraining biography backfill leaked")
            require('entity["' not in ans1 and "**:::" not in ans1, "Raw ChatGPT export markers leaked")
            require("zrubrics" not in ans1.lower(), "Distractor Zrubrics leaked into response")
            require(len(ans1) >= 900, f"Expected detailed exhaustive response >= 900 chars, got {len(ans1)}")

            # Query 2: who is michael chen (proves disambiguation is 100% general, zero hardcoded names)
            print("\n[E2E 3b/5] Querying live HTTP /api/query: 'who is michael chen'...")
            st2, q2 = http_json(args.port, "POST", "/api/query", {"prompt": "who is michael chen"})
            require(st2 == 200, f"HTTP {st2} on who is michael chen: {q2}")
            ans2 = q2.get("synthesis_prompt", "")
            print("=== [LIVE /api/query RESPONSE: who is michael chen] ===")
            print(ans2)
            print("=== [END RESPONSE] ===")
            require(
                "### Clinical & Healthcare Records" in ans2
                and "### Software Engineering, Architecture & Cybersecurity" in ans2,
                "General homonym disambiguation failed on Michael Chen",
            )

            # Phase A (Default-Off Forensics Verification)
            print("\n[E2E 4/5] Verifying Forensics is OFF BY DEFAULT (HTTP 403 + disabled query notice)...")
            st_art1, art1 = http_json(args.port, "GET", "/api/artemis/status")
            require(st_art1 == 403, f"Expected HTTP 403 on GET /api/artemis/status when disabled, got {st_art1}: {art1}")
            require(art1.get("forensics_enabled") is False, f"Expected forensics_enabled=False in 403 payload: {art1}")

            st_art2, art2 = http_json(args.port, "GET", "/api/v1/artemis/status")
            require(st_art2 == 403, f"Expected HTTP 403 on GET /api/v1/artemis/status when disabled, got {st_art2}: {art2}")

            st3_off, q3_off = http_json(args.port, "POST", "/api/query", {"prompt": "WHAT PROCESS IS USING DNS TRAFFIC"})
            require(st3_off == 200, f"HTTP {st3_off} on disabled DNS forensic query: {q3_off}")
            ans3_off = q3_off.get("synthesis_prompt", "")
            require(
                "forensics subsystem is currently disabled" in ans3_off.lower(),
                f"Expected disabled forensics notice in default-off query response, got:\n{ans3_off}",
            )
            require(
                "artemis://" not in json.dumps(q3_off.get("citations", [])).lower(),
                "artemis:// citation leaked when forensics was disabled!",
            )

            # Phase B (Explicit User Opt-In Forensics Verification)
            print("\n[E2E 5/5] Opting into Forensics via POST /api/settings and verifying live OS DNS table...")
            st_set, resp_set = http_json(args.port, "POST", "/api/settings", {"forensics_enabled": True})
            require(st_set == 200, f"Failed to enable forensics via POST /api/settings ({st_set}): {resp_set}")

            st_cfg, resp_cfg = http_json(
                args.port,
                "POST",
                "/api/v1/artemis/config",
                {"enabled": True, "local_collection_enabled": True},
            )
            require(st_cfg == 200, f"Failed to enable local collection via /api/v1/artemis/config ({st_cfg}): {resp_cfg}")

            st_art_on, art_on = http_json(args.port, "GET", "/api/artemis/status")
            require(st_art_on == 200, f"Expected HTTP 200 on GET /api/artemis/status after opt-in, got {st_art_on}: {art_on}")

            st3, q3 = http_json(
                args.port,
                "POST",
                "/api/query",
                {"prompt": "WHAT PROCESS IS USING DNS TRAFFIC", "bypass_cache": True},
            )
            require(st3 == 200, f"HTTP {st3} on WHAT PROCESS IS USING DNS TRAFFIC (enabled): {q3}")
            ans3 = q3.get("synthesis_prompt", "")
            print("=== [LIVE /api/query RESPONSE: WHAT PROCESS IS USING DNS TRAFFIC (OPT-IN)] ===")
            print(ans3)
            print("=== [END RESPONSE] ===")
            require(
                "get_dns_query_sysmon" not in ans3 and "TODO: Process the results" not in ans3,
                "Static Python C2_Traffic_Detection_Adequacy distractor leaked into live DNS forensic answer",
            )
            require(
                '"EventID":' not in ans3 and '"telemetry_type":' not in ans3,
                "Raw JSON leaked into formatted DNS forensic response",
            )
            require(
                "codeintegrity" not in ans3.lower(),
                "Unrelated CodeIntegrity events leaked into DNS forensic response",
            )
            require(
                "| # | Process | PID | Protocol / Port |" in ans3
                and "\n|---|---|---|---|---|---|---|\n" in ans3,
                f"Expected structured multi-line Markdown DNS forensic summary table, got:\n{ans3}",
            )
            if sys.platform == "win32":
                require(
                    "svchost.exe" in ans3.lower() or "dnscache" in ans3.lower(),
                    f"Expected Windows svchost.exe / Dnscache attribution in DNS response:\n{ans3}",
                )

            try:
                http_json(args.port, "POST", "/api/shutdown", {}, timeout=5.0)
            except Exception:
                pass
        except Exception:
            try:
                daemon_log_f.flush()
                tail = daemon_log_path.read_text(encoding="utf-8", errors="replace")[-8000:]
                print(f"\n=== [DAEMON LOG TAIL] ===\n{tail}\n=== [END DAEMON LOG TAIL] ===", file=sys.stderr)
            except Exception:
                pass
            raise
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    try:
                        proc.wait(timeout=5)
                    except Exception:
                        pass
            daemon_log_f.close()

    print("\nALL LIVE HTTP /api/query E2E TEST QUERIES (DEFAULT-OFF + OPT-IN FORENSICS) PASSED SUCCESSFULLY!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
