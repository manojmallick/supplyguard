# © 2026 Manoj Mallick. SupplyGuard.
"""Seed index=cicd via HEC so the SupplyGuard dashboard renders on live Splunk.

Ships three sourcetypes:
  • package_manifest     — 7 days of dependency scans across repos (risk profile,
                           CVE count, NIS2 scan coverage)
  • supply_chain_decision — the agent's REAL block decision (run live, in demo
                           mode for the read path) + a few historical decisions
  • supply_chain_detection — flat per-finding rows for the Recent Detections table

Secrets come only from the environment:
    SPLUNK_HEC_URL   (default https://localhost:8088/services/collector/event)
    SPLUNK_HEC_TOKEN (required)
"""

from __future__ import annotations

import json
import os
import sys
import time
import pathlib
import urllib3
import requests

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from supplyguard import Config, SupplyGuardAgent, SupplyGuardCollector

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEC_URL = os.environ.get("SPLUNK_HEC_URL", "https://localhost:8088/services/collector/event")
HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN", "")
INDEX = "cicd"
DAY = 86400
REPOS = ["payment-service", "user-service", "api-gateway", "frontend", "auth-service"]

# (clean, medium, critical) dependency counts per day, oldest → today.
# Improving posture across the week, then today's risky build spikes critical.
DIST = [(18, 4, 2), (20, 3, 1), (22, 2, 1), (24, 2, 0), (26, 1, 0), (28, 1, 0), (24, 2, 1)]


def _events_to_hec(events: list[dict]) -> str:
    return "\n".join(json.dumps(e) for e in events)


def _post(events: list[dict]) -> None:
    body = _events_to_hec(events)
    r = requests.post(HEC_URL, headers={"Authorization": f"Splunk {HEC_TOKEN}"},
                      data=body, verify=False, timeout=30)
    r.raise_for_status()


def _ev(ts: float, sourcetype: str, event: dict) -> dict:
    return {"time": ts, "source": "supplyguard", "sourcetype": sourcetype,
            "index": INDEX, "event": event}


def seed_manifests(now: float) -> int:
    events, cve_seq = [], 0
    for day, (clean, medium, critical) in enumerate(DIST):
        ts = now - (len(DIST) - 1 - day) * DAY - 7200  # 2h before "now" each day (always past)
        for repo_i in range(clean):
            repo = REPOS[repo_i % len(REPOS)]
            events.append(_ev(ts, "package_manifest", {
                "build_id": f"{repo}#{1200 + day * 10 + repo_i}", "repository": repo,
                "package": f"pkg-{repo_i}", "version": "1.0.0", "ecosystem": "pypi",
                "max_cvss": 0, "is_scanned": "true", "dependency_type": "direct"}))
        for j in range(medium):
            cve_seq += 1
            repo = REPOS[j % len(REPOS)]
            events.append(_ev(ts, "package_manifest", {
                "build_id": f"{repo}#{1200 + day * 10 + 90 + j}", "repository": repo,
                "package": "lodash", "version": "4.17.19", "ecosystem": "npm",
                "max_cvss": 7.4, "cve_id": f"CVE-2020-{8200 + cve_seq}",
                "is_scanned": "true", "dependency_type": "transitive"}))
        for k in range(critical):
            cve_seq += 1
            repo = REPOS[k % len(REPOS)]
            events.append(_ev(ts, "package_manifest", {
                "build_id": f"{repo}#{1200 + day * 10 + 95 + k}", "repository": repo,
                "package": "log4j-core", "version": "2.14.0", "ecosystem": "maven",
                "max_cvss": 10.0, "cve_id": "CVE-2021-44228",
                "is_scanned": "true" if (day + k) % 12 else "false",
                "dependency_type": "direct"}))
    _post(events)
    return len(events)


def seed_decisions(now: float) -> dict:
    # The REAL agent decision (read path in demo mode; shipped to live Splunk).
    agent = SupplyGuardAgent(Config(demo_mode=True, autonomous=True),
                             collector=SupplyGuardCollector(Config(demo_mode=True)))
    decision = agent.run_cycle("payment-service#1247")
    today = _ev(now - 600, "supply_chain_decision", decision.as_event())

    historical = [
        _ev(now - 1 * DAY, "supply_chain_decision", {
            "status": "flagged", "build_id": "api-gateway#1239",
            "action": {"kind": "open_remediation_pr"},
            "result": {"status": "executed", "detail": "Opened PR: upgrade lodash past CVE-2020-8203."},
            "nis2_note": "High-severity CVE flagged; remediation PR raised."}),
        _ev(now - 3 * DAY, "supply_chain_decision", {
            "status": "flagged", "build_id": "frontend#1231",
            "action": {"kind": "flag"},
            "result": {"status": "executed", "detail": "Flagged frontend#1231 for review (non-blocking)."},
            "nis2_note": "Medium finding; flagged for review."}),
        _ev(now - 5 * DAY, "supply_chain_decision", {
            "status": "clean", "build_id": "user-service#1224",
            "action": {"kind": "allow"},
            "result": {"status": "executed", "detail": "Build user-service#1224 cleared."},
            "nis2_note": "No risk findings."}),
    ]
    _post([today, *historical])
    return decision.as_event()


def seed_detections(now: float, decision_event: dict) -> int:
    rows = []
    sev = {"CRITICAL": "BLOCKED", "HIGH": "BLOCKED", "MEDIUM": "FLAGGED"}
    for f in decision_event.get("findings", []):
        rows.append(_ev(now - 600, "supply_chain_detection", {
            "build_id": decision_event.get("build_id", "payment-service#1247"),
            "package": f.get("package"),
            "type": f.get("kind"),
            "severity": f.get("severity"),
            "action": sev.get(f.get("severity"), "FLAGGED")}))
    # a couple of earlier-today detections for table depth
    rows += [
        _ev(now - 5400, "supply_chain_detection", {
            "build_id": "api-gateway#1239", "package": "lodash", "type": "cve",
            "severity": "MEDIUM", "action": "FLAGGED"}),
        _ev(now - 9000, "supply_chain_detection", {
            "build_id": "frontend#1231", "package": "left-pad", "type": "typosquat",
            "severity": "MEDIUM", "action": "FLAGGED"}),
    ]
    _post(rows)
    return len(rows)


def main() -> None:
    if not HEC_TOKEN:
        sys.exit("SPLUNK_HEC_TOKEN is not set — run scripts/setup_splunk.py first.")
    now = time.time()
    print(f"Seeding index={INDEX} via HEC ...")
    m = seed_manifests(now)
    print(f"  [+] {m} package_manifest events (7 days, {len(REPOS)} repos)")
    dec = seed_decisions(now)
    print(f"  [+] supply_chain_decision events (1 live block + 3 historical)")
    d = seed_detections(now, dec)
    print(f"  [+] {d} supply_chain_detection events")
    print(f"Done. Open the SupplyGuard dashboard — set time range to 'Last 7 days'.")


if __name__ == "__main__":
    main()
