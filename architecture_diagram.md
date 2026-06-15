# SupplyGuard — Architecture Diagram

![SupplyGuard architecture](architecture_diagram.png)

SupplyGuard is an agentic software-supply-chain security tool built on Splunk. It
ingests CI/CD events, then runs an autonomous agent that senses new/changed
dependencies, detects CVEs and typosquatting, triages with a Splunk hosted
security model, and blocks risky builds — emitting NIS2 Article 21 evidence — all
on Splunk infrastructure.

---

## 1. How the application interacts with Splunk

| Splunk capability | Interaction |
|---|---|
| **HTTP Event Collector (HEC)** | `supplyguard/collector.py` POSTs CI/CD supply-chain events (manifests, build logs, decisions) to `index=cicd` — metadata only, secrets env-only. |
| **SPL + Threat Intel** | CVE correlation via `lookup`, install-spike detection via `eventstats`, and NIS2 scan-coverage posture — `spl/queries.spl` (no native `levenshtein`, no `join` anti-pattern). |
| **Splunk MCP Server** | The agent reads `index=cicd` over MCP (JSON-RPC, `initialize` handshake → `tools/call run_splunk_query`) to sense the dependency manifest diff and cross-repo impact — `supplyguard/mcp_client.py`. |
| **Splunk Hosted Models** | `foundation-sec-1.1-8b-instruct` classifies typosquats (malicious? confidence) and writes the NIS2 narrative — `supplyguard/judge.py`. |
| **Dashboard Studio** | `dashboards/supplyguard_security.json` renders live from `index=cicd` — risk profile, detections, agent audit trail. |

## 2. How AI models / agents are integrated

- **Hosted security model (`foundation-sec`):** for any suspicious package, the
  model returns a `{malicious, confidence, reason}` verdict and generates the
  NIS2 Article 21(2)(d) compliance note — `supplyguard/judge.py` (deterministic
  heuristic fallback when offline).
- **The SupplyGuard Agent** (`supplyguard/agent.py`) runs a closed control loop:
  **SENSE** (manifest diff from Splunk via MCP) → **DETECT** (CVE lookup + real
  Levenshtein typosquat detection) → **INVESTIGATE** (hosted-model triage +
  cross-repo impact map) → **DECIDE** (block / open-PR / NIS2-report / flag) →
  **ACT** (execute, with a human-approval gate on a hard build-block) → **LOG**
  (decision written back to `index=cicd` as an audit + NIS2 trail).

## 3. Data flow between services, APIs, and application components

```
CI/CD events (GitHub/GitLab/Jenkins · manifests, lockfiles, build logs)
        │  collector.py → HEC
        ▼
   Splunk  ── index=cicd ── SPL + CVE/threat-intel lookups
        │  ▲                         
        │  │ MCP: run_splunk_query (sense manifest diff + cross-repo impact)
        ▼  │
   SupplyGuard Agent  ──►  Foundation-sec hosted model (triage + NIS2 narrative)
        │
        ├─ DECIDE → ACT:  block_build (human-approval gate) · open PR · NIS2 report · flag
        └─ LOG → HEC → index=cicd  (audit + NIS2 evidence trail)
        ▼
   Dashboard Studio (supplyguard_security)  ·  Build blocked / PR / report
```

**Air-gapped by default:** `SUPPLYGUARD_DEMO=1` runs the full loop offline with
deterministic data (no network). Live: `SUPPLYGUARD_DEMO=0` + Splunk MCP token +
hosted-model endpoint. Secrets come only from the environment and are masked in
logs.
