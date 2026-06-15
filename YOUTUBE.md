# SupplyGuard — YouTube title & description

## Title (pick one)
- `SupplyGuard — Agentic Supply-Chain Security on Splunk (Agentic Ops Hackathon)`
- `SupplyGuard: Splunk caught the backdoor — and blocked the build`

## Description (paste into YouTube)

SupplyGuard ingests CI/CD events into Splunk and runs an autonomous agent that
guards every build — detecting CVEs and typosquatting, triaging with a Splunk
hosted security model (foundation-sec), and blocking risky builds behind a
human-approval gate, with an NIS2 Article 21 evidence trail.

Built for the Splunk Agentic Ops Hackathon — Security.

Supply-chain attacks (XZ Utils, SolarWinds, Log4Shell) all enter through the
build pipeline: a dependency that wasn't there before, or one that silently
changed. Most teams watch network traffic; almost none watch the pipeline.
SupplyGuard makes Splunk watch it in real time — and act. In the demo it catches
build payment-service#1247, which added `reqursts` (one edit from `requests`) and
log4j-core 2.14 (CVE-2021-44228, CVSS 10), maps 3 affected repos, and blocks the
build.

⏱️ Chapters
0:00  The problem — attacks enter the build pipeline
0:15  CI/CD events in Splunk (index=cicd via HEC)
0:45  The agent acts (running: python demo.py --auto) — blocks the build
1:30  Proof in Splunk — live Dashboard Studio (real index=cicd data)
2:05  Capabilities + NIS2 compliance — architecture
2:35  Close

🔧 How Splunk is used
• Splunk MCP Server (Splunkbase App 7931) — agent reads index=cicd via run_splunk_query (SPL, initialize handshake)
• Splunk hosted model (foundation-sec-1.1-8b-instruct) — threat triage AND NIS2 narrative
• HEC + SPL + Dashboard Studio — ingestion, CVE/typosquat detection, NIS2 posture, verified live in Splunk Enterprise
• Real Levenshtein typosquatting (no fabricated SPL), lookup-based CVE correlation (no join anti-pattern)

✅ Runs end-to-end offline (SUPPLYGUARD_DEMO=1), human-approval gate on hard build-blocks, MIT licensed, real tool names only.

Code: https://github.com/manojmallick/supplyguard

#Splunk #MCP #ModelContextProtocol #AgenticOps #Security #SupplyChainSecurity #CVE #Typosquatting #NIS2 #FoundationSec #DevSecOps #AI
