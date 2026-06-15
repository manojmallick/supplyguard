# SupplyGuard — Final Demo Script (≤ 3:00)

Target: **2:45** (judges stop at 3:00). Narration is word-for-word; "SCREEN"
tells you what to show. Speak calmly — the visuals carry it.

> Rules this satisfies: shows the project **running**, shows **AI usage**
> (hosted-model triage + agent decision), states the **problem**, shows the
> **value** (a malicious build blocked before it ships).

---

## ⏱️ Beat-by-beat

### [0:00–0:15] HOOK
**SCREEN:** `gallery/01_hero.png` (or the live Splunk dashboard with the red risk).
**SAY:**
> "Your CI/CD pipeline added a backdoor last Tuesday. XZ Utils, SolarWinds,
> Log4Shell — they all entered the same way: a dependency that wasn't there
> before, or one that silently changed. Security teams watch network traffic.
> Almost nobody watches the build pipeline. SupplyGuard does — on Splunk."

### [0:15–0:45] THE PROBLEM → INGESTION
**SCREEN:** Splunk search — run:
`index=cicd sourcetype=package_manifest | head 20`
**SAY:**
> "Every CI/CD build streams its dependency manifest into Splunk through HEC —
> packages, versions, scan status. This is real data in a real Splunk index.
> Splunk already watches infrastructure at scale; SupplyGuard points that same
> machinery at the software supply chain."

### [0:45–1:30] THE AGENT ACTS  ← the core; show AI
**SCREEN:** Terminal — run `python3 demo.py --auto`. Let the loop print live.
**SAY:**
> "But SupplyGuard doesn't just watch — it acts. Watch the agent guard a build.
> It SENSES the dependency diff from Splunk over the MCP Server, and DETECTS two
> threats: log4j-core 2.14 — a critical CVE — and 'reqursts', one character from
> 'requests', a textbook typosquat. A Splunk hosted security model, foundation-sec,
> triages it as a high-confidence attack and maps three affected repos. Then it
> DECIDES and ACTS: it blocks the build — behind a human-approval gate — and
> writes its decision back to Splunk as an NIS2 evidence trail."

### [1:30–2:05] PROOF IN SPLUNK
**SCREEN:** Open the **supplyguard_security** dashboard. Point at **Builds Blocked: 1**,
**CVEs: 3**, **NIS2: 100%**, the **7-day risk profile** (improving, then today's spike),
and the **Agent Decision Audit Trail**. Then run:
`index=cicd sourcetype=supply_chain_decision action.kind=block_build | table _time build_id action.kind result.detail nis2_note`
**SAY:**
> "Here it is in Splunk Dashboard Studio — builds blocked, CVEs detected, NIS2
> compliance, a seven-day risk profile improving until today's caught spike. And
> this — the agent's own decision, queried straight back out of Splunk: build
> 1247 blocked, offending packages named, NIS2 note attached. The agent shows
> its work."

### [2:05–2:35] CAPABILITIES + COMPLIANCE
**SCREEN:** Architecture (`architecture_diagram.png`) or the CVE detail design screen.
**SAY:**
> "SupplyGuard uses Splunk end to end: HEC and SPL for ingestion and detection —
> CVE correlation by lookup, typosquatting by real edit distance — the Splunk MCP
> Server so the agent reads Splunk securely, and a Splunk hosted security model
> for triage and the NIS2 narrative. The build pipeline is a net-new Splunk data
> source, with a net-new compliance angle: NIS2 Article 21 supply-chain security."

### [2:35–2:50] CLOSE
**SCREEN:** `gallery/01_hero.png` again, or the repo page.
**SAY:**
> "Hard build-blocks wait for one human approval, and every decision is audited in
> Splunk — responsible autonomy. SupplyGuard: your supply chain, secured. Every
> commit, every dependency, every build — in Splunk. Thank you."

---

## What to have ready (pre-roll, off camera)
1. Splunk logged in (manoj / manoj028), **fresh data seeded** — run once before recording:
   `SPLUNK_USER=manoj SPLUNK_PASSWORD=manoj028 ./run_live.sh`
2. Browser tabs pre-opened:
   - `http://localhost:8989/en-US/app/search/supplyguard_security` (time range **Last 7 days**)
   - a Search tab ready to paste the two SPL queries above
3. A terminal in the repo root, large font, ready to run `python3 demo.py --auto`.

## Recording tips
- **Tool:** QuickTime (File → New Screen Recording) or Loom. 1080p minimum.
- **Font:** bump terminal + browser zoom so text reads at small size.
- **Audio:** quiet room, simple mic. No copyrighted music (rules). Silence or a royalty-free bed only.
- **No third-party logos** beyond Splunk (their hackathon) — Splunk UI is fine.
- Show the **mouse moving/clicking** so it's clearly live, not slides.
- Keep total **under 2:50**.

## After recording
1. Upload to **YouTube or Vimeo** (Unlisted is allowed).
2. Paste the title + description from `YOUTUBE.md`.
3. Add the video link to the Devpost submission + as a second "Try it out" link.
4. Final check: video is **< 3:00**, public/unlisted, shows **AI usage** + the **build block**.
