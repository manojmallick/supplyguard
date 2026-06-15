# SupplyGuard — UI Design Prototype

High-fidelity, interactive HTML prototype of the SupplyGuard product UI (Stitch
design system, Tailwind + Material Symbols). These three screens define the
target SOC experience; the **functional** equivalent runs live on Splunk
Dashboard Studio (see [`../dashboards/`](../dashboards/)).

| Screen | File | Live Splunk dashboard |
|---|---|---|
| Supply-Chain Security Dashboard | [dashboard.html](dashboard.html) | `supplyguard_security` |
| CVE Investigation Detail | [cve_investigation.html](cve_investigation.html) | (drill-down from detections) |
| NIS2 Article 21 Compliance Report | [nis2_report.html](nis2_report.html) | (NIS2 posture panels) |

The three screens are cross-linked — the left sidebar (Dashboard · CVE
Investigations · Compliance Reports) navigates between them. Open
[dashboard.html](dashboard.html) (or `index.html`) to start.

**Static captures** for the submission/deck: `dashboard.png`,
`cve_investigation.png`, `nis2_report.png`.

**Design system:** see [DESIGN.md](DESIGN.md) — a SOC-grade "glass-and-wire"
dark theme (Splunk green `#65E075` for health/primary, isolated critical/high
severity colors, tonal-layer elevation with 1px blueprint borders), Inter for UI
text + JetBrains Mono for technical evidence (CVE IDs, SHA-256 hashes, SBOM).

> Prototype data is illustrative; the live Splunk dashboard renders the same
> views from real `index=cicd` events emitted by the SupplyGuard agent.
