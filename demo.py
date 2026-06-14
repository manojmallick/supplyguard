# © 2026 LearnHubPlay BV. SupplyGuard — runnable end-to-end demo.
"""Run the full SupplyGuard agentic loop with zero network access.

    python demo.py            # human-approval gate ON  → block staged
    python demo.py --auto     # autonomous             → build blocked

The agent senses a build (#1247) that added a typosquat ('reqursts' ~ 'requests')
and a critical-CVE dependency (log4j-core 2.14.0), triages with a Splunk hosted
security model, maps cross-repo impact via the MCP Server, and blocks the build.
No Splunk instance or API key required (SUPPLYGUARD_DEMO=1 is the default).
"""

from __future__ import annotations

import sys

from supplyguard import Config, SupplyGuardAgent, SupplyGuardCollector


def banner(text: str) -> None:
    print(f"\n\033[1;32m{'─' * 66}\n{text}\n{'─' * 66}\033[0m")


def main() -> None:
    autonomous = "--auto" in sys.argv
    config = Config(demo_mode=True, autonomous=autonomous)
    collector = SupplyGuardCollector(config)

    banner(f"SupplyGuard Agent · CI/CD supply-chain guard  (autonomous={autonomous})")
    agent = SupplyGuardAgent(config, collector=collector)
    decision = agent.run_cycle(build_id="payment-service#1247")

    for line in decision.narrative:
        print(f"  {line}")

    banner(f"RESULT · status = {decision.status}")
    print(f"  findings    : {len(decision.findings)} "
          f"({sum(1 for f in decision.findings if f['kind']=='cve')} CVE, "
          f"{sum(1 for f in decision.findings if f['kind']=='typosquat')} typosquat)")
    if decision.action:
        print(f"  action      : {decision.action['kind']}")
        print(f"  rationale   : {decision.action['rationale']}")
        print(f"  result      : {decision.result['detail']}")
    if decision.nis2_note:
        print(f"\n  NIS2 note   : {decision.nis2_note}")
    if decision.status == "awaiting_approval":
        print("\n  ▶ Human-approval gate held the block. Re-run with --auto to let the "
              "agent block the build autonomously.")


if __name__ == "__main__":
    main()
