# © 2026 LearnHubPlay BV. SupplyGuard.
"""The SupplyGuard Agent — the agentic core.

This is what turns SupplyGuard from a one-shot CI script into Agentic Ops. On
each build the agent runs a closed loop entirely on Splunk infrastructure:

    SENSE      pull the dependency manifest diff from Splunk via the MCP Server
    DETECT     CVE + typosquatting analysis on new/changed packages (deterministic)
    INVESTIGATE classify suspicious packages + map cross-repo impact via a hosted model
    DECIDE     block_build / open_remediation_pr / generate_nis2 / flag / allow
    ACT        execute — with a human-approval gate for a hard build-block
    LOG        write the decision + evidence back to Splunk for audit / NIS2

Call run_cycle(build_id) from a CI step or a Splunk modular input.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict

from .config import Config
from .mcp_client import SplunkMCPClient
from .analyzer import SupplyChainAnalyzer, Finding
from .judge import FoundationSecJudge
from .actions import ActionExecutor, ActionPlan
from .collector import SupplyGuardCollector


@dataclass
class AgentDecision:
    status: str                         # clean | build_blocked | awaiting_approval | flagged
    build_id: str = ""
    findings: list[dict] = field(default_factory=list)
    impact: list[dict] = field(default_factory=list)
    action: dict | None = None
    result: dict | None = None
    nis2_note: str | None = None
    narrative: list[str] = field(default_factory=list)

    def as_event(self) -> dict:
        d = asdict(self)
        d["component"] = "supplyguard_agent"
        return d


class SupplyGuardAgent:
    def __init__(self, config: Config, mcp: SplunkMCPClient | None = None,
                 analyzer: SupplyChainAnalyzer | None = None,
                 judge: FoundationSecJudge | None = None,
                 actions: ActionExecutor | None = None,
                 collector: SupplyGuardCollector | None = None):
        self.config = config
        self.mcp = mcp or SplunkMCPClient(config)
        self.analyzer = analyzer or SupplyChainAnalyzer(config)
        self.judge = judge or FoundationSecJudge(config)
        self.actions = actions or ActionExecutor(config)
        self.collector = collector

    def run_cycle(self, build_id: str) -> AgentDecision:
        log: list[str] = []

        # 1. SENSE — read the manifest diff from Splunk through the MCP Server.
        deps = self.mcp.manifest_diff(build_id)
        log.append(f"SENSE  · pulled {len(deps)} new/changed deps for {build_id} via MCP")

        # 2. DETECT — CVE + typosquatting (deterministic, real edit distance).
        findings = self.analyzer.analyze(deps)
        if not findings:
            log.append("DETECT · no CVEs or typosquats — build clean")
            return self._finish(AgentDecision(status="clean", build_id=build_id,
                                              narrative=log), ActionPlan(
                "allow", build_id, "No risk findings."))
        log.append("DETECT · " + ", ".join(
            f"{f.package}[{f.kind}:{f.severity}]" for f in findings))

        # 3. INVESTIGATE — classify typosquats + map cross-repo impact (hosted model + MCP).
        worst = findings[0]
        for f in findings:
            if f.kind == "typosquat":
                verdict = self.judge.classify_typosquat(f.package, f.similar_to, f.edit_distance)
                f.detail += f" | Foundation-sec: {verdict['confidence']} ({verdict['reason']})"
                if verdict["malicious"] and verdict["confidence"] == "HIGH":
                    worst = f
        impact = self.mcp.repos_using(worst.package)
        log.append(f"INVESTIGATE · {self.config.hosted_model} triaged findings; "
                   f"{worst.package} impacts {len(impact)} repos")

        # 4. DECIDE — translate the worst finding into an action plan.
        plan = self._decide(build_id, findings, worst)
        log.append(f"DECIDE · {plan.kind} (approval_required={plan.requires_approval})")

        # 5. ACT — execute with the human-approval gate.
        result = self.actions.execute(plan)
        log.append(f"ACT    · {result.status}: {result.detail}")

        # NIS2 narrative for the compliance report.
        nis2 = self.judge.nis2_narrative(
            f"Build {build_id}", [f.as_dict() for f in findings], impact)

        decision = AgentDecision(
            status="awaiting_approval" if result.status == "staged_for_approval"
            else ("build_blocked" if plan.kind == "block_build" else "flagged"),
            build_id=build_id,
            findings=[f.as_dict() for f in findings],
            impact=impact,
            action={"kind": plan.kind, "rationale": plan.rationale, "params": plan.params},
            result={"status": result.status, "detail": result.detail},
            nis2_note=nis2,
            narrative=log)
        return self._finish(decision, plan)

    # ── decision logic ───────────────────────────────────────────────────────
    def _decide(self, build_id: str, findings: list[Finding], worst: Finding) -> ActionPlan:
        critical = [f for f in findings if f.cvss >= self.config.cvss_block]
        hi_typo = [f for f in findings if f.kind == "typosquat" and f.severity == "HIGH"]
        if critical or hi_typo:
            offending = sorted({f.package for f in critical + hi_typo})
            return ActionPlan(
                kind="block_build", target=build_id, requires_approval=True,
                rationale=f"Critical CVE and/or high-confidence typosquat: {', '.join(offending)}.",
                params={"packages": offending})
        flag_worthy = [f for f in findings if f.cvss >= self.config.cvss_flag]
        if flag_worthy:
            return ActionPlan(
                kind="open_remediation_pr", target=build_id, requires_approval=False,
                rationale=f"High-severity CVE in {worst.package} — propose upgrade.",
                params={"fix": f"upgrade {worst.package} past {worst.cve_id}"})
        return ActionPlan(kind="flag", target=build_id, requires_approval=False,
                          rationale="Low/medium findings — flag for review.")

    def _finish(self, decision: AgentDecision, plan: ActionPlan) -> AgentDecision:
        # 6. LOG — write the full decision back to Splunk for audit / NIS2 trail.
        if self.collector is not None:
            self.collector.log_agent_decision(decision.as_event())
            decision.narrative.append(
                "LOG    · decision written to index=cicd (audit + NIS2 trail)")
        return decision
