# © 2026 LearnHubPlay BV. SupplyGuard.
"""Remediation actions the agent can take on a risky build.

Responsible agentic ops: a hard build-block is impactful, so `block_build`
carries `requires_approval=True`. Running non-autonomously stages it for a human;
only `--auto` lets the agent block on its own. Non-destructive actions
(open PR, generate report, flag) execute immediately.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ActionPlan:
    kind: str                    # block_build | open_remediation_pr | generate_nis2 | flag | allow
    target: str                  # build id
    rationale: str
    requires_approval: bool = False
    params: dict = field(default_factory=dict)


@dataclass
class ActionResult:
    kind: str
    status: str                  # executed | staged_for_approval | failed
    detail: str


class ActionExecutor:
    """Executes remediation. In demo_mode it simulates side effects."""

    def __init__(self, config):
        self.config = config

    def execute(self, plan: ActionPlan) -> ActionResult:
        if plan.requires_approval and not self.config.autonomous:
            return ActionResult(plan.kind, "staged_for_approval",
                                f"Awaiting human approval to {plan.kind} on {plan.target}")
        handler = getattr(self, f"_do_{plan.kind}", None)
        if handler is None:
            return ActionResult(plan.kind, "failed", f"Unknown action: {plan.kind}")
        return handler(plan)

    def _do_block_build(self, plan: ActionPlan) -> ActionResult:
        pkgs = ", ".join(plan.params.get("packages", []))
        return ActionResult("block_build", "executed",
                            f"Build {plan.target} BLOCKED. Offending: {pkgs}. Pipeline halted.")

    def _do_open_remediation_pr(self, plan: ActionPlan) -> ActionResult:
        fix = plan.params.get("fix", "pin/upgrade affected dependency")
        return ActionResult("open_remediation_pr", "executed",
                            f"Opened PR on {plan.target}: {fix}.")

    def _do_generate_nis2(self, plan: ActionPlan) -> ActionResult:
        return ActionResult("generate_nis2", "executed",
                            "NIS2 Article 21 supply-chain report generated and attached.")

    def _do_flag(self, plan: ActionPlan) -> ActionResult:
        return ActionResult("flag", "executed",
                            f"Flagged {plan.target} for review (non-blocking).")

    def _do_allow(self, plan: ActionPlan) -> ActionResult:
        return ActionResult("allow", "executed", f"Build {plan.target} cleared.")
