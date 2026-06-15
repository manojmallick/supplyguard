# © 2026 Manoj Mallick. SupplyGuard.
"""Configuration. All secrets come from the environment — never hardcoded."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

# Risk policy thresholds.
CVSS_BLOCK = 9.0          # critical CVE → block build
CVSS_FLAG = 7.0           # high CVE → flag + open remediation PR
TYPOSQUAT_MAX_DISTANCE = 2  # edit distance ≤ 2 from a trusted package = suspicious


@dataclass
class Config:
    """Runtime config. `demo_mode` makes everything runnable with zero network."""

    # Splunk HEC (ingestion of CI/CD supply-chain events).
    hec_url: str = field(default_factory=lambda: os.environ.get(
        "SPLUNK_HEC_URL", "https://localhost:8088/services/collector/event"))
    hec_token: str = field(default_factory=lambda: os.environ.get("SPLUNK_HEC_TOKEN", ""))
    index: str = "cicd"

    # Splunk MCP Server (the agent reads CI/CD + threat-intel data through this).
    mcp_url: str = field(default_factory=lambda: os.environ.get(
        "SPLUNK_MCP_URL", "https://localhost:8089/services/mcp"))
    mcp_token: str = field(default_factory=lambda: os.environ.get("SPLUNK_MCP_TOKEN", ""))

    # Splunk hosted model — Foundation-sec is purpose-built for security triage.
    hosted_model: str = field(default_factory=lambda: os.environ.get(
        "SPLUNK_HOSTED_MODEL", "foundation-sec-1.1-8b-instruct"))
    hosted_model_url: str = field(default_factory=lambda: os.environ.get(
        "SPLUNK_HOSTED_MODEL_URL", "https://localhost:8089/services/ml/v1/chat/completions"))

    # Agent behaviour.
    autonomous: bool = False        # if False, a hard build-block needs human approval
    cvss_block: float = CVSS_BLOCK
    cvss_flag: float = CVSS_FLAG
    typosquat_max_distance: int = TYPOSQUAT_MAX_DISTANCE

    # Demo mode: no network calls, deterministic synthetic data. CLAUDE.md Rule 5.
    demo_mode: bool = field(default_factory=lambda: os.environ.get(
        "SUPPLYGUARD_DEMO", "1") == "1")

    def mask_token(self, token: str) -> str:
        """Mask secrets for logs/CLI. Never print a raw token."""
        if not token:
            return "<unset>"
        return token[:4] + "***" if len(token) > 4 else "***"
