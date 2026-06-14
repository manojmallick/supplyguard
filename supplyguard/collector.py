# © 2026 LearnHubPlay BV. SupplyGuard.
"""Instrument CI/CD supply-chain events into Splunk via HEC (privacy-safe).

Logs metadata only — package names, versions, hashes, risk decisions. Never raw
source or secrets. In demo_mode events are buffered in-memory (no network).
"""

from __future__ import annotations

import time


class SupplyGuardCollector:
    """Ships supply-chain + agent-decision events to Splunk HEC."""

    def __init__(self, config, app_name: str = "supplyguard"):
        self.config = config
        self.app_name = app_name
        self.events: list[dict] = []

    def log_event(self, sourcetype: str, event: dict) -> None:
        payload = {"time": time.time(), "source": self.app_name,
                   "sourcetype": sourcetype, "index": self.config.index, "event": event}
        self.events.append(payload)
        if self.config.demo_mode:
            return
        import requests  # local import: demo_mode needs no network deps
        requests.post(self.config.hec_url,
                      headers={"Authorization": f"Splunk {self.config.hec_token}"},
                      json=payload, timeout=5)

    def log_agent_decision(self, decision: dict) -> None:
        self.log_event("supply_chain_decision", decision)
