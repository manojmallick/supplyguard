# © 2026 Manoj Mallick. SupplyGuard.
"""Splunk MCP Server client.

The agent *reads* CI/CD and threat-intel data from Splunk through the Splunk MCP
Server (Model Context Protocol over streamable HTTP). This is what makes
SupplyGuard agentic rather than a one-shot CI script: it senses the dependency
manifest diff and cross-repo impact from Splunk, reasons over it, and acts.

In demo_mode the client returns a deterministic synthetic build so the whole
loop runs offline (CLAUDE.md air-gapped rule).
"""

from __future__ import annotations

import json

from .analyzer import Dependency
from .config import Config


class SplunkMCPClient:
    """Talks to the Splunk MCP Server. Token-based auth, with the MCP handshake."""

    PROTOCOL_VERSION = "2025-06-18"

    def __init__(self, config: Config):
        self.config = config
        self._rpc_id = 0
        self._session_id: str | None = None
        self._session_ready = False

    # ── high-level operations the agent uses ─────────────────────────────────
    def manifest_diff(self, build_id: str) -> list[Dependency]:
        """New/changed dependencies for a build, sensed from index=cicd via MCP."""
        spl = (
            f'index=cicd sourcetype=package_manifest build_id="{build_id}" '
            '| eval status=if(isnull(prev_version),"NEW","CHANGED") '
            "| table package version ecosystem status"
        )
        rows = self._run_splunk_query(spl)
        return [Dependency(r["package"], r["version"],
                           r.get("ecosystem", "pypi"), r.get("status") == "NEW")
                for r in rows]

    def repos_using(self, package: str) -> list[dict]:
        """Cross-repo impact: which repositories depend on this package (direct/transitive)."""
        spl = (
            f'index=cicd sourcetype=package_manifest package="{package}" '
            "| stats values(dependency_type) as types by repository "
            "| table repository types"
        )
        return self._run_splunk_query(spl)

    # ── MCP / JSON-RPC transport (handshake-aware) ───────────────────────────
    def _run_splunk_query(self, spl: str) -> list[dict]:
        if self.config.demo_mode:
            return self._demo_rows(spl)
        return self._call_tool("run_splunk_query", {"query": spl, "earliest": "-24h"})

    def _ensure_session(self) -> None:
        """MCP `initialize` handshake once: streamable-HTTP servers require it
        (server returns Mcp-Session-Id) before any tools/call."""
        if self._session_ready:
            return
        init = self._post({
            "jsonrpc": "2.0", "id": self._next_id(), "method": "initialize",
            "params": {"protocolVersion": self.PROTOCOL_VERSION, "capabilities": {},
                       "clientInfo": {"name": "supplyguard-agent", "version": "1.0.0"}},
        })
        self._session_id = init.headers.get("Mcp-Session-Id") or self._session_id
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"},
                   expect_response=False)
        self._session_ready = True

    def _call_tool(self, tool: str, arguments: dict) -> list[dict]:
        self._ensure_session()
        resp = self._post({
            "jsonrpc": "2.0", "id": self._next_id(), "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        })
        result = self._decode(resp).get("result", {})
        content = result.get("content", [])
        if content and content[0].get("type") == "text":
            return json.loads(content[0]["text"])
        return result.get("rows", [])

    def _post(self, body: dict, expect_response: bool = True):
        import requests  # local import: demo_mode needs no network deps

        headers = {
            "Authorization": f"Bearer {self.config.mcp_token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": self.PROTOCOL_VERSION,
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        resp = requests.post(self.config.mcp_url, headers=headers, json=body, timeout=15)
        resp.raise_for_status()
        return resp

    @staticmethod
    def _decode(resp) -> dict:
        if "text/event-stream" in resp.headers.get("Content-Type", ""):
            for line in reversed(resp.text.splitlines()):
                if line.startswith("data:"):
                    return json.loads(line[5:].strip())
            return {}
        return resp.json() if resp.content else {}

    def _next_id(self) -> int:
        self._rpc_id += 1
        return self._rpc_id

    # ── deterministic demo data (a build that adds a typosquat + a critical CVE) ─
    @staticmethod
    def _demo_rows(spl: str) -> list[dict]:
        if "stats values(dependency_type)" in spl:
            return [
                {"repository": "payment-service", "types": "direct"},
                {"repository": "user-service", "types": "direct"},
                {"repository": "analytics-service", "types": "transitive"},
            ]
        # manifest diff for build #1247
        return [
            {"package": "reqursts", "version": "2.1.3", "ecosystem": "pypi", "status": "NEW"},
            {"package": "log4j-core", "version": "2.14.0", "ecosystem": "maven", "status": "CHANGED"},
            {"package": "lodash", "version": "4.17.19", "ecosystem": "npm", "status": "CHANGED"},
            {"package": "react", "version": "18.3.1", "ecosystem": "npm", "status": "NEW"},
        ]
