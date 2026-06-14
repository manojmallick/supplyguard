# © 2026 LearnHubPlay BV. SupplyGuard.
"""Deterministic supply-chain analysis: CVE lookup + typosquatting.

This is the *non-AI* evidence layer. It runs in pure Python with no native-SPL
dependency — fixing the original plan's two correctness bugs:

  • `levenshtein()` is NOT a native SPL function. Edit distance is computed here,
    in Python, against a trusted-package set — not faked in SPL.
  • The original SPL used `join` (a subsearch anti-pattern). Retrieval now happens
    via `stats`/`lookup`-style aggregation; correlation happens in the agent.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# Top packages most often typosquatted (subset; load from a lookup in production).
TRUSTED_PACKAGES = [
    "requests", "urllib3", "numpy", "pandas", "flask", "django", "lodash",
    "react", "express", "axios", "log4j-core", "jackson-databind", "spring-core",
]


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str = "pypi"      # pypi | npm | maven
    is_new: bool = True


@dataclass
class Finding:
    package: str
    version: str
    kind: str                    # cve | typosquat
    severity: str                # CRITICAL | HIGH | MEDIUM | LOW
    detail: str
    cvss: float = 0.0
    cve_id: str | None = None
    similar_to: str | None = None
    edit_distance: int | None = None

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}


def levenshtein(a: str, b: str) -> int:
    """Classic edit distance — what the SPL `levenshtein()` pretended to be."""
    if a == b:
        return 0
    if not a or not b:
        return len(a) or len(b)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _severity_from_cvss(cvss: float) -> str:
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    return "LOW"


class SupplyChainAnalyzer:
    """Scores new/changed dependencies for CVEs and typosquatting."""

    def __init__(self, config, trusted: list[str] | None = None,
                 cve_db: dict[str, list[dict]] | None = None):
        self.config = config
        self.trusted = trusted or TRUSTED_PACKAGES
        # name -> [{cve_id, cvss, summary}]. In production: NVD/OSV via threat intel.
        self.cve_db = cve_db if cve_db is not None else _DEMO_CVE_DB

    def analyze(self, deps: list[Dependency]) -> list[Finding]:
        findings: list[Finding] = []
        for dep in deps:
            findings.extend(self._check_cves(dep))
            typo = self._check_typosquat(dep)
            if typo:
                findings.append(typo)
        # Worst first.
        return sorted(findings, key=lambda f: f.cvss, reverse=True)

    def _check_cves(self, dep: Dependency) -> list[Finding]:
        out = []
        for entry in self.cve_db.get(dep.name, []):
            cvss = float(entry["cvss"])
            out.append(Finding(
                package=dep.name, version=dep.version, kind="cve",
                severity=_severity_from_cvss(cvss), cvss=cvss,
                cve_id=entry["cve_id"], detail=entry["summary"]))
        return out

    def _check_typosquat(self, dep: Dependency) -> Finding | None:
        if dep.name in self.trusted:
            return None
        best, best_dist = None, 99
        for t in self.trusted:
            d = levenshtein(dep.name, t)
            if 0 < d < best_dist:
                best, best_dist = t, d
        if best is not None and best_dist <= self.config.typosquat_max_distance:
            sev = "HIGH" if best_dist == 1 else "MEDIUM"
            return Finding(
                package=dep.name, version=dep.version, kind="typosquat",
                severity=sev, similar_to=best, edit_distance=best_dist,
                detail=f"'{dep.name}' is edit-distance {best_dist} from trusted '{best}'")
        return None


# Synthetic CVE data for the offline demo (well-known public CVEs).
_DEMO_CVE_DB: dict[str, list[dict]] = {
    "log4j-core": [{"cve_id": "CVE-2021-44228", "cvss": 10.0,
                    "summary": "Log4Shell: JNDI lookup enables remote code execution (2.0–2.14.x)."}],
    "lodash": [{"cve_id": "CVE-2020-8203", "cvss": 7.4,
                "summary": "Prototype pollution in lodash < 4.17.20."}],
}
