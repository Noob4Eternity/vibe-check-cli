"""SAST analyzer (P2) — Bandit + Semgrep integration."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from typing import List, Tuple

from vibe_check.analyzers.base import BaseAnalyzer
from vibe_check.models.finding import Category, Finding, Severity

logger = logging.getLogger("vibe_check.sast")

# ---------------------------------------------------------------------------
# Severity mapping helpers
# ---------------------------------------------------------------------------

_BANDIT_SEVERITY_MAP = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
}

_SEMGREP_SEVERITY_MAP = {
    "INFO": Severity.INFO,
    "WARNING": Severity.MEDIUM,
    "ERROR": Severity.HIGH,
}

# Path to the bundled Semgrep rules shipped with vibe-check
_RULES_DIR = os.path.join(os.path.dirname(__file__), os.pardir, "rules")
_VIBE_RULES = os.path.normpath(
    os.path.join(_RULES_DIR, "vibe_antipatterns.yml")
)


# ---------------------------------------------------------------------------
# Tool runners
# ---------------------------------------------------------------------------

async def _run_bandit(repo_path: str, config: dict | None = None) -> List[Finding]:
    """Run Bandit and return parsed findings."""
    if shutil.which("bandit") is None:
        logger.warning(
            "bandit is not installed — skipping SAST/Bandit scan. "
            "Install with: pip install bandit"
        )
        return []

    from vibe_check.utils.git_utils import is_git_repo, get_git_tracked_files

    # Layer 1: In a git repo, feed only tracked .py files to Bandit.
    # Layer 2: For non-git dirs, use -r with hardcoded excludes.
    if is_git_repo(repo_path):
        py_files = get_git_tracked_files(repo_path, extensions=[".py"])
        if not py_files:
            logger.info("No git-tracked Python files found — skipping Bandit")
            return []
        # Pass tracked files directly (paths are relative to repo_path)
        cmd = ["bandit", "-f", "json", "-ll"] + py_files
    else:
        cmd = ["bandit", "-r", repo_path, "-f", "json", "-ll"]
        if config and config.get("exclude"):
            excludes = [x.rstrip("/") for x in config["exclude"]]
            cmd.extend(["-x", ",".join(excludes)])
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
    except Exception as exc:
        logger.warning("bandit failed to launch: %s", exc)
        return []

    # Bandit returns exit-code 1 when it finds issues — that's expected.
    if proc.returncode not in (0, 1):
        logger.warning(
            "bandit exited with code %d: %s",
            proc.returncode,
            stderr.decode(errors="replace").strip(),
        )

    try:
        data = json.loads(stdout.decode(errors="replace"))
    except json.JSONDecodeError as exc:
        logger.warning("Could not parse bandit output: %s", exc)
        return []

    findings: List[Finding] = []
    for issue in data.get("results", []):
        severity = _BANDIT_SEVERITY_MAP.get(
            issue.get("issue_severity", "").upper(), Severity.MEDIUM
        )
        cwe_obj = issue.get("issue_cwe", {})
        cwe_id = f"CWE-{cwe_obj.get('id')}" if cwe_obj.get("id") else None

        # Build a relative file path for consistency
        filepath = issue.get("filename", "")
        line_number = issue.get("line_number", 0)

        findings.append(
            Finding(
                title=issue.get("test_name", "Bandit Issue"),
                severity=severity,
                category=Category.SAST,
                file=filepath,
                line=line_number,
                description=issue.get("issue_text", ""),
                remediation=(
                    "Review the flagged code and apply the recommended secure "
                    "coding pattern. See Bandit docs for details on "
                    f"{issue.get('test_id', 'this test')}."
                ),
                ai_prompt=(
                    f"Review {filepath}:{line_number} — "
                    f"{issue.get('issue_text', '')}. "
                    "Suggest a secure alternative."
                ),
                evidence=issue.get("code", ""),
                tool="bandit",
                cwe=cwe_id,
                confidence=_confidence_for_bandit(
                    issue.get("issue_confidence", "MEDIUM")
                ),
            )
        )

    logger.info("Bandit scan complete — %d finding(s)", len(findings))
    return findings


def _confidence_for_bandit(confidence_str: str) -> float:
    """Map Bandit confidence labels to a 0-1 float."""
    return {"HIGH": 1.0, "MEDIUM": 0.7, "LOW": 0.4}.get(
        confidence_str.upper(), 0.7
    )


# ---------------------------------------------------------------------------

async def _run_semgrep(repo_path: str, config: dict | None = None) -> List[Finding]:
    """Run Semgrep with the bundled vibe-antipattern rules and return findings."""
    if shutil.which("semgrep") is None:
        logger.warning(
            "semgrep is not installed — skipping SAST/Semgrep scan. "
            "Install with: pip install semgrep"
        )
        return []

    # If the rules file is empty / placeholder, fall back to the auto config
    rules_arg = _VIBE_RULES if _rules_file_has_content() else "auto"

    cmd = [
        "semgrep",
        "--config", rules_arg,
        "--json",
    ]

    if config and config.get("exclude"):
        for ex in config["exclude"]:
            cmd.extend(["--exclude", ex.rstrip("/")])

    cmd.append(repo_path)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
    except Exception as exc:
        logger.warning("semgrep failed to launch: %s", exc)
        return []

    # Semgrep exits with 1 when findings exist — that's fine.
    if proc.returncode not in (0, 1):
        logger.warning(
            "semgrep exited with code %d: %s",
            proc.returncode,
            stderr.decode(errors="replace").strip(),
        )

    try:
        data = json.loads(stdout.decode(errors="replace"))
    except json.JSONDecodeError as exc:
        logger.warning("Could not parse semgrep output: %s", exc)
        return []

    findings: List[Finding] = []
    for result in data.get("results", []):
        severity = _SEMGREP_SEVERITY_MAP.get(
            result.get("extra", {}).get("severity", "").upper(),
            Severity.MEDIUM,
        )
        filepath = result.get("path", "")
        line_number = result.get("start", {}).get("line", 0)

        # CWE extraction — Semgrep may embed it in metadata
        metadata = result.get("extra", {}).get("metadata", {})
        cwe_raw = metadata.get("cwe", "")
        if isinstance(cwe_raw, list):
            cwe_raw = cwe_raw[0] if cwe_raw else ""
        cwe_id = cwe_raw if cwe_raw else None

        findings.append(
            Finding(
                title=result.get("check_id", "Semgrep Issue"),
                severity=severity,
                category=Category.SAST,
                file=filepath,
                line=line_number,
                description=result.get("extra", {}).get(
                    "message", "Semgrep rule matched."
                ),
                remediation=(
                    "Review the matched pattern and refactor according to "
                    "secure coding guidelines. "
                    f"Rule: {result.get('check_id', 'N/A')}."
                ),
                ai_prompt=(
                    f"Review {filepath}:{line_number} — Semgrep rule "
                    f"'{result.get('check_id', '')}' matched. "
                    "Suggest a fix."
                ),
                evidence=result.get("extra", {}).get("lines", ""),
                tool="semgrep",
                cwe=cwe_id,
            )
        )

    logger.info("Semgrep scan complete — %d finding(s)", len(findings))
    return findings


def _rules_file_has_content() -> bool:
    """Return True if the vibe_antipatterns rules file has actual rules."""
    if not os.path.isfile(_VIBE_RULES):
        return False
    try:
        import yaml  # pyyaml is already a project dependency

        with open(_VIBE_RULES, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return bool(data and data.get("rules"))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _dedup(
    bandit_findings: List[Finding], semgrep_findings: List[Finding]
) -> List[Finding]:
    """Merge findings, preferring the Semgrep version on file+line collision."""
    seen: dict[Tuple[str, int], Finding] = {}

    # Add Semgrep findings first so they take priority
    for f in semgrep_findings:
        key = (f.file or "", f.line or 0)
        seen[key] = f

    # Add Bandit findings only if no Semgrep finding at the same location
    for f in bandit_findings:
        key = (f.file or "", f.line or 0)
        if key not in seen:
            seen[key] = f

    return list(seen.values())


# ---------------------------------------------------------------------------
# Analyzer class
# ---------------------------------------------------------------------------

class SASTAnalyzer(BaseAnalyzer):
    """Runs Bandit and Semgrep in parallel, merges and deduplicates findings."""

    @property
    def name(self) -> str:
        return "sast"

    @property
    def tier(self) -> int:
        return 1

    async def analyze(
        self, repo_path: str, config: dict | None = None
    ) -> List[Finding]:
        # Run both tools concurrently
        bandit_findings, semgrep_findings = await asyncio.gather(
            _run_bandit(repo_path, config),
            _run_semgrep(repo_path, config),
        )

        # Merge and deduplicate (Semgrep wins on collision)
        merged = _dedup(bandit_findings, semgrep_findings)
        logger.info(
            "SAST scan complete — %d Bandit + %d Semgrep → %d merged finding(s)",
            len(bandit_findings),
            len(semgrep_findings),
            len(merged),
        )
        return merged
