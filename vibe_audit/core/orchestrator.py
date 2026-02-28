"""Orchestrator — runs all analyzers in parallel and assembles the ScanResult."""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import List

from vibe_audit.analyzers.base import BaseAnalyzer
from vibe_audit.core.scorer import calculate_composite, get_grade, get_verdict
from vibe_audit.models.finding import Finding
from vibe_audit.models.result import ScanResult

logger = logging.getLogger("vibe_audit.orchestrator")


def _detect_languages(repo_path: str) -> List[str]:
    """Quick language detection by file extension."""
    ext_map = {
        ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
        ".jsx": "JSX", ".tsx": "TSX", ".go": "Go", ".rb": "Ruby",
        ".rs": "Rust", ".java": "Java", ".yml": "YAML", ".yaml": "YAML",
    }
    langs = set()
    for root, _dirs, files in os.walk(repo_path):
        # Skip hidden dirs and node_modules
        parts = root.split(os.sep)
        if any(p.startswith(".") or p == "node_modules" for p in parts):
            continue
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in ext_map:
                langs.add(ext_map[ext])
    return sorted(langs)


def _count_files(repo_path: str) -> int:
    """Count scannable files in the repo."""
    count = 0
    scannable = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb",
                 ".rs", ".java", ".yml", ".yaml", ".json", ".toml",
                 ".cfg", ".ini", ".env", ".md", ".txt"}
    for root, _dirs, files in os.walk(repo_path):
        parts = root.split(os.sep)
        if any(p.startswith(".") or p == "node_modules" for p in parts):
            continue
        for fname in files:
            if os.path.splitext(fname)[1].lower() in scannable:
                count += 1
    return count


class Orchestrator:
    """Runs a list of analyzers in parallel and produces a ScanResult."""

    def __init__(
        self,
        analyzers: List[BaseAnalyzer],
        timeout: int = 60,
        config: dict | None = None,
    ):
        self.analyzers = analyzers
        self.timeout = timeout
        self.config = config or {}

    async def _run_one(self, analyzer: BaseAnalyzer, repo_path: str) -> List[Finding]:
        """Run a single analyzer with timeout."""
        try:
            findings = await asyncio.wait_for(
                analyzer.analyze(repo_path, self.config),
                timeout=self.timeout,
            )
            logger.info(
                "%s finished — %d findings", analyzer.name, len(findings)
            )
            return findings
        except asyncio.TimeoutError:
            logger.warning("%s timed out after %ds", analyzer.name, self.timeout)
            return []
        except Exception as exc:
            logger.warning("%s crashed: %s", analyzer.name, exc, exc_info=True)
            return []

    async def run(self, repo_path: str) -> ScanResult:
        """Execute all analyzers in parallel and return the scored result."""
        start = time.perf_counter()

        results = await asyncio.gather(
            *(self._run_one(a, repo_path) for a in self.analyzers),
            return_exceptions=False,  # exceptions are caught inside _run_one
        )

        all_findings: List[Finding] = []
        for batch in results:
            all_findings.extend(batch)

        elapsed = time.perf_counter() - start
        score, category_scores = calculate_composite(all_findings)
        grade = get_grade(score)
        verdict = get_verdict(score)

        return ScanResult(
            score=score,
            grade=grade,
            verdict=verdict,
            findings=all_findings,
            category_scores=category_scores,
            scan_time=elapsed,
            repo_path=repo_path,
            languages_detected=_detect_languages(repo_path),
            files_scanned=_count_files(repo_path),
        )
