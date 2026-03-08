"""Orchestrator — runs all analyzers in parallel and assembles the ScanResult."""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import List

from vibe_check.analyzers.base import BaseAnalyzer
from vibe_check.core.scorer import calculate_composite, get_grade, get_verdict
from vibe_check.models.finding import Finding
from vibe_check.models.result import ScanResult

logger = logging.getLogger("vibe_check.orchestrator")


def _detect_languages(repo_path: str) -> List[str]:
    """Quick language detection by file extension."""
    ext_map = {
        ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
        ".jsx": "JSX", ".tsx": "TSX", ".go": "Go", ".rb": "Ruby",
        ".rs": "Rust", ".java": "Java", ".yml": "YAML", ".yaml": "YAML",
    }

    from vibe_check.utils.git_utils import is_git_repo, get_git_tracked_files

    if is_git_repo(repo_path):
        files = get_git_tracked_files(repo_path)
        langs = set()
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in ext_map:
                langs.add(ext_map[ext])
        return sorted(langs)

    # Fallback for non-git directories — walk with hardcoded skips
    _SKIP_DIRS = {"node_modules", ".venv", "venv", "env", "__pycache__"}
    langs = set()
    for root, _dirs, files in os.walk(repo_path):
        parts = root.split(os.sep)
        if any(p.startswith(".") or p in _SKIP_DIRS for p in parts):
            continue
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in ext_map:
                langs.add(ext_map[ext])
    return sorted(langs)


def _count_files(repo_path: str) -> int:
    """Count scannable files in the repo."""
    scannable = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb",
                 ".rs", ".java", ".yml", ".yaml", ".json", ".toml",
                 ".cfg", ".ini", ".env", ".md", ".txt"}

    from vibe_check.utils.git_utils import is_git_repo, get_git_tracked_files

    if is_git_repo(repo_path):
        files = get_git_tracked_files(repo_path)
        return sum(1 for f in files if os.path.splitext(f)[1].lower() in scannable)

    # Fallback for non-git directories
    _SKIP_DIRS = {"node_modules", ".venv", "venv", "env", "__pycache__"}
    count = 0
    for root, _dirs, files in os.walk(repo_path):
        parts = root.split(os.sep)
        if any(p.startswith(".") or p in _SKIP_DIRS for p in parts):
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
        """Execute all analyzers in parallel and return the scored result.

        LLMSummarizer is handled specially: it runs *after* all other analyzers
        and receives the collected findings via its summarize() method.
        """
        start = time.perf_counter()

        # ── Git-aware file filtering ────────────────────────────────
        # Call git ls-files ONCE and share the set with all analyzers
        # via config. Non-git repos (ZIP uploads) get None → fallback
        # to each analyzer's built-in _SKIP_DIRS.
        from vibe_check.utils.git_utils import is_git_repo, get_git_tracked_files
        if is_git_repo(repo_path):
            tracked = set(get_git_tracked_files(repo_path))
            self.config["tracked_files"] = tracked
            logger.info("Git repo detected — %d tracked files", len(tracked))
        else:
            self.config["tracked_files"] = None
            logger.info("Non-git directory — using _SKIP_DIRS fallback")

        # Separate LLMSummarizer from regular analyzers
        from vibe_check.analyzers.llm_summarizer import LLMSummarizer

        regular = [a for a in self.analyzers if not isinstance(a, LLMSummarizer)]
        summarizers = [a for a in self.analyzers if isinstance(a, LLMSummarizer)]

        # Phase 1 — run all regular analyzers in parallel
        results = await asyncio.gather(
            *(self._run_one(a, repo_path) for a in regular),
            return_exceptions=False,
        )

        all_findings: List[Finding] = []
        for batch in results:
            all_findings.extend(batch)

        # Track which analyzer names ran (for showing clean categories)
        scanned_analyzers = [a.name for a in regular]

        # Phase 2 — run LLMSummarizer with the collected findings
        for summarizer in summarizers:
            try:
                summary_findings = await asyncio.wait_for(
                    summarizer.summarize(all_findings),
                    timeout=self.timeout,
                )
                all_findings.extend(summary_findings)
                logger.info("LLM summarizer produced %d findings", len(summary_findings))
            except asyncio.TimeoutError:
                logger.warning("LLM summarizer timed out after %ds", self.timeout)
            except Exception as exc:
                logger.warning("LLM summarizer crashed: %s", exc, exc_info=True)

        # Collect token usage from any LLM client in the analyzers
        tokens_used = self._collect_token_usage()

        elapsed = time.perf_counter() - start
        score, category_scores = calculate_composite(all_findings, scanned_analyzers)
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
            tokens_used=tokens_used,
        )

    def _collect_token_usage(self) -> int:
        """Sum token usage from all analyzers that have an LLM client."""
        total = 0
        seen_clients: set[int] = set()
        for a in self.analyzers:
            client = getattr(a, "_llm", None)
            if client and id(client) not in seen_clients:
                seen_clients.add(id(client))
                total += getattr(client, "tokens_used", 0)
        return total
