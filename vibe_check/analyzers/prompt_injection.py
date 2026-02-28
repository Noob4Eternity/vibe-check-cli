"""Prompt injection analyzer (P1) — OWASP LLM Top 10 detection.

Three-phase approach:
  Phase 1: Semgrep with prompt_injection.yml rules (zero LLM)
  Phase 2: Extract ±15 lines of code context for each flagged location
  Phase 3: Send ONLY flagged segments to LLM for confidence scoring
           Filter out false positives (confidence < 0.3)
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import List, Optional

from vibe_check.analyzers.base import BaseAnalyzer
from vibe_check.models.finding import Category, Finding, Severity
from vibe_check.utils.llm_client import LLMClient

logger = logging.getLogger("vibe_check.prompt_injection")

PROMPT_TEMPLATE_PATH = (
    Path(__file__).parent.parent / "prompts" / "injection_review.txt"
)
RULES_PATH = Path(__file__).parent.parent / "rules" / "prompt_injection.yml"

# How many lines of context around a flagged line
CONTEXT_LINES = 15

# Max tokens per LLM call for a single segment
MAX_TOKENS_PER_SEGMENT = 2000

# Confidence threshold — below this we discard as false positive
CONFIDENCE_THRESHOLD = 0.3


class PromptInjectionAnalyzer(BaseAnalyzer):
    """Detects prompt injection surfaces in LLM-using codebases."""

    def __init__(self, llm_client: Optional[LLMClient] = None) -> None:
        if llm_client:
            self._llm = llm_client
        else:
            try:
                from vibe_check.utils.llm_client import LLMClient
                self._llm = LLMClient(provider="gemini")
            except Exception:
                self._llm = None

    @property
    def name(self) -> str:
        return "prompt_injection"

    @property
    def tier(self) -> int:
        return 4

    async def analyze(
        self, repo_path: str, config: dict | None = None
    ) -> List[Finding]:
        # Phase 1 — semgrep scan
        raw_hits = await self._run_semgrep(repo_path)
        logger.info("Phase 1 (semgrep): %d raw hits", len(raw_hits))

        if not raw_hits:
            return []

        # Phase 2 — extract code context for each hit
        segments = self._extract_segments(repo_path, raw_hits)
        logger.info("Phase 2 (context): %d segments extracted", len(segments))

        # Phase 3 — LLM verification (if available)
        if self._llm:
            findings = await self._llm_verify(segments)
            logger.info("Phase 3 (LLM): %d confirmed findings", len(findings))
            return findings

        # No LLM — return all semgrep hits as-is (lower confidence)
        return [seg["finding"] for seg in segments]

    # ── Phase 1: Semgrep ────────────────────────────────────────────

    async def _run_semgrep(self, repo_path: str) -> list[dict]:
        """Run semgrep with prompt injection rules, return raw results."""
        if not RULES_PATH.exists():
            logger.warning("Prompt injection rules not found: %s", RULES_PATH)
            return []

        try:
            proc = await asyncio.create_subprocess_exec(
                "semgrep",
                "--config", str(RULES_PATH),
                "--json",
                "--quiet",
                str(repo_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=30
            )
        except FileNotFoundError:
            logger.warning("semgrep not installed — skipping prompt injection rules")
            return []
        except asyncio.TimeoutError:
            logger.warning("semgrep timed out")
            return []

        if not stdout:
            return []

        try:
            data = json.loads(stdout.decode())
        except json.JSONDecodeError:
            logger.warning("Failed to parse semgrep output")
            return []

        return data.get("results", [])

    # ── Phase 2: Context extraction ─────────────────────────────────

    def _extract_segments(
        self, repo_path: str, raw_hits: list[dict]
    ) -> list[dict]:
        """For each semgrep hit, extract ±15 lines of surrounding code."""
        segments: list[dict] = []
        root = Path(repo_path)

        for hit in raw_hits:
            file_path = hit.get("path", "")
            target_line = hit.get("start", {}).get("line", 1)
            check_id = hit.get("check_id", "prompt-injection")
            message = hit.get("extra", {}).get("message", "Potential prompt injection surface")

            full_path = root / file_path
            if not full_path.exists():
                continue

            try:
                lines = full_path.read_text(
                    encoding="utf-8", errors="ignore"
                ).splitlines()
            except OSError:
                continue

            start = max(0, target_line - CONTEXT_LINES - 1)
            end = min(len(lines), target_line + CONTEXT_LINES)
            code_segment = "\n".join(lines[start:end])

            finding = Finding(
                title=check_id,
                severity=Severity.HIGH,
                category=Category.PROMPT_INJECTION,
                file=file_path,
                line=target_line,
                description=message,
                remediation="Sanitize user input before passing to LLM API. Use allowlists or template-based prompts instead of string concatenation.",
                ai_prompt=f"In {file_path} at line {target_line}, user input flows into an LLM API call without sanitization. Refactor to use a template-based prompt with input validation.",
                evidence=code_segment[:500],
                tool="semgrep",
                confidence=0.6,
            )

            segments.append(
                {
                    "file_path": file_path,
                    "start_line": start + 1,
                    "end_line": end,
                    "code_segment": code_segment,
                    "finding": finding,
                }
            )

        return segments

    # ── Phase 3: LLM verification ───────────────────────────────────

    async def _llm_verify(self, segments: list[dict]) -> List[Finding]:
        """Send each flagged segment to LLM for confidence scoring.

        Filters out false positives (confidence < 0.3).
        """
        if not self._llm:
            return [s["finding"] for s in segments]

        try:
            template = PROMPT_TEMPLATE_PATH.read_text(encoding="utf-8")
        except FileNotFoundError:
            logger.warning("Injection review prompt template not found")
            return [s["finding"] for s in segments]

        # Run all LLM calls concurrently
        tasks = [
            self._verify_single(template, seg) for seg in segments
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: List[Finding] = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.warning("LLM verification failed for segment %d: %s", i, result)
                # Keep the finding with original confidence on LLM failure
                findings.append(segments[i]["finding"])
            elif result is not None:
                findings.append(result)

        return findings

    async def _verify_single(
        self, template: str, segment: dict
    ) -> Optional[Finding]:
        """Verify a single segment with LLM. Returns Finding or None (false positive)."""
        prompt = (
            template.replace("{file_path}", segment["file_path"])
            .replace("{start_line}", str(segment["start_line"]))
            .replace("{end_line}", str(segment["end_line"]))
            .replace("{code_segment}", segment["code_segment"][:800])
        )

        try:
            response = await self._llm.ask(prompt, max_tokens=MAX_TOKENS_PER_SEGMENT)
        except Exception as e:
            logger.error("LLM call failed: %s", e)
            return segment["finding"]

        verdict = self._parse_verdict(response)
        if verdict is None:
            return segment["finding"]

        confidence = verdict.get("confidence", 0.5)

        # Filter false positives
        if not verdict.get("is_vulnerable", False) or confidence < CONFIDENCE_THRESHOLD:
            logger.info(
                "Filtered false positive: %s (confidence=%.2f)",
                segment["file_path"],
                confidence,
            )
            return None

        # Update finding with LLM-verified data
        finding = segment["finding"]
        finding.confidence = confidence
        finding.description = verdict.get("explanation", finding.description)

        owasp = verdict.get("owasp_ref")
        if owasp:
            finding.cwe = f"OWASP LLM {owasp}"

        return finding

    def _parse_verdict(self, response: str) -> Optional[dict]:
        """Parse LLM JSON response."""
        text = response.strip()

        # Handle markdown code blocks
        if "```" in text:
            match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
            if match:
                text = match.group(1)

        # Find JSON object
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1:
            return None

        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            logger.warning("Failed to parse LLM verdict JSON")
            return None
