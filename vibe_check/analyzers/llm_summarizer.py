"""LLM summarizer (P1) — final LLM call to produce executive summary + remediation prompts.

Takes all findings from all analyzers, compresses into ~500 tokens,
sends ONE LLM call to generate:
  - 3-sentence executive summary
  - Copy-paste remediation prompts for each critical/high finding
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import List, Optional

from vibe_check.analyzers.base import BaseAnalyzer
from vibe_check.models.finding import Category, Finding, Severity
from vibe_check.utils.llm_client import LLMClient

logger = logging.getLogger("vibe_check.llm_summarizer")

PROMPT_TEMPLATE_PATH = Path(__file__).parent.parent / "prompts" / "summary.txt"


class LLMSummarizer(BaseAnalyzer):
    """Generates executive summary and remediation prompts from all findings."""

    def __init__(self, llm_client: Optional[LLMClient] = None) -> None:
        if llm_client:
            self._llm = llm_client
        else:
            try:
                self._llm = LLMClient(provider="gemini")
            except Exception:
                self._llm = None

    @property
    def name(self) -> str:
        return "llm_summarizer"

    @property
    def tier(self) -> int:
        return 5

    async def analyze(
        self, repo_path: str, config: dict | None = None
    ) -> List[Finding]:
        """Not used directly — call summarize() instead."""
        return []

    async def summarize(self, all_findings: List[Finding]) -> List[Finding]:
        """Produce summary findings from the aggregated finding list.

        Returns a list of Finding objects:
          - One finding with the executive summary
          - One finding per remediation prompt for critical/high issues
        """
        if not self._llm or not all_findings:
            return []

        # Compress findings into a compact summary (~500 tokens)
        compressed = self._compress_findings(all_findings)
        logger.info("Compressed %d findings into %d chars", len(all_findings), len(compressed))

        # Load prompt template
        try:
            template = PROMPT_TEMPLATE_PATH.read_text(encoding="utf-8")
        except FileNotFoundError:
            logger.warning("Summary prompt template not found")
            return []

        prompt = template.replace("{findings_summary}", compressed)

        # ONE LLM call
        try:
            response = await self._llm.ask(prompt, max_tokens=8192)
        except Exception as e:
            logger.error("LLM summarization failed: %s", e)
            return []

        return self._parse_response(response)

    def _compress_findings(self, findings: List[Finding]) -> str:
        """Compress findings into a structured summary targeting ~500 tokens.

        Includes: counts by severity, counts by category, top critical/high details.
        """
        # Counts by severity
        sev_counts: dict[str, int] = {}
        for f in findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

        # Counts by category
        cat_counts: dict[str, int] = {}
        for f in findings:
            cat_counts[f.category.value] = cat_counts.get(f.category.value, 0) + 1

        # Top critical/high findings (compact)
        critical_high = [
            f for f in findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]

        lines = [
            f"Total: {len(findings)} findings",
            f"By severity: {', '.join(f'{k}={v}' for k, v in sorted(sev_counts.items()))}",
            f"By category: {', '.join(f'{k}={v}' for k, v in sorted(cat_counts.items()))}",
            "",
            "Top critical/high issues:",
        ]

        # Include up to 8 critical/high findings, compact format
        for f in critical_high[:8]:
            loc = f"{f.file}:{f.line}" if f.file and f.line else (f.file or "?")
            lines.append(
                f"- [{f.severity.value.upper()}] {f.title} @ {loc}: {f.description[:100]}"
            )

        return "\n".join(lines)

    def _parse_response(self, response: str) -> List[Finding]:
        """Parse LLM response into Finding objects."""
        text = response.strip()

        # Handle markdown code blocks
        if "```" in text:
            match = re.search(r"```(?:json)?(.*?)```", text, re.DOTALL)
            if match:
                text = match.group(1).strip()

        # Find JSON object
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1:
            logger.warning("No JSON found in LLM summary response")
            return []

        try:
            data = json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            logger.warning("Failed to parse LLM summary JSON")
            return []

        findings: List[Finding] = []

        # Executive summary as a finding
        summary = data.get("executive_summary", "")
        if summary:
            findings.append(
                Finding(
                    title="Executive Summary",
                    severity=Severity.INFO,
                    category=Category.LLM_REVIEW,
                    description=summary,
                    remediation="See individual findings for specific fixes.",
                    ai_prompt="",
                    tool="llm-summarizer",
                    confidence=1.0,
                )
            )

        # Remediation prompts as findings (INFO severity — these are
        # guidance for developers, NOT new security vulnerabilities.
        # Using the original severity would double-count penalties.)
        for item in data.get("remediation_prompts", []):
            if not isinstance(item, dict):
                continue

            findings.append(
                Finding(
                    title=f"Remediation: {item.get('title', 'Fix')}",
                    severity=Severity.INFO,
                    category=Category.LLM_REVIEW,
                    description=f"AI-generated remediation for: {item.get('title', '')}",
                    remediation=item.get("prompt", ""),
                    ai_prompt=item.get("prompt", ""),
                    tool="llm-summarizer",
                    confidence=0.9,
                )
            )

        return findings
