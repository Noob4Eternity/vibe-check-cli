"""Compliance analyzer (P1) — GDPR/SOC2 gap detection.

Three-phase approach:
  Phase 1: Semgrep with gdpr.yml + soc2.yml rules (zero LLM)
  Phase 2: Build compressed AST summary of repo (~300 tokens)
  Phase 3: Send AST summary to LLM for compliance reasoning
"""

from __future__ import annotations

import ast
import asyncio
import json
import logging
import os
import re
from pathlib import Path
from typing import List, Optional

from vibe_check.analyzers.base import BaseAnalyzer
from vibe_check.models.finding import Category, Finding, Severity
from vibe_check.utils.llm_client import LLMClient

logger = logging.getLogger("vibe_check.compliance")

PROMPT_TEMPLATE_PATH = Path(__file__).parent.parent / "prompts" / "compliance_review.txt"

# Semgrep rule files for compliance
RULE_FILES = ["gdpr.yml", "soc2.yml"]


class ComplianceAnalyzer(BaseAnalyzer):
    """Detects GDPR and SOC2 compliance gaps using semgrep + LLM reasoning."""

    def __init__(self, llm_client: Optional[LLMClient] = None) -> None:
        if llm_client:
            self._llm = llm_client
        else:
            # Auto-initialize from env if API key is available
            try:
                self._llm = LLMClient(provider="gemini")
            except Exception:
                self._llm = None

    @property
    def name(self) -> str:
        return "compliance"

    @property
    def tier(self) -> int:
        return 3

    async def analyze(
        self, repo_path: str, config: dict | None = None
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Phase 1 — semgrep rules (deterministic)
        semgrep_findings = await self._run_semgrep(repo_path)
        findings.extend(semgrep_findings)
        logger.info("Phase 1 (semgrep): %d findings", len(semgrep_findings))

        # Phase 2 — build AST summary
        ast_summary = self._build_ast_summary(repo_path)
        logger.info("Phase 2 (AST summary): %d chars", len(ast_summary))

        # Phase 3 — LLM compliance reasoning
        if self._llm and ast_summary.strip():
            llm_findings = await self._llm_compliance_check(ast_summary)
            findings.extend(llm_findings)
            logger.info("Phase 3 (LLM): %d findings", len(llm_findings))

        return findings

    # ── Phase 1: Semgrep ────────────────────────────────────────────

    async def _run_semgrep(self, repo_path: str) -> List[Finding]:
        """Run semgrep with GDPR + SOC2 rules, parse JSON output."""
        rules_dir = Path(__file__).parent.parent / "rules"
        findings: List[Finding] = []

        for rule_file in RULE_FILES:
            rule_path = rules_dir / rule_file
            if not rule_path.exists():
                logger.warning("Rule file not found: %s", rule_path)
                continue

            try:
                proc = await asyncio.create_subprocess_exec(
                    "semgrep",
                    "--config", str(rule_path),
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
                logger.warning("semgrep not installed — skipping compliance rules")
                return []
            except asyncio.TimeoutError:
                logger.warning("semgrep timed out for %s", rule_file)
                continue

            if not stdout:
                continue

            try:
                data = json.loads(stdout.decode())
            except json.JSONDecodeError:
                logger.warning("Failed to parse semgrep output for %s", rule_file)
                continue

            for result in data.get("results", []):
                sev_map = {
                    "ERROR": Severity.HIGH,
                    "WARNING": Severity.MEDIUM,
                    "INFO": Severity.LOW,
                }
                cat = (
                    Category.COMPLIANCE_GDPR
                    if "gdpr" in rule_file
                    else Category.COMPLIANCE_SOC2
                )
                findings.append(
                    Finding(
                        title=result.get("check_id", "compliance-issue"),
                        severity=sev_map.get(
                            result.get("extra", {}).get("severity", "WARNING"),
                            Severity.MEDIUM,
                        ),
                        category=cat,
                        file=result.get("path", ""),
                        line=result.get("start", {}).get("line"),
                        description=result.get("extra", {}).get(
                            "message", "Compliance issue detected by semgrep"
                        ),
                        remediation="Review and fix the flagged compliance issue.",
                        ai_prompt=f"Fix the compliance issue in {result.get('path', 'this file')} at line {result.get('start', {}).get('line', '?')}: {result.get('extra', {}).get('message', '')}",
                        evidence=result.get("extra", {}).get("lines", ""),
                        tool="semgrep",
                    )
                )

        return findings

    # ── Phase 2: AST Summary ────────────────────────────────────────

    def _build_ast_summary(self, repo_path: str) -> str:
        """Build a compressed structural summary of the repo.

        Extracts: routes, PII-like fields, auth decorators, logging calls.
        Targets ~300 tokens output.
        """
        routes: list[str] = []
        pii_fields: list[str] = []
        auth_decorators: list[str] = []
        logging_calls: list[str] = []
        has_consent_mechanism = False
        has_deletion_endpoint = False
        has_encryption = False
        frameworks: list[str] = []

        root = Path(repo_path)

        # Scan Python files with ast
        for py_file in root.rglob("*.py"):
            try:
                rel = py_file.relative_to(root)
                if _should_skip(rel):
                    continue
                source = py_file.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(source, filename=str(rel))
                self._extract_python(tree, str(rel), routes, pii_fields, auth_decorators, logging_calls, frameworks)

                # Simple keyword checks
                lower = source.lower()
                if "consent" in lower or "gdpr" in lower:
                    has_consent_mechanism = True
                if "delete" in lower and ("user" in lower or "account" in lower):
                    has_deletion_endpoint = True
                if "encrypt" in lower or "fernet" in lower or "aes" in lower:
                    has_encryption = True

            except (SyntaxError, UnicodeDecodeError):
                continue

        # Scan JS/TS files with regex
        for pattern in ("*.js", "*.ts", "*.jsx", "*.tsx"):
            for js_file in root.rglob(pattern):
                try:
                    rel = js_file.relative_to(root)
                    if _should_skip(rel):
                        continue
                    source = js_file.read_text(encoding="utf-8", errors="ignore")
                    self._extract_js(source, str(rel), routes, pii_fields, auth_decorators, logging_calls, frameworks)

                    lower = source.lower()
                    if "consent" in lower or "gdpr" in lower:
                        has_consent_mechanism = True
                    if "delete" in lower and ("user" in lower or "account" in lower):
                        has_deletion_endpoint = True

                except UnicodeDecodeError:
                    continue

        # Build compact summary
        lines = []
        if frameworks:
            lines.append(f"Frameworks: {', '.join(list(set(frameworks))[:5])}")
        if routes:
            lines.append(f"Routes: {', '.join(routes[:15])}")
        if pii_fields:
            lines.append(f"PII-like fields: {', '.join(list(set(pii_fields))[:10])}")
        if auth_decorators:
            lines.append(f"Auth decorators: {', '.join(list(set(auth_decorators))[:5])}")
        else:
            lines.append("Auth decorators: NONE DETECTED")
        if logging_calls:
            lines.append(f"Logging calls: {len(logging_calls)} total")
        else:
            lines.append("Logging calls: NONE DETECTED")
        lines.append(f"Consent mechanism: {'yes' if has_consent_mechanism else 'NOT DETECTED'}")
        lines.append(f"Deletion endpoint: {'yes' if has_deletion_endpoint else 'NOT DETECTED'}")
        lines.append(f"Encryption usage: {'yes' if has_encryption else 'NOT DETECTED'}")

        return "\n".join(lines)

    def _extract_python(
        self,
        tree: ast.AST,
        filename: str,
        routes: list,
        pii_fields: list,
        auth_decorators: list,
        logging_calls: list,
        frameworks: list,
    ) -> None:
        """Walk Python AST and collect structural info."""
        PII_PATTERNS = re.compile(
            r"(email|password|passwd|phone|ssn|social_security|"
            r"credit_card|card_number|address|date_of_birth|dob|"
            r"first_name|last_name|full_name|ip_address)",
            re.IGNORECASE,
        )

        for node in ast.walk(tree):
            # Detect routes
            if isinstance(node, ast.FunctionDef):
                for dec in node.decorator_list:
                    dec_str = ast.dump(dec)
                    # Flask/FastAPI route decorators
                    if any(m in dec_str for m in ("route", "get", "post", "put", "delete", "patch")):
                        method = "?"
                        path = "?"
                        if isinstance(dec, ast.Call) and dec.args:
                            if isinstance(dec.args[0], ast.Constant):
                                path = dec.args[0].value
                        for kw in ("get", "post", "put", "delete", "patch"):
                            if kw in dec_str.lower():
                                method = kw.upper()
                                break
                        routes.append(f"{method} {path} ({filename})")

                    # Auth decorators
                    if any(
                        a in dec_str
                        for a in ("login_required", "auth", "Depends", "jwt_required", "permission")
                    ):
                        auth_decorators.append(f"{node.name} ({filename})")

            # Detect PII-like attribute/variable names
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and PII_PATTERNS.search(target.id):
                        pii_fields.append(target.id)
                    elif isinstance(target, ast.Attribute) and PII_PATTERNS.search(target.attr):
                        pii_fields.append(target.attr)

            # Detect logging calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ("info", "warning", "error", "debug", "critical"):
                        logging_calls.append(filename)
                    elif node.func.attr in ("log",):
                        logging_calls.append(filename)
                elif isinstance(node.func, ast.Name):
                    if node.func.id == "print":
                        logging_calls.append(filename)

            # Detect frameworks
            if isinstance(node, ast.ImportFrom) and node.module:
                if "flask" in node.module:
                    frameworks.append("Flask")
                elif "fastapi" in node.module:
                    frameworks.append("FastAPI")
                elif "django" in node.module:
                    frameworks.append("Django")

    def _extract_js(
        self,
        source: str,
        filename: str,
        routes: list,
        pii_fields: list,
        auth_decorators: list,
        logging_calls: list,
        frameworks: list,
    ) -> None:
        """Regex-based extraction for JS/TS files."""
        # Routes — Express/Next.js patterns
        for m in re.finditer(
            r"""(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"](.*?)['"]""",
            source,
        ):
            routes.append(f"{m.group(1).upper()} {m.group(2)} ({filename})")

        # Next.js API routes (file-based routing)
        if "pages/api/" in filename or "app/api/" in filename:
            for m in re.finditer(r"export\s+(?:default\s+)?(?:async\s+)?function\s+(\w+)", source):
                routes.append(f"API_ROUTE {filename}")
                break

        # PII-like fields
        for m in re.finditer(
            r"""(?:email|password|phone|ssn|creditCard|cardNumber|address|dateOfBirth)""",
            source,
            re.IGNORECASE,
        ):
            pii_fields.append(m.group(0))

        # Auth middleware
        if re.search(r"(?:auth|middleware|protect|guard|session)", source, re.IGNORECASE):
            if re.search(r"(?:require|check|verify|validate)", source, re.IGNORECASE):
                auth_decorators.append(f"middleware ({filename})")

        # Console/logging
        if "console.log" in source or "console.error" in source:
            logging_calls.append(filename)

        # Frameworks
        if "express" in source:
            frameworks.append("Express")
        if "next" in filename.lower() or "Next" in source:
            frameworks.append("Next.js")

    # ── Phase 3: LLM Compliance Check ──────────────────────────────

    async def _llm_compliance_check(self, ast_summary: str) -> List[Finding]:
        """Send AST summary to LLM for GDPR/SOC2 gap reasoning."""
        if not self._llm:
            return []

        try:
            template = PROMPT_TEMPLATE_PATH.read_text(encoding="utf-8")
        except FileNotFoundError:
            logger.warning("Compliance prompt template not found")
            return []

        prompt = template.replace("{ast_summary}", ast_summary)

        try:
            response = await self._llm.ask(prompt, max_tokens=8192)
        except Exception as e:
            logger.error("LLM compliance check failed: %s", e)
            return []

        return self._parse_llm_response(response)

    def _parse_llm_response(self, response: str) -> List[Finding]:
        """Parse LLM JSON array response into findings."""
        # Extract JSON from response (handle markdown code blocks)
        json_str = response.strip()
        if "```" in json_str:
            match = re.search(r"```(?:json)?(.*?)```", json_str, re.DOTALL)
            if match:
                json_str = match.group(1).strip()

        # Try to find JSON array
        start = json_str.find("[")
        end = json_str.rfind("]")
        if start == -1 or end == -1:
            logger.warning(f"No JSON array found in LLM response. Raw response was: {repr(response)}")
            return []

        json_str = json_str[start : end + 1]

        try:
            items = json.loads(json_str)
        except json.JSONDecodeError:
            logger.warning("Failed to parse LLM JSON response")
            return []

        findings: List[Finding] = []
        sev_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        cat_map = {
            "compliance_gdpr": Category.COMPLIANCE_GDPR,
            "compliance_soc2": Category.COMPLIANCE_SOC2,
        }

        for item in items:
            if not isinstance(item, dict):
                continue
            findings.append(
                Finding(
                    title=item.get("title", "Compliance gap"),
                    severity=sev_map.get(
                        item.get("severity", "medium"), Severity.MEDIUM
                    ),
                    category=cat_map.get(
                        item.get("category", "compliance_gdpr"),
                        Category.COMPLIANCE_GDPR,
                    ),
                    file=item.get("file"),
                    description=item.get("description", ""),
                    remediation=item.get("remediation", ""),
                    ai_prompt=f"Fix compliance issue: {item.get('title', '')}. {item.get('remediation', '')}",
                    compliance_ref=item.get("compliance_ref"),
                    confidence=0.8,
                    tool="llm-compliance",
                )
            )

        return findings


def _should_skip(rel_path: Path) -> bool:
    """Skip vendor, node_modules, venv, etc."""
    parts = rel_path.parts
    skip_dirs = {
        "node_modules", ".venv", "venv", "__pycache__", ".git",
        "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
    }
    return bool(set(parts) & skip_dirs)
