"""Cost efficiency analyzer — flags wasteful patterns in vibe-coded repos.

Five deterministic checks (no LLM required):
  1. Expensive LLM models where cheaper alternatives exist
  2. Over-provisioned cloud resources (K8s, Docker, Serverless)
  3. Missing caching on repeated calls
  4. Redundant API calls to the same URL in one file
  5. Bloated dependencies with lighter alternatives
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import List

from vibe_check.analyzers.base import BaseAnalyzer
from vibe_check.models.finding import Category, Finding, Severity

logger = logging.getLogger("vibe_check.cost")

# ── Check 1: Expensive LLM Models ─────────────────────────────────
# Maps expensive models to their cheaper alternatives
_EXPENSIVE_MODELS: dict[str, str] = {
    # OpenAI
    "gpt-4o\"": "gpt-4o-mini (10× cheaper, similar quality for most tasks)",
    "gpt-4-turbo": "gpt-4o-mini (10× cheaper, similar quality for most tasks)",
    "gpt-4\"": "gpt-4o-mini (10× cheaper, similar quality for most tasks)",
    "o1-preview": "o1-mini or gpt-4o-mini (significantly cheaper for most tasks)",
    "o1\"": "o1-mini or gpt-4o-mini (significantly cheaper for most tasks)",
    # Anthropic
    "claude-3-opus": "claude-3-haiku or claude-3.5-sonnet (2-60× cheaper)",
    "claude-3-5-sonnet": "claude-3-haiku (10× cheaper for simple tasks)",
    "claude-sonnet-4": "claude-3-haiku (10× cheaper for simple tasks)",
    # Google
    "gemini-2.5-pro": "gemini-2.0-flash (much cheaper for simple tasks)",
    "gemini-1.5-pro": "gemini-1.5-flash or gemini-2.0-flash (10× cheaper)",
}

# ── Check 2: Over-provisioned Resources ───────────────────────────
_K8S_CPU_RE = re.compile(r"cpu:\s*[\"']?(\d+)(?:m)?[\"']?", re.IGNORECASE)
_K8S_MEM_RE = re.compile(r"memory:\s*[\"']?(\d+)(Mi|Gi)[\"']?", re.IGNORECASE)
_SERVERLESS_MEM_RE = re.compile(r"memorySize:\s*(\d+)", re.IGNORECASE)

# ── Check 5: Bloated Dependencies ─────────────────────────────────
_BLOATED_DEPS: dict[str, str] = {
    # JS/TS
    "moment": "dayjs (2KB vs 72KB, same API)",
    "lodash": "lodash-es or native JS (tree-shakeable, 70% smaller)",
    "underscore": "native JS Array/Object methods",
    "request": "node-fetch or native fetch (request is deprecated)",
    "axios": "native fetch API (built-in, zero dependencies)",
    "jquery": "native DOM APIs (no dependency needed in modern browsers)",
    "left-pad": "String.prototype.padStart (built-in)",
    "is-even": "n % 2 === 0 (built-in)",
    "is-odd": "n % 2 !== 0 (built-in)",
    # Python
    "pandas": "csv module or polars (pandas is 30MB+ for simple CSV tasks)",
    "tensorflow": "tensorflow-lite or onnxruntime (if only doing inference)",
    "boto3": "specific service SDK (e.g., s3fs) if only using one AWS service",
}

# Directories to skip
_SKIP_DIRS = {
    "node_modules", ".venv", "venv", "__pycache__", ".git",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
    "tests", "test", "fixtures", "__tests__", "__mocks__",
    "vibe_check",  # Don't scan our own tool code
    ".next", ".nuxt", "out",  # Framework build outputs
}


class CostAnalyzer(BaseAnalyzer):
    """Detects cost inefficiencies in vibe-coded repositories."""

    @property
    def name(self) -> str:
        return "cost_efficiency"

    @property
    def tier(self) -> int:
        return 1  # Fast — pure regex, no subprocesses or LLM

    async def analyze(
        self, repo_path: str, config: dict | None = None
    ) -> List[Finding]:
        findings: List[Finding] = []
        root = Path(repo_path)
        tracked = (config or {}).get("tracked_files")

        findings.extend(self._check_expensive_models(root, tracked))
        findings.extend(self._check_overprovisioned(root, tracked))
        findings.extend(self._check_redundant_calls(root, tracked))
        findings.extend(self._check_bloated_deps(root, tracked))

        logger.info("Cost analyzer: %d findings", len(findings))
        return findings

    # ── Check 1: Expensive LLM models ─────────────────────────────

    def _check_expensive_models(self, root: Path, tracked: set | None = None) -> List[Finding]:
        findings: List[Finding] = []
        patterns = ("*.py", "*.js", "*.ts", "*.jsx", "*.tsx")

        for pattern in patterns:
            for fpath in root.rglob(pattern):
                if _should_skip(fpath, root, tracked):
                    continue
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue

                rel = str(fpath.relative_to(root))
                for model_str, alternative in _EXPENSIVE_MODELS.items():
                    # Only match model strings in actual usage context:
                    #   model="gpt-4o"  or  model: "gpt-4o"  or  model='gpt-4o'
                    # This avoids matching config dicts or reference comments.
                    usage_pattern = re.compile(
                        rf'model\s*[=:]\s*["\']?{re.escape(model_str.strip(chr(34)))}',
                        re.IGNORECASE,
                    )
                    for m in usage_pattern.finditer(content):
                        line_num = content[:m.start()].count("\n") + 1
                        findings.append(
                            Finding(
                                title=f"Expensive LLM model: {model_str.strip('\"')}",
                                severity=Severity.MEDIUM,
                                category=Category.COST_EFFICIENCY,
                                file=rel,
                                line=line_num,
                                description=(
                                    f"Using expensive model '{model_str.strip('\"')}'. "
                                    f"Consider {alternative} for cost savings."
                                ),
                                remediation=(
                                    f"Replace with a cheaper model. Alternative: {alternative}. "
                                    "Only use expensive models for tasks that require "
                                    "superior reasoning (complex analysis, code generation)."
                                ),
                                ai_prompt=(
                                    f"Review the use of '{model_str.strip('\"')}' in {rel}:{line_num}. "
                                    f"Determine if {alternative} would be sufficient for this use case."
                                ),
                                tool="cost-analyzer",
                                confidence=0.8,
                            )
                        )
        return findings

    # ── Check 2: Over-provisioned resources ───────────────────────

    def _check_overprovisioned(self, root: Path, tracked: set | None = None) -> List[Finding]:
        findings: List[Finding] = []
        config_patterns = ("*.yml", "*.yaml", "Dockerfile", "docker-compose*")

        for pattern in config_patterns:
            for fpath in root.rglob(pattern):
                if _should_skip(fpath, root, tracked):
                    continue
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue

                rel = str(fpath.relative_to(root))

                # K8s CPU check (>2 cores)
                for m in _K8S_CPU_RE.finditer(content):
                    cpu_val = int(m.group(1))
                    unit = m.group(0)
                    # Skip millicore values like 500m
                    if "m" in unit.lower() and cpu_val <= 2000:
                        continue
                    if cpu_val > 2:
                        line_num = content[:m.start()].count("\n") + 1
                        findings.append(
                            Finding(
                                title=f"Over-provisioned CPU: {cpu_val} cores",
                                severity=Severity.MEDIUM,
                                category=Category.COST_EFFICIENCY,
                                file=rel,
                                line=line_num,
                                description=(
                                    f"Container requests {cpu_val} CPU cores. "
                                    "Most application containers run fine on 0.5-1 cores."
                                ),
                                remediation=(
                                    "Review actual CPU usage and right-size the resource request. "
                                    "Start with 500m (0.5 cores) and scale up based on metrics."
                                ),
                                ai_prompt=f"Review CPU allocation of {cpu_val} cores in {rel}:{line_num}. Right-size based on actual usage.",
                                tool="cost-analyzer",
                                confidence=0.7,
                            )
                        )

                # K8s Memory check (>4Gi)
                for m in _K8S_MEM_RE.finditer(content):
                    mem_val = int(m.group(1))
                    unit = m.group(2)
                    mem_mi = mem_val * 1024 if unit == "Gi" else mem_val
                    if mem_mi > 4096:  # > 4Gi
                        line_num = content[:m.start()].count("\n") + 1
                        findings.append(
                            Finding(
                                title=f"Over-provisioned memory: {mem_val}{unit}",
                                severity=Severity.MEDIUM,
                                category=Category.COST_EFFICIENCY,
                                file=rel,
                                line=line_num,
                                description=(
                                    f"Container requests {mem_val}{unit} memory. "
                                    "Most web applications run under 512Mi-1Gi."
                                ),
                                remediation=(
                                    "Review actual memory usage and right-size. "
                                    "Start with 256Mi-512Mi and scale up based on OOM metrics."
                                ),
                                ai_prompt=f"Review memory allocation of {mem_val}{unit} in {rel}:{line_num}. Right-size based on actual usage.",
                                tool="cost-analyzer",
                                confidence=0.7,
                            )
                        )

                # Serverless memory check (>512MB)
                for m in _SERVERLESS_MEM_RE.finditer(content):
                    mem_val = int(m.group(1))
                    if mem_val > 512:
                        line_num = content[:m.start()].count("\n") + 1
                        findings.append(
                            Finding(
                                title=f"Over-provisioned Lambda: {mem_val}MB",
                                severity=Severity.LOW,
                                category=Category.COST_EFFICIENCY,
                                file=rel,
                                line=line_num,
                                description=(
                                    f"Lambda function configured with {mem_val}MB memory. "
                                    "Most functions run under 256-512MB."
                                ),
                                remediation=(
                                    "Use AWS Lambda Power Tuning to find the optimal "
                                    "memory size for cost/performance balance."
                                ),
                                ai_prompt=f"Review Lambda memory allocation of {mem_val}MB in {rel}:{line_num}.",
                                tool="cost-analyzer",
                                confidence=0.6,
                            )
                        )

        return findings

    # ── Check 3 & 4: Redundant API calls ──────────────────────────

    def _check_redundant_calls(self, root: Path, tracked: set | None = None) -> List[Finding]:
        """Detect duplicate API calls to the same URL in a single file."""
        findings: List[Finding] = []
        patterns = ("*.py", "*.js", "*.ts", "*.jsx", "*.tsx")

        # Regex to find API calls with URL strings
        api_call_re = re.compile(
            r'(?:fetch|requests\.(?:get|post|put|delete)|axios\.(?:get|post|put|delete)|'
            r'httpx\.(?:get|post|put|delete)|aiohttp\.(?:get|post|put|delete))'
            r"""\s*\(\s*['"`]([^'"`]{10,})['"`]""",
        )

        for pattern in patterns:
            for fpath in root.rglob(pattern):
                if _should_skip(fpath, root, tracked):
                    continue
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue

                rel = str(fpath.relative_to(root))
                url_calls: dict[str, list[int]] = {}

                for m in api_call_re.finditer(content):
                    url = m.group(1)
                    line_num = content[:m.start()].count("\n") + 1
                    url_calls.setdefault(url, []).append(line_num)

                for url, lines in url_calls.items():
                    if len(lines) >= 2:
                        findings.append(
                            Finding(
                                title="Redundant API calls to same URL",
                                severity=Severity.MEDIUM,
                                category=Category.COST_EFFICIENCY,
                                file=rel,
                                line=lines[0],
                                description=(
                                    f"The URL '{url[:60]}...' is called {len(lines)} times "
                                    f"in this file (lines {', '.join(map(str, lines[:5]))}). "
                                    "Each call incurs network latency and potential API costs."
                                ),
                                remediation=(
                                    "Cache the response or extract the call into a shared function. "
                                    "Use memoization, React Query, SWR, or a simple variable."
                                ),
                                ai_prompt=(
                                    f"Refactor {rel} to deduplicate API calls to '{url[:60]}'. "
                                    "Add caching or extract into a shared utility."
                                ),
                                tool="cost-analyzer",
                                confidence=0.7,
                            )
                        )

        return findings

    # ── Check 5: Bloated dependencies ─────────────────────────────

    def _check_bloated_deps(self, root: Path, tracked: set | None = None) -> List[Finding]:
        findings: List[Finding] = []

        # Check package.json
        for pjson in root.rglob("package.json"):
            if _should_skip(pjson, root, tracked):
                continue
            try:
                content = pjson.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            rel = str(pjson.relative_to(root))
            for dep, alternative in _BLOATED_DEPS.items():
                # Match as a dependency key
                pattern = f'"{dep}"'
                idx = content.find(pattern)
                if idx != -1:
                    line_num = content[:idx].count("\n") + 1
                    findings.append(
                        Finding(
                            title=f"Bloated dependency: {dep}",
                            severity=Severity.LOW,
                            category=Category.COST_EFFICIENCY,
                            file=rel,
                            line=line_num,
                            description=(
                                f"'{dep}' is a heavy dependency. "
                                f"Consider: {alternative}."
                            ),
                            remediation=(
                                f"Replace '{dep}' with {alternative} to reduce "
                                "bundle size and improve load times."
                            ),
                            ai_prompt=(
                                f"Replace the '{dep}' dependency in {rel} with {alternative}. "
                                "Ensure all usage is migrated."
                            ),
                            tool="cost-analyzer",
                            confidence=0.8,
                        )
                    )

        # Check requirements.txt / pyproject.toml
        for req_file in list(root.rglob("requirements*.txt")) + list(root.rglob("pyproject.toml")):
            if _should_skip(req_file, root, tracked):
                continue
            try:
                content = req_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            rel = str(req_file.relative_to(root))
            for dep, alternative in _BLOATED_DEPS.items():
                # Match as a line or dependency listing
                if re.search(rf'(?:^|\n|")\s*{re.escape(dep)}\s*(?:[=<>!\n"])', content):
                    line_num = 1
                    for i, line in enumerate(content.splitlines(), 1):
                        if dep in line:
                            line_num = i
                            break
                    findings.append(
                        Finding(
                            title=f"Bloated dependency: {dep}",
                            severity=Severity.LOW,
                            category=Category.COST_EFFICIENCY,
                            file=rel,
                            line=line_num,
                            description=(
                                f"'{dep}' is a heavy dependency. "
                                f"Consider: {alternative}."
                            ),
                            remediation=(
                                f"Replace '{dep}' with {alternative} to reduce "
                                "install size and build times."
                            ),
                            ai_prompt=(
                                f"Replace the '{dep}' dependency in {rel} with {alternative}."
                            ),
                            tool="cost-analyzer",
                            confidence=0.7,
                        )
                    )

        return findings


def _should_skip(fpath: Path, root: Path, tracked: set | None = None) -> bool:
    """Skip files not tracked by git, or vendor/test/build directories."""
    try:
        rel = fpath.relative_to(root)
    except ValueError:
        return True
    rel_str = str(rel)
    # Always skip our own tool code (prevents self-referencing false positives)
    if rel_str.startswith("vibe_check/"):
        return True
    # If we have a git tracked-files set, skip anything not in it
    if tracked is not None:
        return rel_str not in tracked
    # Fallback: skip known vendor/build directories
    return bool(set(rel.parts) & _SKIP_DIRS)
