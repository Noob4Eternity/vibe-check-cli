"""Dependency analyzer (P4) — THE KILLER FEATURE.

Detects hallucinated (non-existent) packages, typosquats, outdated/deprecated
dependencies, and low-popularity suspicious packages by querying real registries.

Merged: BaseAnalyzer integration + async HTTP (P3) with robust parsing,
semver version comparison, and deprecation detection (P4-teammate).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]

import aiohttp

from vibe_check.analyzers.base import BaseAnalyzer
from vibe_check.models.finding import Category, Finding, Severity

logger = logging.getLogger("vibe_check.dependencies")


# ── Popular package lists for typosquat detection ──────────────────

_TOP_PYPI = [
    "requests", "flask", "django", "numpy", "pandas", "fastapi", "sqlalchemy",
    "pydantic", "boto3", "celery", "redis", "pytest", "pillow", "scipy",
    "scikit-learn", "tensorflow", "torch", "transformers", "httpx", "aiohttp",
    "beautifulsoup4", "selenium", "scrapy", "gunicorn", "uvicorn", "jinja2",
    "click", "typer", "rich", "cryptography", "paramiko", "pyyaml", "toml",
    "python-dotenv", "openai", "anthropic", "langchain", "streamlit", "gradio",
    "matplotlib", "seaborn", "black", "flake8", "mypy", "ruff",
]

_TOP_NPM = [
    "react", "next", "express", "axios", "lodash", "typescript", "webpack",
    "eslint", "prettier", "jest", "mocha", "chai", "vue", "angular", "svelte",
    "tailwindcss", "postcss", "vite", "rollup", "babel", "moment", "dayjs",
    "uuid", "dotenv", "cors", "jsonwebtoken", "bcrypt", "mongoose", "prisma",
    "zod", "yup", "formik", "redux", "zustand", "socket.io", "nodemon",
    "chalk", "commander", "inquirer", "puppeteer", "playwright", "cheerio",
    "openai", "langchain", "sharp", "multer",
]


# ── Registry URLs ──────────────────────────────────────────────────

REGISTRY_URLS: Dict[str, str] = {
    "pypi": "https://pypi.org/pypi/{name}/json",
    "npm": "https://registry.npmjs.org/{name}",
    "rubygems": "https://rubygems.org/api/v1/gems/{name}.json",
    "crates": "https://crates.io/api/v1/crates/{name}",
}

_DEPRECATION_YEARS = 3


# ══════════════════════════════════════════════════════════════════
# Manifest parsers
# ══════════════════════════════════════════════════════════════════

_VER_SPLIT = re.compile(r'([<>=!~]{1,2})')


def _parse_requirements_txt(path: Path) -> List[Tuple[str, str]]:
    """Parse requirements.txt → list of (package_name, ecosystem)."""
    packages = []
    for raw in path.read_text(errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r", "--requirement", "-e", "git+")):
            continue
        # Strip inline comments and env markers
        line = line.split("#", 1)[0].strip()
        name_part = line.split(";", 1)[0].strip()
        # Split on version specifier
        m = _VER_SPLIT.search(name_part)
        name = name_part[:m.start()].strip() if m else name_part.strip()
        # Strip extras in brackets
        name = re.sub(r"\[.*\]", "", name).strip()
        if name:
            packages.append((name.lower(), "pypi"))
    return packages


def _parse_pyproject_toml(path: Path) -> List[Tuple[str, str]]:
    """Extract dependencies from pyproject.toml.

    Supports [project.dependencies], [project.optional-dependencies],
    and [tool.poetry.dependencies] / [tool.poetry.dev-dependencies].
    Falls back to regex parsing if tomllib is unavailable.
    """
    packages = []

    if tomllib is not None:
        try:
            with open(path, "rb") as fh:
                data = tomllib.load(fh)
        except Exception:
            data = None

        if data:
            def _parse_pep508(spec: str) -> Optional[str]:
                """Extract package name from a PEP 508 string."""
                spec = spec.split(";", 1)[0].strip()
                spec = re.sub(r"\[.*?\]", "", spec)
                m = _VER_SPLIT.search(spec)
                return spec[:m.start()].strip() if m else spec.strip()

            # [project.dependencies]
            project = data.get("project") or {}
            for dep in project.get("dependencies") or []:
                name = _parse_pep508(dep)
                if name:
                    packages.append((name.lower(), "pypi"))

            # [project.optional-dependencies]
            for group_deps in (project.get("optional-dependencies") or {}).values():
                for dep in group_deps or []:
                    name = _parse_pep508(dep)
                    if name:
                        packages.append((name.lower(), "pypi"))

            # [tool.poetry.dependencies / dev-dependencies / groups]
            poetry = (data.get("tool") or {}).get("poetry") or {}
            for key in ("dependencies", "dev-dependencies"):
                for name in (poetry.get(key) or {}):
                    if name.lower() != "python":
                        packages.append((name.lower(), "pypi"))
            for group in (poetry.get("group") or {}).values():
                for name in (group.get("dependencies") or {}):
                    if name.lower() != "python":
                        packages.append((name.lower(), "pypi"))

            return packages

    # Fallback: simple regex parsing
    content = path.read_text(errors="ignore")
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("dependencies") and "=" in stripped:
            in_deps = True
            continue
        if in_deps:
            if stripped == "]":
                in_deps = False
                continue
            match = re.match(r'["\']([a-zA-Z0-9_-]+)', stripped)
            if match:
                packages.append((match.group(1).lower(), "pypi"))
    return packages


def _parse_package_json(path: Path) -> List[Tuple[str, str]]:
    """Parse package.json → list of (package_name, 'npm')."""
    packages = []
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(section, {})
        if isinstance(deps, dict):
            for name in deps:
                packages.append((name.lower(), "npm"))
    return packages


def _parse_gemfile(path: Path) -> List[Tuple[str, str]]:
    """Parse Gemfile → list of (gem_name, 'rubygems')."""
    packages = []
    for line in path.read_text(errors="ignore").splitlines():
        match = re.match(r"^\s*gem\s+['\"]([^'\"]+)['\"]", line)
        if match:
            packages.append((match.group(1).lower(), "rubygems"))
    return packages


def _parse_cargo_toml(path: Path) -> List[Tuple[str, str]]:
    """Parse Cargo.toml → list of (crate_name, 'crates')."""
    packages = []
    in_deps = False
    for line in path.read_text(errors="ignore").splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and "dependencies" in stripped:
            in_deps = True
            continue
        if stripped.startswith("[") and "dependencies" not in stripped:
            in_deps = False
            continue
        if in_deps:
            match = re.match(r'^([a-zA-Z0-9_-]+)\s*=', stripped)
            if match:
                packages.append((match.group(1).lower(), "crates"))
    return packages


def _parse_pipfile(path: Path) -> List[Tuple[str, str]]:
    """Parse Pipfile."""
    packages = []
    in_packages = False
    for line in path.read_text(errors="ignore").splitlines():
        stripped = line.strip()
        if stripped in ("[packages]", "[dev-packages]"):
            in_packages = True
            continue
        if stripped.startswith("["):
            in_packages = False
            continue
        if in_packages:
            match = re.match(r'^([a-zA-Z0-9_-]+)\s*=', stripped)
            if match:
                packages.append((match.group(1).lower(), "pypi"))
    return packages


MANIFEST_PARSERS = {
    "requirements.txt": _parse_requirements_txt,
    "pyproject.toml": _parse_pyproject_toml,
    "package.json": _parse_package_json,
    "Gemfile": _parse_gemfile,
    "Cargo.toml": _parse_cargo_toml,
    "Pipfile": _parse_pipfile,
}


# ══════════════════════════════════════════════════════════════════
# Levenshtein + typosquat detection
# ══════════════════════════════════════════════════════════════════

def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr_row.append(min(
                curr_row[j] + 1,
                prev_row[j + 1] + 1,
                prev_row[j] + cost,
            ))
        prev_row = curr_row
    return prev_row[-1]


def _check_typosquat(name: str, ecosystem: str) -> Optional[str]:
    """Check if a package name is within Levenshtein distance 1-2 of a popular package."""
    top_packages = _TOP_PYPI if ecosystem == "pypi" else _TOP_NPM if ecosystem == "npm" else []
    # Skip if the package itself is already a known popular package
    if name in top_packages:
        return None
    for popular in top_packages:
        dist = _levenshtein(name, popular)
        if 1 <= dist <= 2 and name != popular:
            return popular
    return None


# ══════════════════════════════════════════════════════════════════
# Version comparison (from P4 teammate)
# ══════════════════════════════════════════════════════════════════

def _parse_semver(v: str) -> Tuple[int, ...]:
    """Parse a version string into a tuple of ints, e.g. '2.3.1' -> (2, 3, 1)."""
    parts = []
    for segment in re.split(r"[.\-]", v):
        m = re.match(r"(\d+)", segment)
        if m:
            parts.append(int(m.group(1)))
    return tuple(parts) if parts else (0,)


def _extract_base_version(requested: Optional[str]) -> Optional[str]:
    """Pull the first concrete version from a specifier, e.g. '>=2.25,<3.0' -> '2.25'."""
    if not requested:
        return None
    m = re.search(r"(\d[\d.]*)", requested)
    return m.group(1) if m else None


def _years_since(iso_date: str) -> float:
    """Return fractional years since an ISO-8601 date string."""
    try:
        dt = datetime.fromisoformat(iso_date.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days / 365.25
    except Exception:
        return 0.0


def _check_version_staleness(
    requested_version: Optional[str],
    latest_version: Optional[str],
    latest_release_date: Optional[str],
) -> Optional[Tuple[Severity, str]]:
    """Compare requested vs latest version and check deprecation.

    Returns (Severity, description) or None if up-to-date.
    """
    # Deprecation check
    if latest_release_date:
        age = _years_since(latest_release_date)
        if age >= _DEPRECATION_YEARS:
            return (Severity.HIGH, f"deprecated — last release {age:.1f} years ago")

    if not latest_version or not requested_version:
        return None

    req_base = _extract_base_version(requested_version)
    if not req_base:
        return None

    latest = _parse_semver(latest_version)
    requested = _parse_semver(req_base)

    # Pad to 3 elements
    lat = (latest + (0, 0, 0))[:3]
    req = (requested + (0, 0, 0))[:3]

    maj_diff = lat[0] - req[0]
    min_diff = lat[1] - req[1] if maj_diff == 0 else 0

    if maj_diff >= 2:
        return (Severity.HIGH, f"{maj_diff} major versions behind ({req_base} → {latest_version})")
    if maj_diff == 1:
        return (Severity.MEDIUM, f"1 major version behind ({req_base} → {latest_version})")
    if min_diff >= 3:
        return (Severity.MEDIUM, f"{min_diff} minor versions behind ({req_base} → {latest_version})")
    # Patch or 1-2 minor behind — not worth a finding
    return None


# ══════════════════════════════════════════════════════════════════
# Main Analyzer
# ══════════════════════════════════════════════════════════════════

class DependencyAnalyzer(BaseAnalyzer):
    """Checks package registries for hallucinated, typosquatted, outdated, and suspicious deps."""

    @property
    def name(self) -> str:
        return "dependencies"

    @property
    def tier(self) -> int:
        return 2

    async def analyze(
        self, repo_path: str, config: dict | None = None
    ) -> List[Finding]:
        # 1. Discover manifest files and parse package names
        all_packages: List[Tuple[str, str, str]] = []  # (name, ecosystem, manifest_file)
        root = Path(repo_path)
        tracked = (config or {}).get("tracked_files")

        for manifest_name, parser in MANIFEST_PARSERS.items():
            # Check root level
            root_manifest = root / manifest_name
            if root_manifest.exists():
                rel_str = str(root_manifest.relative_to(root))
                # Skip if not tracked by git
                if tracked is not None and rel_str not in tracked:
                    continue
                try:
                    parsed = parser(root_manifest)
                    for pkg_name, ecosystem in parsed:
                        all_packages.append((pkg_name, ecosystem, rel_str))
                except Exception as e:
                    logger.warning("Failed to parse %s: %s", root_manifest, e)

            # Monorepo support — also check subdirectories
            for candidate in root.rglob(manifest_name):
                rel = candidate.relative_to(root)
                rel_str = str(rel)
                # Skip if not tracked by git
                if tracked is not None:
                    if rel_str not in tracked:
                        continue
                else:
                    if any(p.startswith(".") or p in ("node_modules", ".venv", "venv", "__pycache__") for p in rel.parts):
                        continue
                if candidate == root_manifest:
                    continue
                try:
                    parsed = parser(candidate)
                    for pkg_name, ecosystem in parsed:
                        all_packages.append((pkg_name, ecosystem, rel_str))
                except Exception as e:
                    logger.warning("Failed to parse %s: %s", candidate, e)

        if not all_packages:
            logger.info("No manifest files found")
            return []

        # Deduplicate
        seen: set[Tuple[str, str]] = set()
        unique_packages = []
        for name, eco, manifest in all_packages:
            key = (name, eco)
            if key not in seen:
                seen.add(key)
                unique_packages.append((name, eco, manifest))

        logger.info("Found %d unique packages across %d manifest files",
                     len(unique_packages), len(set(m for _, _, m in unique_packages)))

        # 2. Check all packages against real registries in parallel
        findings: List[Finding] = []
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            headers={"User-Agent": "vibe-check/0.1.0"},
        ) as session:
            # Registry checks + CVE audit run concurrently
            registry_tasks = [
                self._check_package(session, name, ecosystem, manifest)
                for name, ecosystem, manifest in unique_packages
            ]
            cve_task = asyncio.create_task(self._run_cve_audits(root))

            registry_results = await asyncio.gather(*registry_tasks, return_exceptions=True)
            cve_findings = await cve_task

            for result in registry_results:
                if isinstance(result, Exception):
                    logger.debug("Registry check failed: %s", result)
                    continue
                if isinstance(result, list):
                    findings.extend(result)
                elif result is not None:
                    findings.append(result)

            findings.extend(cve_findings)

        logger.info("Dependency scan complete — %d finding(s)", len(findings))
        return findings

    async def _check_package(
        self,
        session: aiohttp.ClientSession,
        name: str,
        ecosystem: str,
        manifest: str,
    ) -> Optional[Finding] | List[Finding]:
        """Check a single package against its registry."""
        url_template = REGISTRY_URLS.get(ecosystem)
        if not url_template:
            return None

        url = url_template.format(name=name)

        try:
            async with session.get(url) as resp:
                if resp.status == 404:
                    # ── HALLUCINATED PACKAGE ─────────────────────
                    similar = _check_typosquat(name, ecosystem)
                    suggestion = f" Did you mean '{similar}'?" if similar else ""
                    return Finding(
                        title=f"Hallucinated Package: {name}",
                        severity=Severity.CRITICAL,
                        category=Category.HALLUCINATED_DEPENDENCY,
                        file=manifest,
                        description=(
                            f"Package '{name}' does not exist on "
                            f"{ecosystem.upper()} (HTTP 404). "
                            f"Likely hallucinated by an LLM.{suggestion}"
                        ),
                        remediation=(
                            f"Remove '{name}' from {manifest}."
                            + (f" Use '{similar}' instead." if similar else
                               " Find a real package that provides the needed functionality.")
                        ),
                        ai_prompt=(
                            f"The package '{name}' in {manifest} doesn't exist. "
                            f"{'Replace it with ' + similar + ' and update all imports.' if similar else 'Find a real alternative and update imports.'}"
                        ),
                        evidence=f"{url} → 404 Not Found",
                        tool="dependency-checker",
                    )

                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    result_findings: List[Finding] = []

                    # Extract version info from registry response
                    latest_version, latest_release_date, requested = self._extract_metadata(
                        data, ecosystem, name
                    )

                    # Check for outdated / deprecated
                    staleness = _check_version_staleness(
                        requested, latest_version, latest_release_date
                    )
                    if staleness:
                        sev, desc = staleness
                        result_findings.append(Finding(
                            title=f"Outdated Package: {name}",
                            severity=sev,
                            category=Category.VULNERABLE_DEPENDENCY,
                            file=manifest,
                            description=f"Package '{name}' is {desc}.",
                            remediation=f"Update '{name}' to version {latest_version}.",
                            ai_prompt=f"Update '{name}' in {manifest} to latest version {latest_version}.",
                            evidence=f"Requested: {requested or 'unpinned'}, Latest: {latest_version}",
                            tool="dependency-checker",
                            confidence=0.9,
                        ))

                    # Check for low downloads (suspicious)
                    weekly_downloads = self._get_downloads(data, ecosystem)
                    if weekly_downloads is not None and weekly_downloads < 100:
                        result_findings.append(Finding(
                            title=f"Suspicious Low-Download Package: {name}",
                            severity=Severity.HIGH,
                            category=Category.VULNERABLE_DEPENDENCY,
                            file=manifest,
                            description=(
                                f"Package '{name}' has only {weekly_downloads} "
                                f"weekly downloads on {ecosystem.upper()}. "
                                f"Low-popularity packages are higher risk for "
                                f"supply chain attacks."
                            ),
                            remediation=f"Verify that '{name}' is the correct package.",
                            ai_prompt=f"The package '{name}' in {manifest} has very few downloads. Verify it's legitimate.",
                            evidence=f"{weekly_downloads} weekly downloads",
                            tool="dependency-checker",
                        ))

                    # Check for typosquat (only if the package actually exists)
                    similar = _check_typosquat(name, ecosystem)
                    if similar:
                        result_findings.append(Finding(
                            title=f"Possible Typosquat: {name}",
                            severity=Severity.MEDIUM,
                            category=Category.VULNERABLE_DEPENDENCY,
                            file=manifest,
                            description=(
                                f"Package '{name}' is very similar to popular "
                                f"package '{similar}' (Levenshtein distance ≤ 2). "
                                f"This could be a typosquat or a typo."
                            ),
                            remediation=f"Verify you intend to use '{name}' and not '{similar}'.",
                            ai_prompt=f"Check if '{name}' in {manifest} should be '{similar}' instead.",
                            evidence=f"Levenshtein distance to '{similar}' ≤ 2",
                            tool="dependency-checker",
                            confidence=0.7,
                        ))

                    return result_findings if result_findings else None

        except asyncio.TimeoutError:
            logger.debug("Timeout checking %s on %s", name, ecosystem)
        except Exception as e:
            logger.debug("Error checking %s on %s: %s", name, ecosystem, e)

        return None

    @staticmethod
    def _extract_metadata(
        data: dict, ecosystem: str, name: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Extract (latest_version, latest_release_date, requested_version) from registry data."""
        try:
            if ecosystem == "pypi":
                info = data.get("info", {}) or {}
                releases = data.get("releases", {}) or {}
                latest_version = info.get("version")
                latest_release_date = None
                if latest_version and latest_version in releases:
                    files = releases.get(latest_version) or []
                    times = [f.get("upload_time_iso_8601") for f in files if f.get("upload_time_iso_8601")]
                    if times:
                        latest_release_date = max(times)
                return latest_version, latest_release_date, None

            elif ecosystem == "npm":
                dist_tags = data.get("dist-tags") or {}
                latest_version = dist_tags.get("latest")
                time_info = data.get("time") or {}
                latest_release_date = time_info.get(latest_version) if latest_version else time_info.get("modified")
                return latest_version, latest_release_date, None

            elif ecosystem == "rubygems":
                return data.get("version"), None, None

            elif ecosystem == "crates":
                crate = data.get("crate", {})
                return crate.get("newest_version"), crate.get("updated_at"), None

        except Exception:
            pass
        return None, None, None

    @staticmethod
    def _get_downloads(data: dict, ecosystem: str) -> Optional[int]:
        """Extract download count from registry response."""
        try:
            if ecosystem == "rubygems":
                return data.get("downloads")
            elif ecosystem == "crates":
                return data.get("crate", {}).get("recent_downloads")
        except Exception:
            pass
        return None

    # ── CVE audit via subprocess ───────────────────────────────────

    async def _run_cve_audits(self, root: Path) -> List[Finding]:
        """Run npm audit and pip-audit concurrently for known CVEs."""
        import shutil

        tasks = []
        if (root / "package.json").exists() and shutil.which("npm"):
            tasks.append(self._run_npm_audit(root))
        if any((root / f).exists() for f in ("requirements.txt", "pyproject.toml", "Pipfile")) and shutil.which("pip-audit"):
            tasks.append(self._run_pip_audit(root))

        if not tasks:
            return []

        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings: List[Finding] = []
        for result in results:
            if isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, Exception):
                logger.debug("CVE audit error: %s", result)
        return findings

    @staticmethod
    async def _run_npm_audit(root: Path) -> List[Finding]:
        """Run `npm audit --json` and convert to Findings."""
        findings: List[Finding] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "npm", "audit", "--json",
                cwd=str(root),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            data = json.loads(stdout.decode("utf-8", errors="replace"))

            # npm audit v7+ format: { vulnerabilities: { package: { ... } } }
            vulns = data.get("vulnerabilities", {})
            for pkg_name, info in vulns.items():
                severity_str = (info.get("severity") or "moderate").lower()
                severity_map = {
                    "critical": Severity.CRITICAL,
                    "high": Severity.HIGH,
                    "moderate": Severity.MEDIUM,
                    "low": Severity.LOW,
                    "info": Severity.INFO,
                }
                sev = severity_map.get(severity_str, Severity.MEDIUM)

                # Extract advisory details
                via = info.get("via", [])
                cve_ids = []
                titles = []
                urls = []
                for v in via:
                    if isinstance(v, dict):
                        if v.get("title"):
                            titles.append(v["title"])
                        if v.get("url"):
                            urls.append(v["url"])
                        if v.get("cve"):
                            cve_ids.append(v["cve"])

                fix_available = info.get("fixAvailable")
                fix_str = ""
                if isinstance(fix_available, dict):
                    fix_str = f" Fix: update to {fix_available.get('name', pkg_name)}@{fix_available.get('version', 'latest')}"
                elif fix_available:
                    fix_str = " Run `npm audit fix` to resolve."

                title_detail = titles[0] if titles else f"Known vulnerability in {pkg_name}"

                findings.append(Finding(
                    title=f"CVE: {pkg_name} — {title_detail}",
                    severity=sev,
                    category=Category.VULNERABLE_DEPENDENCY,
                    file="package.json",
                    description=(
                        f"npm audit found a {severity_str} vulnerability in '{pkg_name}'. "
                        f"{' | '.join(titles[:2])}"
                        f"{' (' + ', '.join(cve_ids[:2]) + ')' if cve_ids else ''}"
                    ),
                    remediation=f"Update '{pkg_name}' to a patched version.{fix_str}",
                    ai_prompt=f"Update '{pkg_name}' in package.json to fix {', '.join(cve_ids[:2]) or 'the known vulnerability'}.",
                    evidence=" | ".join(urls[:2]) if urls else f"npm audit --json ({severity_str})",
                    tool="npm-audit",
                    cwe=cve_ids[0] if cve_ids else None,
                ))

            logger.info("npm audit: %d vulnerability(ies)", len(findings))

        except FileNotFoundError:
            logger.debug("npm not found — skipping npm audit")
        except asyncio.TimeoutError:
            logger.debug("npm audit timed out")
        except json.JSONDecodeError:
            logger.debug("npm audit returned non-JSON output")
        except Exception as e:
            logger.debug("npm audit failed: %s", e)

        return findings

    @staticmethod
    async def _run_pip_audit(root: Path) -> List[Finding]:
        """Run `pip-audit --format json` and convert to Findings."""
        findings: List[Finding] = []

        # Determine the requirements source
        args = ["pip-audit", "--format", "json"]
        if (root / "requirements.txt").exists():
            args.extend(["-r", str(root / "requirements.txt")])
        else:
            args.append("--desc")

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                cwd=str(root),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            data = json.loads(stdout.decode("utf-8", errors="replace"))

            # pip-audit format: { dependencies: [ { name, version, vulns: [...] } ] }
            for dep in data.get("dependencies", []):
                dep_name = dep.get("name", "unknown")
                dep_version = dep.get("version", "?")
                for vuln in dep.get("vulns", []):
                    vuln_id = vuln.get("id", "UNKNOWN")
                    description = vuln.get("description", "No description available")
                    fix_versions = vuln.get("fix_versions", [])

                    findings.append(Finding(
                        title=f"CVE: {dep_name}=={dep_version} — {vuln_id}",
                        severity=Severity.HIGH,
                        category=Category.VULNERABLE_DEPENDENCY,
                        file="requirements.txt",
                        description=(
                            f"pip-audit found vulnerability {vuln_id} in "
                            f"'{dep_name}=={dep_version}'. {description[:200]}"
                        ),
                        remediation=(
                            f"Update '{dep_name}' to {', '.join(fix_versions)}"
                            if fix_versions else
                            f"Check for a patched version of '{dep_name}'"
                        ),
                        ai_prompt=(
                            f"Update '{dep_name}' in requirements.txt to fix {vuln_id}."
                            f" Safe versions: {', '.join(fix_versions)}" if fix_versions else ""
                        ),
                        evidence=f"https://osv.dev/vulnerability/{vuln_id}",
                        tool="pip-audit",
                        cwe=vuln_id,
                    ))

            logger.info("pip-audit: %d vulnerability(ies)", len(findings))

        except FileNotFoundError:
            logger.debug("pip-audit not found — skipping")
        except asyncio.TimeoutError:
            logger.debug("pip-audit timed out")
        except json.JSONDecodeError:
            logger.debug("pip-audit returned non-JSON output")
        except Exception as e:
            logger.debug("pip-audit failed: %s", e)

        return findings
