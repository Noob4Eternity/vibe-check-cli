"""Next.js specific security analyzer.

Catches the exact mistakes vibe-coded Next.js apps make:
- Unprotected API routes (missing auth middleware)
- NEXT_PUBLIC_ prefix leaking secrets to browser
- Unvalidated server actions
- dangerouslySetInnerHTML usage
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import List, Optional

from vibe_audit.analyzers.base import BaseAnalyzer
from vibe_audit.models.finding import Category, Finding, Severity

logger = logging.getLogger("vibe_audit.nextjs")

# Sensitive variable patterns that should NEVER be prefixed with NEXT_PUBLIC_
_SENSITIVE_PATTERNS = re.compile(
    r"(SECRET|PASSWORD|API_KEY|PRIVATE_KEY|TOKEN|DATABASE_URL|DB_URL|"
    r"STRIPE_SECRET|AWS_SECRET|OPENAI_API|ANTHROPIC_API|GEMINI_API|"
    r"AUTH_SECRET|JWT_SECRET|ENCRYPTION_KEY|SUPABASE_SERVICE_ROLE)",
    re.IGNORECASE,
)

# Auth patterns in JS/TS code
_AUTH_PATTERNS = [
    r"getServerSession",
    r"getSession",
    r"auth\(\)",
    r"currentUser",
    r"getToken",
    r"verifyToken",
    r"jwt\.verify",
    r"requireAuth",
    r"withAuth",
    r"isAuthenticated",
    r"middleware",
    r"NextAuth",
    r"clerk",
    r"supabase\.auth",
    r"getAuth",
]

_AUTH_REGEX = re.compile("|".join(_AUTH_PATTERNS), re.IGNORECASE)

# Server action indicator
_SERVER_ACTION_RE = re.compile(r"""['"]use server['"]""")

# Input validation patterns
_VALIDATION_PATTERNS = [
    r"\.parse\(",       # zod .parse()
    r"\.safeParse\(",   # zod .safeParse()
    r"\.validate\(",    # yup/joi .validate()
    r"\.validateSync\(",
    r"typeof\s+\w+\s*[!=]==",
    r"if\s*\(\s*!\s*\w+",  # basic null check
    r"assert\(",
    r"sanitize",
    r"escape\(",
    r"DOMPurify",
]

_VALIDATION_REGEX = re.compile("|".join(_VALIDATION_PATTERNS), re.IGNORECASE)


class NextJSAnalyzer(BaseAnalyzer):
    """Next.js specific security checks targeting vibe-coded mistakes."""

    @property
    def name(self) -> str:
        return "nextjs"

    @property
    def tier(self) -> int:
        return 1  # Deterministic, fast

    async def analyze(
        self, repo_path: str, config: dict | None = None
    ) -> List[Finding]:
        root = Path(repo_path)

        # Only run on Next.js projects
        if not self._is_nextjs_project(root):
            return []

        findings: List[Finding] = []

        # 1. Check for NEXT_PUBLIC_ leaking secrets
        findings.extend(self._check_env_exposure(root))

        # 2. Check for unprotected API routes
        findings.extend(self._check_unprotected_api_routes(root))

        # 3. Check for unvalidated server actions
        findings.extend(self._check_server_actions(root))

        # 4. Check for dangerouslySetInnerHTML
        findings.extend(self._check_dangerous_html(root))

        logger.info("Next.js scan complete — %d finding(s)", len(findings))
        return findings

    @staticmethod
    def _is_nextjs_project(root: Path) -> bool:
        """Detect if this is a Next.js project."""
        nextjs_indicators = [
            "next.config.js", "next.config.ts", "next.config.mjs",
        ]
        if any((root / f).exists() for f in nextjs_indicators):
            return True
        # Also check package.json for next dependency
        pkg_json = root / "package.json"
        if pkg_json.exists():
            try:
                import json
                data = json.loads(pkg_json.read_text(errors="ignore"))
                deps = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {})}
                return "next" in deps
            except Exception:
                pass
        return False

    def _check_env_exposure(self, root: Path) -> List[Finding]:
        """Check .env files for sensitive vars prefixed with NEXT_PUBLIC_."""
        findings = []
        env_files = list(root.glob(".env*"))
        for env_file in env_files:
            try:
                for i, line in enumerate(env_file.read_text(errors="ignore").splitlines(), 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" not in line:
                        continue
                    var_name = line.split("=", 1)[0].strip()
                    if var_name.startswith("NEXT_PUBLIC_") and _SENSITIVE_PATTERNS.search(var_name):
                        findings.append(Finding(
                            title=f"Secret Exposed to Client: {var_name}",
                            severity=Severity.CRITICAL,
                            category=Category.FRAMEWORK_SPECIFIC,
                            file=str(env_file.relative_to(root)),
                            line=i,
                            description=(
                                f"Environment variable '{var_name}' has the NEXT_PUBLIC_ prefix, "
                                f"which exposes it to the browser. This variable appears to contain "
                                f"sensitive data that should never reach the client."
                            ),
                            remediation=(
                                f"Remove the NEXT_PUBLIC_ prefix from '{var_name}'. "
                                f"Access it only in server-side code (API routes, getServerSideProps, Server Components)."
                            ),
                            ai_prompt=(
                                f"The env var '{var_name}' is prefixed with NEXT_PUBLIC_ which exposes it to the browser. "
                                f"Remove the prefix and refactor the code to only access this var on the server side."
                            ),
                            evidence=f"Line {i}: {var_name}=...",
                            tool="nextjs-checker",
                        ))
            except Exception as e:
                logger.debug("Failed to read %s: %s", env_file, e)
        return findings

    def _check_unprotected_api_routes(self, root: Path) -> List[Finding]:
        """Check API routes for missing authentication."""
        findings = []

        # Next.js API routes can be in:
        # - pages/api/**/*.{js,ts,jsx,tsx}  (Pages Router)
        # - app/api/**/route.{js,ts}        (App Router)
        api_patterns = [
            root / "pages" / "api",
            root / "src" / "pages" / "api",
            root / "app" / "api",
            root / "src" / "app" / "api",
        ]

        for api_dir in api_patterns:
            if not api_dir.exists():
                continue
            for ext in ("*.js", "*.ts", "*.jsx", "*.tsx"):
                for route_file in api_dir.rglob(ext):
                    rel_path = str(route_file.relative_to(root))
                    try:
                        content = route_file.read_text(errors="ignore")

                        # Skip if it has auth checks
                        if _AUTH_REGEX.search(content):
                            continue

                        # Skip health/status endpoints
                        if any(s in rel_path.lower() for s in ("health", "status", "ping", "webhook")):
                            continue

                        findings.append(Finding(
                            title=f"Unprotected API Route: {rel_path}",
                            severity=Severity.HIGH,
                            category=Category.FRAMEWORK_SPECIFIC,
                            file=rel_path,
                            description=(
                                f"API route '{rel_path}' has no authentication check. "
                                f"Any user (or bot) can call this endpoint. This is a common "
                                f"mistake in vibe-coded Next.js apps."
                            ),
                            remediation=(
                                f"Add authentication to this route using getServerSession(), "
                                f"NextAuth, Clerk, or your auth library. Return 401 for "
                                f"unauthenticated requests."
                            ),
                            ai_prompt=(
                                f"Add authentication to {rel_path}. Use getServerSession or equivalent "
                                f"to verify the user is logged in before processing the request."
                            ),
                            evidence="No auth pattern found (getServerSession, verifyToken, withAuth, etc.)",
                            tool="nextjs-checker",
                        ))
                    except Exception as e:
                        logger.debug("Failed to read %s: %s", route_file, e)

        return findings

    def _check_server_actions(self, root: Path) -> List[Finding]:
        """Check server actions for missing input validation."""
        findings = []

        # Server actions can be in any .ts/.tsx/.js/.jsx file
        src_dirs = [root / "app", root / "src" / "app", root / "actions", root / "src" / "actions"]

        for src_dir in src_dirs:
            if not src_dir.exists():
                continue
            for ext in ("*.ts", "*.tsx", "*.js", "*.jsx"):
                for file_path in src_dir.rglob(ext):
                    try:
                        content = file_path.read_text(errors="ignore")

                        # Check if this file contains server actions
                        if not _SERVER_ACTION_RE.search(content):
                            continue

                        rel_path = str(file_path.relative_to(root))

                        # Find exported async functions after "use server"
                        # These are server actions
                        if not _VALIDATION_REGEX.search(content):
                            findings.append(Finding(
                                title=f"Unvalidated Server Action: {rel_path}",
                                severity=Severity.HIGH,
                                category=Category.FRAMEWORK_SPECIFIC,
                                file=rel_path,
                                description=(
                                    f"Server action in '{rel_path}' contains 'use server' but has "
                                    f"no input validation (no zod .parse(), joi.validate(), etc.). "
                                    f"Server actions receive raw user input from the client."
                                ),
                                remediation=(
                                    f"Add input validation using zod, yup, or joi. Parse and validate "
                                    f"all inputs before processing."
                                ),
                                ai_prompt=(
                                    f"Add zod schema validation to the server action in {rel_path}. "
                                    f"Define a schema for the expected input shape and call .parse() on it."
                                ),
                                evidence="'use server' directive found but no validation pattern detected",
                                tool="nextjs-checker",
                            ))
                    except Exception as e:
                        logger.debug("Failed to read %s: %s", file_path, e)

        return findings

    def _check_dangerous_html(self, root: Path) -> List[Finding]:
        """Check for dangerouslySetInnerHTML usage."""
        findings = []

        for ext in ("*.jsx", "*.tsx", "*.js", "*.ts"):
            for file_path in root.rglob(ext):
                rel = file_path.relative_to(root)
                if any(p in str(rel) for p in ("node_modules", ".next", ".venv")):
                    continue
                try:
                    content = file_path.read_text(errors="ignore")
                    for i, line in enumerate(content.splitlines(), 1):
                        if "dangerouslySetInnerHTML" in line:
                            # Check if DOMPurify is used in the file
                            if "DOMPurify" in content or "sanitize" in content.lower():
                                continue  # sanitized — OK

                            findings.append(Finding(
                                title=f"Unsanitized dangerouslySetInnerHTML",
                                severity=Severity.HIGH,
                                category=Category.FRAMEWORK_SPECIFIC,
                                file=str(rel),
                                line=i,
                                description=(
                                    f"dangerouslySetInnerHTML is used without DOMPurify or sanitization. "
                                    f"This enables XSS if the content comes from user input or an LLM."
                                ),
                                remediation=(
                                    f"Install DOMPurify and sanitize the HTML: "
                                    f"dangerouslySetInnerHTML={{{{ __html: DOMPurify.sanitize(content) }}}}"
                                ),
                                ai_prompt=(
                                    f"Add DOMPurify sanitization to the dangerouslySetInnerHTML in "
                                    f"{rel} at line {i}."
                                ),
                                evidence=f"Line {i}: {line.strip()[:100]}",
                                tool="nextjs-checker",
                            ))
                            break  # one per file is enough
                except Exception:
                    pass

        return findings
