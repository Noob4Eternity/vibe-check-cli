"""Secrets analyzer (P2) — detect-secrets integration."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from typing import List

from vibe_check.analyzers.base import BaseAnalyzer
from vibe_check.models.finding import Category, Finding, Severity

logger = logging.getLogger("vibe_check.secrets")

# detect-secrets "type" strings that indicate well-known credential patterns
_KNOWN_PATTERN_TYPES = frozenset({
    "AWSKeyDetector",
    "ArtifactoryDetector",
    "AzureStorageKeyDetector",
    "CloudantDetector",
    "GitHubTokenDetector",
    "DiscordBotTokenDetector",
    "HexHighEntropyString",            # often API keys
    "IbmCloudIamDetector",
    "IbmCosHmacDetector",
    "JwtTokenDetector",
    "MailchimpDetector",
    "NpmDetector",
    "SendGridDetector",
    "SlackDetector",
    "SoftlayerDetector",
    "SquareOAuthDetector",
    "StripeDetector",
    "TwilioKeyDetector",
    "PrivateKeyDetector",
})

# File patterns to ALWAYS exclude from secrets scanning.
# These produce massive false positives (lock file hashes, placeholder keys, etc.)
_SECRETS_EXCLUDE_PATTERNS = [
    # Lock files — contain integrity hashes (SHA-512 base64), NOT secrets
    r"pnpm-lock\.yaml$",
    r"package-lock\.json$",
    r"yarn\.lock$",
    r"poetry\.lock$",
    r"Pipfile\.lock$",
    r"composer\.lock$",
    # Template / example files — contain placeholder credentials
    r"\.example$",
    r"\.sample$",
    r"\.template$",
    r"\.env\.example$",
    r"\.env\.sample$",
    # Documentation — may reference key formats in examples
    r"\.md$",
    r"\.rst$",
    r"\.txt$",
]


def _severity_for(secret_type: str) -> Severity:
    """Map a detect-secrets type to a severity level.

    Known credential patterns (AWS keys, GitHub tokens, etc.) → CRITICAL
    High-entropy strings (likely random secrets)              → HIGH
    """
    if secret_type in _KNOWN_PATTERN_TYPES:
        return Severity.CRITICAL
    # Base64/Hex high-entropy strings default to HIGH
    return Severity.HIGH


def _title_for(secret_type: str) -> str:
    """Human-readable title from the detector class name."""
    # e.g. "AWSKeyDetector" → "AWS Key Detected"
    name = secret_type.replace("Detector", "").replace("Hmac", " HMAC")
    # Insert spaces before uppercase letters for CamelCase splitting
    spaced = ""
    for i, ch in enumerate(name):
        if ch.isupper() and i > 0 and not name[i - 1].isupper():
            spaced += " "
        spaced += ch
    return f"{spaced.strip()} Detected"


class SecretsAnalyzer(BaseAnalyzer):
    """Scans a repository for hard-coded secrets using *detect-secrets*."""

    @property
    def name(self) -> str:
        return "secrets"

    @property
    def tier(self) -> int:
        return 1

    async def analyze(
        self, repo_path: str, config: dict | None = None
    ) -> List[Finding]:
        # ------------------------------------------------------------------
        # 1. Check that detect-secrets is installed
        # ------------------------------------------------------------------
        if shutil.which("detect-secrets") is None:
            logger.warning(
                "detect-secrets is not installed — skipping secrets scan. "
                "Install with: pip install detect-secrets"
            )
            return []

        # ------------------------------------------------------------------
        # 2. Run detect-secrets scan as async subprocess
        # ------------------------------------------------------------------
        from vibe_check.utils.git_utils import is_git_repo

        # Layer 1: In a git repo, omit --all-files so detect-secrets
        #          only scans git-tracked files (respects .gitignore).
        # Layer 2: For non-git dirs, use --all-files but pass the
        #          hardcoded exclude regex as a safety net.
        git_repo = is_git_repo(repo_path)

        if git_repo:
            cmd = ["detect-secrets", "scan"]
        else:
            cmd = ["detect-secrets", "scan", "--all-files"]

        # Build the exclude regex: directory excludes + file-pattern excludes
        import re
        exclude_parts = []

        # Add directory excludes from config
        if config and config.get("exclude"):
            escaped = [re.escape(x.rstrip("/")) for x in config["exclude"]]
            exclude_parts.extend([f"^{e}/" for e in escaped])

        # Always add file-pattern excludes (lock files, templates, docs)
        exclude_parts.extend(_SECRETS_EXCLUDE_PATTERNS)

        if exclude_parts:
            regex = "|".join(exclude_parts)
            cmd.extend(["--exclude-files", regex])

        cmd.append(".")
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=repo_path,
            )
            stdout, stderr = await proc.communicate()
        except Exception as exc:
            logger.warning("detect-secrets failed to launch: %s", exc)
            return []

        if proc.returncode != 0:
            logger.warning(
                "detect-secrets exited with code %d: %s",
                proc.returncode,
                stderr.decode(errors="replace").strip(),
            )
            # Still try to parse stdout — detect-secrets sometimes returns
            # non-zero but still emits valid JSON.

        # ------------------------------------------------------------------
        # 3. Parse JSON output
        # ------------------------------------------------------------------
        try:
            data = json.loads(stdout.decode(errors="replace"))
        except json.JSONDecodeError as exc:
            logger.warning("Could not parse detect-secrets output: %s", exc)
            return []

        results: dict = data.get("results", {})

        # ------------------------------------------------------------------
        # 4. Convert each detected secret into a Finding
        # ------------------------------------------------------------------
        findings: List[Finding] = []
        for filepath, secret_list in results.items():
            for secret in secret_list:
                secret_type: str = secret.get("type", "Unknown")
                line_number: int = secret.get("line_number", 0)
                severity = _severity_for(secret_type)
                title = _title_for(secret_type)

                findings.append(
                    Finding(
                        title=title,
                        severity=severity,
                        category=Category.SECRET,
                        file=filepath,
                        line=line_number,
                        description=(
                            f"A potential secret ({secret_type}) was detected "
                            f"in {filepath} at line {line_number}."
                        ),
                        remediation=(
                            "Move this secret to an environment variable or a "
                            "secrets manager (e.g. AWS Secrets Manager, "
                            "HashiCorp Vault). Rotate the compromised "
                            "credential immediately."
                        ),
                        ai_prompt=(
                            f"Review {filepath}:{line_number} for a "
                            f"hard-coded {secret_type}. Suggest how to "
                            "externalize it safely."
                        ),
                        evidence=secret.get("hashed_secret", ""),
                        tool="detect-secrets",
                    )
                )

        logger.info("Secrets scan complete — %d finding(s)", len(findings))
        return findings
