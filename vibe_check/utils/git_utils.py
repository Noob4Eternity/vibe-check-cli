"""Git-aware helpers for file discovery.

Provides Layer 1 of the exclude strategy: if the scan target lives inside
a Git repository we defer to `git ls-files` so that everything listed in
`.gitignore` (node_modules, .venv, dist, …) is automatically skipped.
"""

from __future__ import annotations

import logging
import os
import subprocess
from typing import List, Optional

logger = logging.getLogger("vibe_check.git_utils")


def is_git_repo(path: str) -> bool:
    """Return *True* if *path* is inside a Git work-tree."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=path,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0 and result.stdout.strip() == "true"
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def get_git_tracked_files(
    repo_path: str,
    extensions: Optional[List[str]] = None,
) -> List[str]:
    """Return a list of git-tracked file paths (relative to *repo_path*).

    Parameters
    ----------
    repo_path:
        Root of the repository to query.
    extensions:
        If provided, only return files whose extension (with leading dot)
        is in this list.  e.g. ``[".py"]`` to get only Python files.
    """
    try:
        result = subprocess.run(
            ["git", "ls-files"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            logger.warning("git ls-files failed: %s", result.stderr.strip())
            return []
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("git ls-files could not run: %s", exc)
        return []

    files = [f for f in result.stdout.splitlines() if f.strip()]

    if extensions:
        ext_set = set(extensions)
        files = [f for f in files if os.path.splitext(f)[1].lower() in ext_set]

    return files
