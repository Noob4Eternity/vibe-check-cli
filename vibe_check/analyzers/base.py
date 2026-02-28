"""Base analyzer — SHARED contract, frozen at minute 0."""

from __future__ import annotations

import abc
from typing import List

from vibe_check.models.finding import Finding


class BaseAnalyzer(abc.ABC):
    """Abstract base class for all vibe-check analyzers."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Human-readable analyzer name (e.g. 'secrets', 'sast')."""
        ...

    @property
    @abc.abstractmethod
    def tier(self) -> int:
        """Execution tier / layer number (1-5). Lower = runs first conceptually."""
        ...

    @abc.abstractmethod
    async def analyze(self, repo_path: str, config: dict | None = None) -> List[Finding]:
        """Run analysis on the repo at *repo_path* and return findings.

        Args:
            repo_path: Absolute path to the repository root.
            config: Optional config dict (from .vibecheck.yml or CLI flags).

        Returns:
            List of Finding instances.
        """
        ...

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r} tier={self.tier}>"
