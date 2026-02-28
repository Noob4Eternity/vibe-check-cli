"""Scorer — computes audit scores from findings."""

from __future__ import annotations

from typing import Dict, List, Tuple

from vibe_check.models.finding import Finding, Severity, CATEGORY_GROUP


# ── Weights per scoring group ──────────────────────────────────────
WEIGHTS: Dict[str, float] = {
    "secrets": 0.20,
    "dependencies": 0.20,
    "sast": 0.15,
    "compliance": 0.15,
    "prompt_injection": 0.10,
    "code_quality": 0.10,
    "iac_security": 0.05,
    "llm_review": 0.05,
}

# ── Penalty per severity level ─────────────────────────────────────
PENALTIES: Dict[Severity, int] = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 15,
    Severity.MEDIUM: 7,
    Severity.LOW: 3,
    Severity.INFO: 0,
}

# ── Grade thresholds ───────────────────────────────────────────────
_GRADE_TABLE: list[tuple[float, str]] = [
    (97, "A+"), (93, "A"), (90, "A-"),
    (87, "B+"), (83, "B"), (80, "B-"),
    (77, "C+"), (73, "C"), (70, "C-"),
    (67, "D+"), (60, "D"),
]


def calculate_category_score(findings: List[Finding]) -> float:
    """Score a single category: starts at 100, subtracts penalty * confidence."""
    score = 100.0
    for f in findings:
        penalty = PENALTIES.get(f.severity, 0)
        score -= penalty * f.confidence
    return max(score, 0.0)


def calculate_composite(all_findings: List[Finding]) -> Tuple[float, Dict[str, float]]:
    """Compute weighted composite score and per-category scores.

    Categories with zero findings are excluded from the weighted average
    so that unused analyzers don't inflate the score.
    """
    # Group findings by scoring group
    groups: Dict[str, List[Finding]] = {}
    for f in all_findings:
        group = CATEGORY_GROUP.get(f.category, "code_quality")
        groups.setdefault(group, []).append(f)

    # Calculate per-group scores
    category_scores: Dict[str, float] = {}
    for group, findings in groups.items():
        category_scores[group] = calculate_category_score(findings)

    # Give 100 to groups that were scanned but had no findings
    # (we only include groups that have a weight and had findings)
    if not category_scores:
        return 100.0, {}

    # Weighted average (only over groups that produced findings)
    total_weight = sum(WEIGHTS.get(g, 0.05) for g in category_scores)
    if total_weight == 0:
        return 100.0, category_scores

    composite = sum(
        category_scores[g] * WEIGHTS.get(g, 0.05) for g in category_scores
    ) / total_weight

    return round(composite, 1), category_scores


def get_grade(score: float) -> str:
    """Map numeric score to letter grade."""
    for threshold, grade in _GRADE_TABLE:
        if score >= threshold:
            return grade
    return "F"


def get_verdict(score: float) -> str:
    """Map numeric score to deployment verdict."""
    if score >= 80:
        return "PRODUCTION READY"
    if score >= 60:
        return "NEEDS REMEDIATION"
    if score >= 40:
        return "NOT PRODUCTION READY"
    return "CRITICAL — DO NOT DEPLOY"
