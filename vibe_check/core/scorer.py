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
    "cost_efficiency": 0.10,
    "code_quality": 0.05,
    "iac_security": 0.025,
    "llm_review": 0.025,
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
    """Score a single category: starts at 100, subtracts penalty * confidence.

    Uses diminishing returns: after the first 3 findings, each additional
    finding's penalty is halved. This prevents a flood of medium-severity
    LLM findings from tanking a category to 0.
    """
    score = 100.0
    for i, f in enumerate(sorted(findings, key=lambda x: PENALTIES.get(x.severity, 0), reverse=True)):
        penalty = PENALTIES.get(f.severity, 0)
        # Diminishing returns: prevents a flood of medium-severity
        # findings from tanking a category to 0.
        #   Findings 1-3: full penalty
        #   Findings 4-5: half penalty
        #   Findings 6+:  quarter penalty
        if i >= 5:
            penalty *= 0.25
        elif i >= 3:
            penalty *= 0.5
        score -= penalty * f.confidence
    return max(score, 0.0)


def calculate_composite(
    all_findings: List[Finding],
    scanned_analyzers: List[str] | None = None,
) -> Tuple[float, Dict[str, float]]:
    """Compute weighted composite score and per-category scores.

    Categories whose analyzer ran but produced zero findings get 100.
    Categories whose analyzer did NOT run are excluded entirely.
    """
    # Map analyzer names to their scoring groups
    _ANALYZER_TO_GROUP = {
        "secrets": "secrets",
        "dependencies": "dependencies",
        "sast": "sast",
        "compliance": "compliance",
        "prompt_injection": "prompt_injection",
        "cost_efficiency": "cost_efficiency",
        "code_quality": "code_quality",
        "iac_security": "iac_security",
        "hallucination": "dependencies",
        "nextjs": "sast",
    }

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
    if scanned_analyzers:
        for analyzer_name in scanned_analyzers:
            group = _ANALYZER_TO_GROUP.get(analyzer_name)
            if group and group not in category_scores:
                category_scores[group] = 100.0

    if not category_scores:
        return 100.0, {}

    # Weighted average (only over groups present in category_scores)
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
