"""Dry-run integration test — exercises all analyzers against test fixtures (no LLM)."""

import asyncio
import os
import sys

# Ensure project root is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vibe_audit.analyzers.compliance import ComplianceAnalyzer
from vibe_audit.analyzers.prompt_injection import PromptInjectionAnalyzer
from vibe_audit.analyzers.llm_summarizer import LLMSummarizer
from vibe_audit.analyzers.secrets import SecretsAnalyzer
from vibe_audit.analyzers.sast import SASTAnalyzer
from vibe_audit.analyzers.dependencies import DependencyAnalyzer
from vibe_audit.core.orchestrator import Orchestrator
from vibe_audit.core.scorer import calculate_composite, get_grade, get_verdict

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")

REPOS = [
    "vulnerable-flask-app",
    "vulnerable-nextjs-app",
    "vulnerable-fastapi-llm-app",
]


async def test_single_repo(repo_name: str):
    """Run all analyzers on one fixture repo and print results."""
    repo_path = os.path.join(FIXTURES_DIR, repo_name)
    print(f"\n{'='*60}")
    print(f"  SCANNING: {repo_name}")
    print(f"{'='*60}")

    # Initialize all analyzers WITHOUT LLM
    analyzers = [
        SecretsAnalyzer(),
        SASTAnalyzer(),
        DependencyAnalyzer(),
        ComplianceAnalyzer(),          # no llm_client = semgrep + AST only
        PromptInjectionAnalyzer(),     # no llm_client = semgrep only
        LLMSummarizer(),               # no llm_client = skipped
    ]

    orchestrator = Orchestrator(analyzers=analyzers, timeout=30)
    result = await orchestrator.run(repo_path)

    # Print results
    print(f"\n  Score: {result.score:.1f}/100  Grade: {result.grade}  Verdict: {result.verdict}")
    print(f"  Files scanned: {result.files_scanned}")
    print(f"  Languages: {', '.join(result.languages_detected)}")
    print(f"  Scan time: {result.scan_time:.2f}s")
    print(f"  Total findings: {len(result.findings)}")
    print(f"  Tokens used: {result.tokens_used}")

    if result.category_scores:
        print(f"\n  Category Scores:")
        for cat, score in sorted(result.category_scores.items(), key=lambda x: x[1]):
            print(f"    {cat:25s} {score:.0f}/100")

    if result.findings:
        print(f"\n  Findings by severity:")
        sev_counts = {}
        for f in result.findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in sev_counts:
                print(f"    {sev.upper():10s} {sev_counts[sev]}")

        print(f"\n  Findings by analyzer:")
        tool_counts = {}
        for f in result.findings:
            tool_counts[f.tool] = tool_counts.get(f.tool, 0) + 1
        for tool, count in sorted(tool_counts.items()):
            print(f"    {tool:25s} {count}")

        print(f"\n  All findings:")
        for f in result.findings:
            loc = f"{f.file}:{f.line}" if f.file and f.line else (f.file or "—")
            print(f"    [{f.severity.value.upper():8s}] [{f.tool:20s}] {f.title}")
            print(f"             @ {loc}")
            if f.description:
                print(f"             {f.description[:120]}")
            print()

    return result


async def main():
    print("VibeAudit Dry Run — Testing all analyzers against fixtures")
    print("(No LLM — deterministic phases only)\n")

    results = {}
    for repo in REPOS:
        repo_path = os.path.join(FIXTURES_DIR, repo)
        if not os.path.isdir(repo_path):
            print(f"SKIP: {repo} (not found)")
            continue
        results[repo] = await test_single_repo(repo)

    # Summary
    print(f"\n{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")
    for repo, result in results.items():
        print(f"  {repo:35s} Score: {result.score:.0f}  Grade: {result.grade}  Findings: {len(result.findings)}")


if __name__ == "__main__":
    asyncio.run(main())
