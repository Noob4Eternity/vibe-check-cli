"""CLI entrypoint for vibe-audit — built with Typer + Rich."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from vibe_audit import __version__

app = typer.Typer(
    name="vibe-audit",
    help="🎵 Audit vibe-coded repos for security, compliance & hallucinations.",
    add_completion=False,
)
console = Console()


def _get_analyzers(mode: str):
    """Build the list of analyzers based on mode."""
    from vibe_audit.analyzers.base import BaseAnalyzer

    analyzers: list[BaseAnalyzer] = []

    # Import each analyzer — skip gracefully if not yet implemented
    analyzer_classes = [
        ("vibe_audit.analyzers.secrets", "SecretsAnalyzer"),
        ("vibe_audit.analyzers.sast", "SASTAnalyzer"),
        ("vibe_audit.analyzers.dependencies", "DependencyAnalyzer"),
        ("vibe_audit.analyzers.hallucination", "HallucinationDetector"),
        ("vibe_audit.analyzers.nextjs", "NextJSAnalyzer"),
        ("vibe_audit.analyzers.compliance", "ComplianceAnalyzer"),
        ("vibe_audit.analyzers.prompt_injection", "PromptInjectionAnalyzer"),
        ("vibe_audit.analyzers.llm_summarizer", "LLMSummarizer"),
    ]

    if mode == "fast":
        # Fast mode: skip LLM-dependent analyzers (tiers 3-5)
        analyzer_classes = [
            ("vibe_audit.analyzers.secrets", "SecretsAnalyzer"),
            ("vibe_audit.analyzers.sast", "SASTAnalyzer"),
            ("vibe_audit.analyzers.dependencies", "DependencyAnalyzer"),
            ("vibe_audit.analyzers.hallucination", "HallucinationDetector"),
            ("vibe_audit.analyzers.nextjs", "NextJSAnalyzer"),
        ]

    for module_path, class_name in analyzer_classes:
        try:
            import importlib
            mod = importlib.import_module(module_path)
            cls = getattr(mod, class_name, None)
            if cls and not getattr(cls, "__abstractmethods__", None):
                analyzers.append(cls())
        except (ImportError, Exception):
            pass  # Analyzer not implemented yet — skip

    return analyzers


@app.command()
def scan(
    path: str = typer.Argument(".", help="Path to repository to scan"),
    mode: str = typer.Option("full", "--mode", "-m", help="Scan mode: fast or full"),
    format: str = typer.Option("terminal", "--format", "-f", help="Output: terminal, json, markdown"),
    exit_code: bool = typer.Option(False, "--exit-code", "-e", help="Exit 1 if score below threshold"),
    threshold: int = typer.Option(60, "--threshold", "-t", help="Score threshold for --exit-code"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter: critical,high,medium,low,info"),
):
    """🔍 Run a full vibe-audit scan on a repository."""
    repo_path = os.path.abspath(path)
    if not os.path.isdir(repo_path):
        console.print(f"[red]Error:[/red] {repo_path} is not a directory")
        raise typer.Exit(1)

    analyzers = _get_analyzers(mode)
    if not analyzers:
        console.print("[yellow]⚠ No analyzers available. Install analyzer dependencies or check implementations.[/yellow]")

    from vibe_audit.core.orchestrator import Orchestrator

    orchestrator = Orchestrator(analyzers=analyzers, config={"mode": mode})
    result = asyncio.run(orchestrator.run(repo_path))

    # Filter by severity if specified
    if severity:
        from vibe_audit.models.finding import Severity
        allowed = {s.strip().lower() for s in severity.split(",")}
        result.findings = [
            f for f in result.findings if f.severity.value in allowed
        ]

    # Output
    if format == "json":
        console.print(result.to_json())
    elif format == "markdown":
        console.print(result.to_markdown())
    else:
        from vibe_audit.core.report import render_terminal
        render_terminal(result)

    if exit_code and result.score < threshold:
        raise typer.Exit(1)


@app.command()
def score(
    path: str = typer.Argument(".", help="Path to repository"),
    exit_code: bool = typer.Option(False, "--exit-code", "-e", help="Exit 1 if failing"),
    threshold: int = typer.Option(60, "--threshold", "-t", help="Score threshold"),
):
    """📊 Quick score — just the number and grade."""
    repo_path = os.path.abspath(path)
    if not os.path.isdir(repo_path):
        console.print(f"[red]Error:[/red] {repo_path} is not a directory")
        raise typer.Exit(1)

    analyzers = _get_analyzers("full")
    from vibe_audit.core.orchestrator import Orchestrator

    orchestrator = Orchestrator(analyzers=analyzers)
    result = asyncio.run(orchestrator.run(repo_path))

    color = "green" if result.score >= 80 else ("yellow" if result.score >= 60 else "red")
    console.print(f"[{color} bold]{result.score:.0f}/100  {result.grade}  {result.verdict}[/{color} bold]")

    if exit_code and result.score < threshold:
        raise typer.Exit(1)


@app.command()
def init():
    """⚙️  Initialize vibe-audit config and git hook in the current repo."""
    config_path = Path(".vibeaudit.yml")
    if config_path.exists():
        console.print("[yellow]⚠ .vibeaudit.yml already exists[/yellow]")
    else:
        config_path.write_text(
            "# VibeAudit Configuration\n"
            "# See https://github.com/vibe-audit for docs\n\n"
            "mode: full\n"
            "threshold: 60\n"
            "severity_filter: []\n"
            "exclude:\n"
            "  - node_modules/\n"
            "  - .venv/\n"
            "  - __pycache__/\n\n"
            "# LLM settings (for compliance + prompt injection analysis)\n"
            "llm:\n"
            "  provider: openai  # openai or anthropic\n"
            "  token_budget: 5000\n"
        )
        console.print("[green]✅ Created .vibeaudit.yml[/green]")

    # Install pre-push hook
    hooks_dir = Path(".git/hooks")
    if hooks_dir.exists():
        hook_path = hooks_dir / "pre-push"
        hook_path.write_text(
            "#!/bin/sh\n"
            '# VibeAudit pre-push hook\n'
            'vibe-audit scan . --mode fast --severity critical,high --exit-code\n'
            'if [ $? -ne 0 ]; then\n'
            '  echo "❌ Push blocked by VibeAudit"\n'
            '  exit 1\n'
            'fi\n'
            'echo "✅ VibeAudit passed"\n'
        )
        hook_path.chmod(0o755)
        console.print("[green]✅ Installed pre-push git hook[/green]")
    else:
        console.print("[yellow]⚠ No .git/hooks directory found — skipping hook install[/yellow]")


def version_callback(value: bool):
    if value:
        console.print(f"vibe-audit {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", "-v", callback=version_callback, is_eager=True),
):
    """🎵 VibeAudit — Security auditor for vibe-coded repos."""
    pass

if __name__ == "__main__":
    app()
