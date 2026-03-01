"""Report — Rich terminal output for scan results."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from vibe_check.models.finding import Severity
from vibe_check.models.result import ScanResult

console = Console()

# ── Helpers ─────────────────────────────────────────────────────────

_SEV_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold bright_red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold blue",
    Severity.INFO: "dim",
}

_SEV_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

_CAT_EMOJI = {
    "secrets": "🔑",
    "dependencies": "📦",
    "sast": "🛡️",
    "compliance": "📋",
    "prompt_injection": "💉",
    "cost_efficiency": "💰",
    "code_quality": "🧹",
    "iac_security": "☁️",
    "llm_review": "🤖",
}


def _score_color(score: float) -> str:
    if score >= 80:
        return "bold green"
    if score >= 60:
        return "bold yellow"
    return "bold red"


# ── Main Renderer ───────────────────────────────────────────────────

def render_terminal(result: ScanResult) -> None:
    """Print a beautiful Rich report to the terminal."""
    console.print()

    # ── Header Panel ────────────────────────────────────────────
    header_lines = [
        f"[bold]Repository:[/bold]  {result.repo_path}",
        f"[bold]Files:[/bold]       {result.files_scanned}",
        f"[bold]Languages:[/bold]   {', '.join(result.languages_detected) or 'N/A'}",
        f"[bold]Scan Time:[/bold]   {result.scan_time:.1f}s",
    ]
    if result.tokens_used:
        header_lines.append(f"[bold]LLM Tokens:[/bold]  {result.tokens_used}")
    console.print(
        Panel(
            "\n".join(header_lines),
            title="[bold cyan]🎵 VibeAudit[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    # ── Score Display ───────────────────────────────────────────
    style = _score_color(result.score)
    score_text = Text()
    score_text.append(f"  {result.score:.0f}", style=style)
    score_text.append(f" / 100  ", style="dim")
    score_text.append(f"  {result.grade}  ", style=style)
    score_text.append(f"  {result.verdict}", style=style)

    console.print(
        Panel(score_text, title="[bold]Score[/bold]", border_style="white", box=box.HEAVY)
    )

    # ── Category Scores Table ───────────────────────────────────
    if result.category_scores:
        table = Table(
            title="Category Breakdown",
            box=box.SIMPLE_HEAVY,
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Category", style="bold")
        table.add_column("Score", justify="right")
        table.add_column("Bar", min_width=12)
        table.add_column("Findings", justify="right")

        # Count findings per group
        from vibe_check.models.finding import CATEGORY_GROUP

        group_counts: dict[str, int] = {}
        for f in result.findings:
            g = CATEGORY_GROUP.get(f.category, "code_quality")
            group_counts[g] = group_counts.get(g, 0) + 1

        for cat, sc in sorted(result.category_scores.items(), key=lambda x: x[1]):
            emoji = _CAT_EMOJI.get(cat, "📌")
            filled = int(sc // 10)
            bar = "█" * filled + "░" * (10 - filled)
            bar_style = _score_color(sc)
            table.add_row(
                f"{emoji} {cat.replace('_', ' ').title()}",
                f"[{bar_style}]{sc:.0f}[/{bar_style}]",
                f"[{bar_style}]{bar}[/{bar_style}]",
                str(group_counts.get(cat, 0)),
            )
        console.print(table)

    # ── Critical & High Findings ────────────────────────────────
    critical_high = [
        f for f in result.findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    if critical_high:
        console.print()
        console.print("[bold red]🚨 Critical & High Findings[/bold red]")
        console.print()
        for f in critical_high:
            emoji = _SEV_EMOJI.get(f.severity, "⚪")
            sev_style = _SEV_STYLE.get(f.severity, "")
            loc = f"{f.file}:{f.line}" if f.file and f.line else (f.file or "—")
            content_lines = [
                f"[bold]File:[/bold] {loc}",
                f"[bold]Tool:[/bold] {f.tool}",
                f"[bold]Description:[/bold] {f.description}",
                f"[bold]Remediation:[/bold] {f.remediation}",
            ]
            if f.ai_prompt:
                content_lines.append(f"[bold]AI Prompt:[/bold] {f.ai_prompt}")
            if f.cwe:
                content_lines.append(f"[bold]CWE:[/bold] {f.cwe}")
            if f.compliance_ref:
                content_lines.append(f"[bold]Compliance:[/bold] {f.compliance_ref}")

            console.print(
                Panel(
                    "\n".join(content_lines),
                    title=f"{emoji} [{sev_style}]{f.title}[/{sev_style}]",
                    border_style="red" if f.severity == Severity.CRITICAL else "yellow",
                    box=box.ROUNDED,
                )
            )

    # ── Summary Counts ──────────────────────────────────────────
    counts: dict[str, int] = {}
    for f in result.findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    if counts:
        summary = Text("  ")
        for sev_name in ["critical", "high", "medium", "low", "info"]:
            if sev_name in counts:
                sev = Severity(sev_name)
                emoji = _SEV_EMOJI.get(sev, "⚪")
                summary.append(f"{emoji} {sev_name.upper()}: {counts[sev_name]}  ")
        console.print(
            Panel(summary, title="[bold]Finding Summary[/bold]", border_style="dim")
        )

    # ── Footer ──────────────────────────────────────────────────
    if result.tokens_used:
        console.print(
            f"\n[dim]💰 Total LLM tokens used: {result.tokens_used} "
            f"(~${result.tokens_used * 0.000003:.4f} at GPT-4o rates)[/dim]"
        )
    console.print()
