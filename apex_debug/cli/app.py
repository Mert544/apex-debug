"""Apex Debug CLI — the command-line entry point.

Usage:
    apex analyze <path>              Static analysis
    apex analyze <path> --output markdown   Export as Markdown
    apex analyze <path> --output sarif      Export as SARIF for GitHub
    apex analyze <path> --output json       Export as JSON
    apex watch <path>                Watch files and re-analyze on change
    apex shell                       Interactive debug shell
    apex patterns                    List available patterns
    apex kb stats                    Knowledge base statistics
    apex info                        Show version and config

Examples:
    apex analyze app.py
    apex analyze src/ --output sarif
    apex watch src/ --interval 1.5
    apex shell
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from apex_debug.core.finding import Severity
from apex_debug.core.history import Step, StepKind
from apex_debug.core.session import DebugSession, SessionConfig
from apex_debug.engine.knowledge import KnowledgeBase
from apex_debug.engine.runner import (
    get_all_patterns,
    get_categories,
    run_pattern_engine,
)
from apex_debug.parsers.registry import ParserRegistry

app = typer.Typer(
    name="apex",
    help="Apex Debug Agent — AST-first static analysis",
    no_args_is_help=True,
)

console = Console()
SEVERITY_COLORS = {
    5: "bold red",
    4: "red",
    3: "yellow",
    2: "dim cyan",
    1: "dim",
}


def _load_config(target: Path) -> SessionConfig:
    from apex_debug.config import find_project_root, load_config, apply_config_to_session

    project_root = find_project_root(target)
    cfg = load_config(project_root)

    session_cfg = SessionConfig(target=target.resolve())
    apply_config_to_session(cfg, session_cfg)
    return session_cfg


def _print_header(session: DebugSession) -> None:
    console.print()
    console.print(
        Panel.fit(
            f"[bold]Apex Debug[/] v0.2.0 — Session {session.id}",
            subtitle=f"Target: {session.config.target}",
        )
    )


def _print_findings_table(session: DebugSession) -> None:
    if not session.findings:
        console.print(Panel("[green]No issues found.[/]", style="green"))
        return

    table = Table(title=f"Findings ({len(session.findings)})")
    table.add_column("Severity", style="bold")
    table.add_column("Category")
    table.add_column("Title")
    table.add_column("Location")
    table.add_column("Message")

    for f in session.findings:
        sev_color = SEVERITY_COLORS.get(f.severity.value, "white")
        table.add_row(
            f"[{sev_color}]{f.severity.label}[/]",
            f.category,
            f.title,
            f.location_str(),
            f.message[:80],
        )

    console.print(table)


def _print_summary(session: DebugSession) -> None:
    counts = {sev.value: len(session.findings_by_severity(sev.name.lower())) for sev in Severity}
    parts = []
    for sev in Severity:
        n = counts[sev.value]
        if n > 0:
            color = SEVERITY_COLORS[sev.value]
            parts.append(f"[{color}]{n} {sev.name}[/]")

    parts.append(f"[dim]{session.finding_count} total[/]")
    console.print("  " + " · ".join(parts))
    console.print()


def _save_report(session: DebugSession, output: str, target: str) -> str:
    """Save findings in the requested output format. Returns the output path."""
    target_path = Path(target)
    base = target_path.stem if target_path.is_file() else "report"

    if output == "markdown":
        from apex_debug.reporter.markdown import save_report
        out = f"{base}.md"
        save_report(session.findings, out)
    elif output == "sarif":
        from apex_debug.reporter.sarif import save_sarif
        out = f"{base}.sarif"
        save_sarif(session.findings, out)
        console.print(f"  [dim]Upload to GitHub: security / code-scanning / upload-sarif[/]")
    elif output == "json":
        from apex_debug.reporter.json_reporter import save_json
        out = f"{base}.json"
        save_json(session.findings, out)
    elif output == "html":
        from apex_debug.reporter.html_reporter import save_html
        out = f"{base}.html"
        save_html(session.findings, out)
    else:
        console.print(f"[red]Unknown output format: {output}[/]")
        raise typer.Exit(1)

    return out


@app.command()
def analyze(
    path: str = typer.Argument(..., help="File or directory to analyze"),
    severity: str = typer.Option("low", "--min-severity", help="Minimum severity: info, low, medium, high, critical"),
    category: Optional[str] = typer.Option(None, "--category", help="Filter by category: security, correctness, performance, style"),
    output: Optional[str] = typer.Option(None, "--output", help="Export report: markdown, sarif, json, html"),
    plugins: Optional[str] = typer.Option(None, "--plugins", help="Custom plugin directory for additional patterns"),
    no_kb: bool = typer.Option(False, "--no-kb", help="Skip knowledge base recording"),
    baseline: Optional[str] = typer.Option(None, "--baseline", help="Filter out known issues from baseline file"),
    save_baseline: Optional[str] = typer.Option(None, "--save-baseline", help="Save current findings as baseline"),
    diff: bool = typer.Option(False, "--diff", help="Only analyze lines changed since last git commit"),
    diff_staged: bool = typer.Option(False, "--diff-staged", help="Only analyze staged changes"),
    fix_dry_run: bool = typer.Option(False, "--fix-dry-run", help="Show auto-fix suggestions without applying"),
    fix: bool = typer.Option(False, "--fix", help="Apply safe auto-fixes to source files"),
    exit_code: bool = typer.Option(False, "--exit-code", help="Exit with non-zero code if findings >= --min-severity"),
    exclude: Optional[str] = typer.Option(None, "--exclude", help="Comma-separated list of dir/file patterns to exclude"),
) -> None:
    """Run static analysis on a file or directory."""
    target = Path(path)
    if not target.exists():
        console.print(f"[red]Error: '{path}' does not exist.[/]")
        raise typer.Exit(1)

    config = _load_config(target)
    config.min_severity = severity
    if category:
        for cat in ("security", "correctness", "performance", "style"):
            setattr(config, f"patterns_{cat}", cat == category)
    if plugins:
        config.plugin_dir = plugins

    session = DebugSession(config=config)
    parser = ParserRegistry()

    _print_header(session)

    exclude_set = set(x.strip() for x in exclude.split(",")) if exclude else None
    files = parser.discover_files(target, exclude=exclude_set)
    console.print(f"Analyzing {len(files)} file(s)...")

    python_files = []
    other_files: list[tuple[Path, str, str]] = []

    for filepath in files:
        source = parser.read_file(filepath)
        if source is None:
            session.add_step(Step(kind=StepKind.ERROR, message=f"Cannot read: {filepath}"))
            continue

        language = parser.detect_language(filepath)
        if language == "python":
            python_files.append((filepath, source))
        else:
            other_files.append((filepath, source, language))

    if python_files:
        if len(python_files) == 1:
            run_pattern_engine(session, python_files[0][0], python_files[0][1])
        else:
            from apex_debug.engine.runner import run_pattern_engine_parallel
            console.print(f"  [dim]Parallel analysis with {min(4, len(python_files))} workers[/]")
            run_pattern_engine_parallel(session, python_files, max_workers=min(4, len(python_files)))

    # Multi-language regex fallback analysis
    if other_files:
        from apex_debug.parsers.multilang import analyze_non_python
        for filepath, source, language in other_files:
            findings = analyze_non_python(language, source, str(filepath))
            for f in findings:
                session.add_finding(f)
            if findings:
                session.add_step(
                    Step(kind=StepKind.ANALYZE, message=f"Analyzed {filepath.name} ({language}) — {len(findings)} finding(s)")
                )

    session.finish()

    # --- Baseline filtering ---
    if baseline:
        from apex_debug.engine.baseline import BaselineManager
        bm = BaselineManager(baseline)
        suppressed = bm.get_suppressed_count(session.findings)
        session.findings = bm.filter_new(session.findings)
        if suppressed > 0:
            console.print(f"  [dim]Baseline suppressed {suppressed} known issue(s)[/]")

    # --- Git diff filtering ---
    if diff or diff_staged:
        from apex_debug.engine.gitdiff import get_git_diff, filter_findings_to_diff
        hunks = get_git_diff(staged=diff_staged)
        if hunks:
            before = len(session.findings)
            session.findings = filter_findings_to_diff(session.findings, hunks)
            console.print(f"  [dim]Git diff: {before} -> {len(session.findings)} finding(s) in changed lines[/]")
        else:
            console.print("  [dim]No git diff changes detected[/]")

    # --- Auto-fix ---
    if fix or fix_dry_run:
        from apex_debug.engine.autofix import AutoFixer
        fixer = AutoFixer()
        total_fixes = 0
        for filepath, _ in python_files:
            suggestions, new_source = fixer.apply_to_file(filepath, dry_run=fix_dry_run)
            if suggestions:
                action = "Would fix" if fix_dry_run else "Fixed"
                console.print(f"  [yellow]{action} {len(suggestions)} issue(s) in {filepath.name}[/]")
                total_fixes += len(suggestions)
        if total_fixes == 0:
            console.print("  [dim]No auto-fixable issues found[/]")
        elif fix_dry_run:
            console.print(f"  [yellow]Run with --fix to apply {total_fixes} suggestion(s)[/]")

    # --- Save baseline ---
    if save_baseline:
        from apex_debug.engine.baseline import BaselineManager
        bm = BaselineManager(save_baseline)
        bm.save(session.findings)
        console.print(f"  [green]Baseline saved: {save_baseline}[/]")

    if not no_kb and session.findings:
        kb = KnowledgeBase()
        new_count = 0
        for f in session.findings:
            if kb.add(f):
                new_count += 1
        if new_count > 0:
            console.print(f"  [dim]KB: {new_count} new, {len(session.findings) - new_count} known[/]")

    if output:
        out_path = _save_report(session, output, path)
        console.print(f"  [green]Report saved: {out_path}[/]")

    _print_findings_table(session)
    _print_summary(session)

    # --- Exit code based on findings ---
    if exit_code and session.findings:
        max_severity = max(f.severity.value for f in session.findings)
        # Exit with the highest severity level found (1-5)
        raise typer.Exit(max_severity)


@app.command()
def shell() -> None:
    """Launch the interactive debug shell."""
    from apex_debug.cli.interactive import run_interactive_shell
    run_interactive_shell()


@app.command()
def watch(
    path: str = typer.Argument(".", help="Directory or file to watch"),
    interval: float = typer.Option(2.0, "--interval", "-i", help="Polling interval in seconds"),
) -> None:
    """Watch files for changes and re-analyze automatically."""
    from apex_debug.engine.watcher import FileWatcher

    target = Path(path).resolve()
    if not target.exists():
        console.print(f"[red]Error: '{path}' does not exist.[/]")
        raise typer.Exit(1)

    config = _load_config(target)
    console.print(f"[bold]Watching[/] {target} (interval: {interval}s)")
    console.print("[dim]Press Ctrl+C to stop[/]")
    console.print()

    def on_change(added: list, removed: list) -> None:
        if added:
            console.print(f"[red]+ {len(added)} new issue(s)[/]")
            for f in added:
                sev_color = SEVERITY_COLORS.get(f.severity.value, "white")
                console.print(
                    f"  [{sev_color}]{f.severity.name:8}[/] {f.file}:{f.line} — {f.title}"
                )
        if removed:
            console.print(f"[green]- {len(removed)} resolved issue(s)[/]")
        console.print()

    watcher = FileWatcher(target, interval=interval, on_findings=on_change, session_config=config)

    try:
        watcher.start()
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping watcher...[/]")
    finally:
        watcher.stop()


@app.command()
def patterns() -> None:
    """List available detection patterns."""
    table = Table(title="Available Patterns")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Severity")
    table.add_column("Description")

    for p in get_all_patterns():
        sev_color = SEVERITY_COLORS.get(p.severity.value, "white")
        table.add_row(
            p.name,
            p.category,
            f"[{sev_color}]{p.severity.name}[/]",
            p.description,
        )

    console.print(table)
    cats = get_categories()
    for cat, pats in cats.items():
        console.print(f"  [bold]{cat}[/]: {len(pats)} patterns")
    console.print(f"\n  [dim]{len(get_all_patterns())} patterns total[/]")


@app.command()
def plugins(
    action: str = typer.Argument("list", help="Action: list, init-example"),
    directory: str = typer.Option(".apex-debug/plugins", "--dir", help="Plugin directory"),
) -> None:
    """Manage custom pattern plugins."""
    from apex_debug.engine.plugins import PluginLoader

    if action == "list":
        loader = PluginLoader()
        custom = loader.load_from_directory(directory)
        if custom:
            console.print(f"[bold]Custom plugins in {directory}:[/]")
            for p in custom:
                sev_color = SEVERITY_COLORS.get(p.severity.value, "white")
                console.print(
                    f"  [{sev_color}]{p.severity.name}[/] {p.name} ({p.category})"
                )
        else:
            console.print(f"[dim]No custom plugins found in {directory}[/]")
            console.print("Run 'apex plugins init-example' to create an example plugin.")

    elif action == "init-example":
        path = PluginLoader.create_example_plugin(directory)
        console.print(f"[green]Example plugin created: {path}[/]")
        console.print("[dim]Edit the file and run with --plugins {directory}[/]")

    else:
        console.print(f"[red]Unknown action: {action}. Use 'list' or 'init-example'[/]")


@app.command()
def kb(
    command: str = typer.Argument("stats", help="Knowledge base command: stats, unresolved, clear"),
) -> None:
    """Manage the knowledge base."""
    from apex_debug.engine.knowledge import KnowledgeBase

    kb = KnowledgeBase()

    if command == "stats":
        stats = kb.get_stats()
        console.print(Panel("[bold]Knowledge Base[/]"))
        console.print(f"  Total findings:    {stats['total']}")
        console.print(f"  Resolved:          {stats['resolved']}")
        console.print(f"  Unresolved:        {stats['unresolved']}")
        console.print("  By category:")
        for cat, count in stats["by_category"].items():
            console.print(f"    {cat}: {count}")

    elif command == "unresolved":
        items = kb.get_unresolved()
        if not items:
            console.print("[green]All known findings resolved.[/]")
            return
        table = Table(title=f"Unresolved Findings ({len(items)})")
        table.add_column("Severity")
        table.add_column("Category")
        table.add_column("Title")
        table.add_column("Seen")
        for item in items:
            sev = Severity(item["severity"])
            sev_color = SEVERITY_COLORS.get(sev.value, "white")
            table.add_row(
                f"[{sev_color}]{sev.name}[/]",
                item["category"],
                item["title"],
                str(item["seen_count"]),
            )
        console.print(table)

    elif command == "clear":
        import sqlite3
        conn = sqlite3.connect(str(kb._db_path))
        conn.execute("DELETE FROM findings")
        conn.commit()
        conn.close()
        console.print("[yellow]Knowledge base cleared.[/]")

    else:
        console.print(f"[red]Unknown kb command: {command}. Use: stats, unresolved, clear[/]")


@app.command()
def info() -> None:
    """Show Apex Debug version and configuration."""
    from apex_debug import __version__
    from apex_debug.engine.runner import get_all_patterns

    console.print(Panel(f"[bold]Apex Debug[/] v{__version__}"))
    console.print(f"  Patterns loaded: {len(get_all_patterns())}")
    console.print("  Modes: analyze, shell, patterns, kb")
    console.print("  Output: terminal, markdown, sarif, json")
    console.print("  Languages: Python (native AST), multi-language (regex fallback)")
    console.print("  Architecture: AST-first, zero external API calls")
    console.print("")
    console.print("  [dim]Core: Static analysis[/] [green]done[/]")
    console.print("  [dim]Patterns + Reporting + KB[/] [green]done[/]")
    console.print("  [dim]Interactive shell + VS Code[/] [green]done[/]")
    console.print("")
    console.print("  [dim]100% free. No API keys. No cloud calls.[/]")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
