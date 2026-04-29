"""Interactive debug shell for Apex Debug.

Works with or without prompt_toolkit. Falls back to plain input() loop.

Commands:
    load <file>     Load a source file
    list / l        Show source around current line
    break <n> / b   Set breakpoint at line
    breaks          List breakpoints
    clear <n>       Clear breakpoint at line
    run / r         Run the current file (subprocess)
    analyze / a     Run static analysis on current file
    findings / f    Show findings from last analyze
    step / s        Advance current line by 1
    goto <n>        Jump to line
    help / h        Show help
    quit / q        Exit shell
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Optional

from apex_debug.core.finding import Finding
from apex_debug.core.session import DebugSession, SessionConfig
from apex_debug.engine.runner import run_pattern_engine
from apex_debug.parsers.registry import ParserRegistry


class DebugShell:
    """Interactive debug session manager."""

    def __init__(self) -> None:
        self.file: Optional[Path] = None
        self.source: str = ""
        self.lines: list[str] = []
        self.current_line: int = 1
        self.breakpoints: set[int] = set()
        self.findings: list[Finding] = []
        self._parser = ParserRegistry()

    def load(self, filepath: str) -> None:
        p = Path(filepath)
        if not p.exists():
            print(f"Error: '{filepath}' not found.")
            return
        self.file = p.resolve()
        source = self._parser.read_file(self.file)
        if source is None:
            print(f"Error: cannot read '{filepath}'.")
            return
        self.source = source
        self.lines = source.split("\n")
        self.current_line = 1
        self.breakpoints.clear()
        self.findings.clear()
        print(f"Loaded {self.file} ({len(self.lines)} lines)")

    def show_list(self, context: int = 5) -> None:
        if not self.lines:
            print("No file loaded. Use 'load <file>' first.")
            return

        start = max(0, self.current_line - context - 1)
        end = min(len(self.lines), self.current_line + context)

        for i in range(start, end):
            line_num = i + 1
            marker = ">>> " if line_num == self.current_line else "    "
            bp = "* " if line_num in self.breakpoints else "  "
            code = self.lines[i].rstrip()
            print(f"{bp}{marker}{line_num:4d} | {code}")

    def set_breakpoint(self, line_str: str) -> None:
        if not self.lines:
            print("No file loaded.")
            return
        try:
            line = int(line_str)
            if 1 <= line <= len(self.lines):
                self.breakpoints.add(line)
                print(f"Breakpoint set at line {line}")
            else:
                print(f"Line {line} out of range (1-{len(self.lines)})")
        except ValueError:
            print(f"Invalid line number: {line_str}")

    def clear_breakpoint(self, line_str: str) -> None:
        try:
            line = int(line_str)
            self.breakpoints.discard(line)
            print(f"Breakpoint cleared at line {line}")
        except ValueError:
            print(f"Invalid line number: {line_str}")

    def list_breakpoints(self) -> None:
        if not self.breakpoints:
            print("No breakpoints set.")
            return
        for bp in sorted(self.breakpoints):
            snippet = self.lines[bp - 1].strip() if bp <= len(self.lines) else ""
            print(f"  * {bp}: {snippet[:60]}")

    def run(self) -> None:
        if not self.file:
            print("No file loaded.")
            return

        print(f"Running {self.file.name}...")
        print("-" * 40)
        try:
            result = subprocess.run(
                [sys.executable, str(self.file)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.stdout:
                print(result.stdout, end="")
            if result.stderr:
                print(result.stderr, end="")
            print("-" * 40)
            if result.returncode != 0:
                print(f"[red]Exited with code {result.returncode}[/red]")
            else:
                print("Done.")
        except subprocess.TimeoutExpired:
            print("[red]Timeout: process took longer than 30s[/red]")
        except Exception as e:
            print(f"[red]Error running file: {e}[/red]")

    def analyze(self) -> None:
        if not self.file or not self.source:
            print("No file loaded.")
            return

        config = SessionConfig(target=self.file)
        session = DebugSession(config=config)
        run_pattern_engine(session, self.file, self.source)
        self.findings = session.findings

        if not self.findings:
            print("No issues found.")
            return

        print(f"\n{len(self.findings)} finding(s):")
        for f in self.findings:
            sev = f.severity.name
            loc = f.location_str()
            print(f"  [{sev}] {f.title} at {loc}")
            print(f"    -> {f.message[:100]}")

    def show_findings(self) -> None:
        if not self.findings:
            print("No findings. Run 'analyze' first.")
            return
        self.analyze()

    def step(self) -> None:
        if not self.lines:
            print("No file loaded.")
            return
        if self.current_line < len(self.lines):
            self.current_line += 1
            print(f"Stepped to line {self.current_line}")
            if self.current_line in self.breakpoints:
                print(f"  [Breakpoint hit at line {self.current_line}]")
            self.show_list(context=2)
        else:
            print("At end of file.")

    def goto(self, line_str: str) -> None:
        try:
            line = int(line_str)
            if 1 <= line <= len(self.lines):
                self.current_line = line
                self.show_list(context=2)
            else:
                print(f"Line {line} out of range.")
        except ValueError:
            print(f"Invalid line number: {line_str}")

    def help(self) -> None:
        print("""
Apex Debug Shell — Commands:
  load <file>     Load a source file
  list / l        Show source around current line
  break <n> / b   Set breakpoint at line
  breaks          List breakpoints
  clear <n>       Clear breakpoint
  run / r         Run the current file
  analyze / a     Static analysis
  findings / f    Show findings
  step / s        Advance one line
  goto <n>        Jump to line
  help / h        Show this help
  quit / q        Exit
""")


def _has_prompt_toolkit() -> bool:
    try:
        import prompt_toolkit  # noqa: F401
        return True
    except ImportError:
        return False


def run_interactive_shell() -> None:
    """Start the interactive debug shell."""
    shell = DebugShell()
    print("Apex Debug Shell v0.1.0")
    print("Type 'help' for commands, 'quit' to exit.")
    print()

    if _has_prompt_toolkit():
        _run_with_prompt_toolkit(shell)
    else:
        _run_with_input(shell)


def _run_with_input(shell: DebugShell) -> None:
    """Fallback: plain input() loop."""
    while True:
        try:
            raw = input("(apex-debug) ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            break
        if not raw:
            continue
        if _process_command(shell, raw):
            break


def _run_with_prompt_toolkit(shell: DebugShell) -> None:
    """Rich input loop with prompt_toolkit."""
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import WordCompleter

    completer = WordCompleter([
        "load", "list", "l", "break", "b", "breaks", "clear",
        "run", "r", "analyze", "a", "findings", "f",
        "step", "s", "goto", "help", "h", "quit", "q",
    ])

    session = PromptSession("(apex-debug) ", completer=completer)
    while True:
        try:
            raw = session.prompt().strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            break
        if not raw:
            continue
        if _process_command(shell, raw):
            break


def _process_command(shell: DebugShell, raw: str) -> bool:
    """Process a single shell command.

    Returns True if shell should exit.
    """
    parts = raw.split(maxsplit=1)
    cmd = parts[0].lower()
    arg = parts[1] if len(parts) > 1 else ""

    if cmd in ("quit", "q", "exit"):
        print("Bye.")
        return True

    if cmd in ("help", "h", "?"):
        shell.help()
    elif cmd == "load":
        if arg:
            shell.load(arg)
        else:
            print("Usage: load <file>")
    elif cmd in ("list", "l"):
        shell.show_list()
    elif cmd in ("break", "b"):
        if arg:
            shell.set_breakpoint(arg)
        else:
            print("Usage: break <line>")
    elif cmd == "breaks":
        shell.list_breakpoints()
    elif cmd == "clear":
        if arg:
            shell.clear_breakpoint(arg)
        else:
            print("Usage: clear <line>")
    elif cmd in ("run", "r"):
        shell.run()
    elif cmd in ("analyze", "a"):
        shell.analyze()
    elif cmd in ("findings", "f"):
        shell.show_findings()
    elif cmd in ("step", "s"):
        shell.step()
    elif cmd == "goto":
        if arg:
            shell.goto(arg)
        else:
            print("Usage: goto <line>")
    else:
        print(f"Unknown command: {cmd}. Type 'help' for commands.")

    return False
