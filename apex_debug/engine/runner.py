"""Pattern engine — discovers and runs all available patterns against source files."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

from apex_debug.core.finding import Finding
from apex_debug.core.session import DebugSession
from apex_debug.engine.patterns.base import AbstractPattern


def get_all_patterns() -> list[AbstractPattern]:
    """Return all available pattern instances.

    Add new patterns here as they are implemented.
    """
    from apex_debug.engine.patterns.correctness import (
        BareExceptPattern,
        NoneComparisonPattern,
        TypeComparisonPattern,
        UnusedVariablePattern,
    )
    from apex_debug.engine.patterns.performance import (
        GlobalInLoopPattern,
        NestedLoopPattern,
        RepeatedCallInLoopPattern,
        StringConcatInLoopPattern,
    )
    from apex_debug.engine.patterns.security import (
        CORSWildcardPattern,
        DangerousSubprocessPattern,
        DebugTruePattern,
        EvalExecPattern,
        HardcodedIPPattern,
        HardcodedSecretPattern,
        InsecureRandomPattern,
        PathTraversalPattern,
        PicklePattern,
        SQLInjectionPattern,
        WeakHashPattern,
    )
    from apex_debug.engine.patterns.style import (
        DeadCodePattern,
        LongFunctionPattern,
        MissingDocstringPattern,
        TooManyArgumentsPattern,
        UnusedFunctionPattern,
    )

    return [
        EvalExecPattern(),
        DangerousSubprocessPattern(),
        PicklePattern(),
        SQLInjectionPattern(),
        WeakHashPattern(),
        HardcodedSecretPattern(),
        InsecureRandomPattern(),
        PathTraversalPattern(),
        HardcodedIPPattern(),
        DebugTruePattern(),
        CORSWildcardPattern(),
        BareExceptPattern(),
        NoneComparisonPattern(),
        TypeComparisonPattern(),
        UnusedVariablePattern(),
        NestedLoopPattern(),
        RepeatedCallInLoopPattern(),
        GlobalInLoopPattern(),
        StringConcatInLoopPattern(),
        MissingDocstringPattern(),
        LongFunctionPattern(),
        TooManyArgumentsPattern(),
        DeadCodePattern(),
        UnusedFunctionPattern(),
    ]


def run_pattern_engine_parallel(
    session: DebugSession,
    files: list[tuple[Path, str]],
    max_workers: int = 4,
) -> list[Finding]:
    """Run pattern engine on multiple files in parallel.

    Args:
        session: Debug session for accumulating findings
        files: List of (filepath, source) tuples
        max_workers: Number of parallel threads

    Returns:
        Combined list of all findings
    """
    all_findings: list[Finding] = []

    def _analyze_file(item: tuple[Path, str]) -> list[Finding]:
        filepath, source = item
        try:
            return run_pattern_engine(session, filepath, source)
        except Exception:
            return []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_analyze_file, item): item for item in files}
        for future in as_completed(futures):
            result = future.result()
            all_findings.extend(result)

    return all_findings


def run_pattern_engine(session: DebugSession, filepath: Path, source: str) -> list[Finding]:
    """Run all enabled patterns against a source file.

    Returns a list of Findings. Each finding is also emitted via the session event bus.

    Args:
        session: Current debug session
        filepath: Path to the source file
        source: Source code as string
    """
    findings: list[Finding] = []

    enabled_categories = {
        "security": session.config.patterns_security,
        "correctness": session.config.patterns_correctness,
        "performance": session.config.patterns_performance,
        "style": session.config.patterns_style,
    }

    patterns = [
        p
        for p in get_all_patterns()
        if enabled_categories.get(p.category, False)
    ]

    for pattern in patterns:
        try:
            result = _analyze_with_python_ast(pattern, source, str(filepath))
        except Exception:
            continue

        min_sev = _severity_from_str(session.config.min_severity)
        for f in result:
            if f.severity >= min_sev:
                findings.append(f)
                session.add_finding(f)

    return findings


def _analyze_with_python_ast(
    pattern: AbstractPattern, source: str, filepath: str
) -> list[Finding]:
    """Analyze Python source using the stdlib ast module."""
    import ast as ast_module

    findings: list[Finding] = []
    try:
        tree = ast_module.parse(source)
    except SyntaxError:
        # Try parsing without __future__ imports and decorators
        return _fallback_regex_analyze(pattern, source, filepath)

    for node in ast_module.walk(tree):
        try:
            result = pattern.analyze_python_ast(node, source, filepath)
            findings.extend(result)
        except Exception:
            continue

    return findings


def _fallback_regex_analyze(
    pattern: AbstractPattern, source: str, filepath: str
) -> list[Finding]:
    """Universal regex fallback for any file or language."""
    import re as re_module

    findings: list[Finding] = []
    regex_info = pattern.get_regex()
    if regex_info is None:
        return findings

    pattern_re, message_template = regex_info
    lines = source.split("\n")

    for line_no, line in enumerate(lines, start=1):
        match = re_module.search(pattern_re, line)
        if match:
            findings.append(
                pattern._make_finding(
                    filepath=filepath,
                    line=line_no,
                    message=message_template.format(
                        line=line_no, file=filepath, match=match.group(0)
                    ),
                    snippet=line.strip(),
                )
            )

    return findings


def _severity_from_str(name: str) -> Severity:
    """Convert a severity string to enum member, defaulting to INFO."""
    from apex_debug.core.finding import Severity as S

    try:
        return S[name.upper()]
    except KeyError:
        return S.INFO


def get_categories() -> dict[str, list[AbstractPattern]]:
    """Group all patterns by category."""
    cats: dict[str, list[AbstractPattern]] = {}
    for p in get_all_patterns():
        cats.setdefault(p.category, []).append(p)
    return cats
