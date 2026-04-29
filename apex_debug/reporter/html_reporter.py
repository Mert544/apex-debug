"""HTML reporter for Apex Debug.

Generates a standalone HTML file with interactive findings display.
Zero dependencies — pure HTML/CSS/JS output.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from apex_debug.core.finding import Finding, Severity


def generate_html(findings: list[Finding], title: str = "Apex Debug Report") -> str:
    """Generate a standalone HTML report from findings.

    Args:
        findings: List of findings to include
        title: Report title

    Returns:
        Complete HTML document as string
    """
    severity_counts = _count_by_severity(findings)
    category_counts = _count_by_category(findings)

    # Severity colors
    colors = {
        "CRITICAL": "#dc3545",
        "HIGH": "#fd7e14",
        "MEDIUM": "#ffc107",
        "LOW": "#17a2b8",
        "INFO": "#6c757d",
    }

    rows = []
    for f in findings:
        sev_color = colors.get(f.severity.name, "#6c757d")
        rows.append(
            f"""<tr data-severity="{f.severity.name}" data-category="{html.escape(f.category)}">
                <td><span class="badge" style="background:{sev_color}">{f.severity.name}</span></td>
                <td>{html.escape(f.category)}</td>
                <td>{html.escape(f.title)}</td>
                <td><code>{html.escape(f.location_str())}</code></td>
                <td>{html.escape(f.message[:200])}</td>
                <td><pre class="snippet">{html.escape(f.snippet[:300] if f.snippet else "")}</pre></td>
            </tr>"""
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html.escape(title)}</title>
<style>
    :root {{ --bg: #f8f9fa; --card: #fff; --text: #212529; --border: #dee2e6; }}
    @media (prefers-color-scheme: dark) {{
        :root {{ --bg: #1a1a2e; --card: #16213e; --text: #e94560; --border: #0f3460; }}
    }}
    body {{ font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 2rem; }}
    .container {{ max-width: 1400px; margin: 0 auto; }}
    h1 {{ margin-bottom: 0.5rem; }}
    .meta {{ color: #6c757d; font-size: 0.9rem; margin-bottom: 1.5rem; }}
    .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }}
    .stat-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }}
    .stat-value {{ font-size: 2rem; font-weight: bold; }}
    .stat-label {{ font-size: 0.85rem; color: #6c757d; text-transform: uppercase; }}
    .controls {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin-bottom: 1rem; display: flex; gap: 1rem; flex-wrap: wrap; align-items: center; }}
    .controls label {{ font-size: 0.9rem; }}
    select, input {{ padding: 0.4rem 0.6rem; border: 1px solid var(--border); border-radius: 4px; background: var(--card); color: var(--text); }}
    table {{ width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
    th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid var(--border); }}
    th {{ background: rgba(0,0,0,0.03); font-weight: 600; }}
    tr:hover {{ background: rgba(0,0,0,0.02); }}
    .badge {{ display: inline-block; padding: 0.25em 0.6em; font-size: 0.75rem; font-weight: 700; border-radius: 4px; color: #fff; text-transform: uppercase; }}
    .snippet {{ background: rgba(0,0,0,0.05); padding: 0.5rem; border-radius: 4px; font-size: 0.85rem; overflow-x: auto; margin: 0; }}
    .hidden {{ display: none; }}
</style>
</head>
<body>
<div class="container">
    <h1>{html.escape(title)}</h1>
    <div class="meta">Generated {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")} &middot; {len(findings)} finding(s)</div>

    <div class="stats">
        <div class="stat-card"><div class="stat-value" style="color:#dc3545">{severity_counts.get("CRITICAL", 0)}</div><div class="stat-label">Critical</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#fd7e14">{severity_counts.get("HIGH", 0)}</div><div class="stat-label">High</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#ffc107">{severity_counts.get("MEDIUM", 0)}</div><div class="stat-label">Medium</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#17a2b8">{severity_counts.get("LOW", 0)}</div><div class="stat-label">Low</div></div>
        <div class="stat-card"><div class="stat-value" style="color:#6c757d">{severity_counts.get("INFO", 0)}</div><div class="stat-label">Info</div></div>
    </div>

    <div class="controls">
        <label>Filter by severity:</label>
        <select id="severityFilter" onchange="filterTable()">
            <option value="">All</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
        </select>
        <label>Filter by category:</label>
        <select id="categoryFilter" onchange="filterTable()">
            <option value="">All</option>
            {''.join(f'<option value="{html.escape(c)}">{html.escape(c)}</option>' for c in sorted(category_counts))}
        </select>
        <label>Search:</label>
        <input type="text" id="searchInput" placeholder="Type to search..." onkeyup="filterTable()">
    </div>

    <table id="findingsTable">
        <thead>
            <tr><th>Severity</th><th>Category</th><th>Title</th><th>Location</th><th>Message</th><th>Snippet</th></tr>
        </thead>
        <tbody>
            {''.join(rows) if rows else '<tr><td colspan="6" style="text-align:center;color:#6c757d">No issues found</td></tr>'}
        </tbody>
    </table>
</div>
<script>
function filterTable() {{
    const sev = document.getElementById('severityFilter').value;
    const cat = document.getElementById('categoryFilter').value;
    const q = document.getElementById('searchInput').value.toLowerCase();
    document.querySelectorAll('#findingsTable tbody tr').forEach(tr => {{
        const s = tr.getAttribute('data-severity');
        const c = tr.getAttribute('data-category');
        const txt = tr.innerText.toLowerCase();
        const ok = (!sev || s === sev) && (!cat || c === cat) && (!q || txt.includes(q));
        tr.classList.toggle('hidden', !ok);
    }});
}}
</script>
</body>
</html>"""


def save_html(findings: list[Finding], filepath: str) -> None:
    """Save findings as an HTML report.

    Args:
        findings: List of findings
        filepath: Output file path
    """
    html_content = generate_html(findings)
    Path(filepath).write_text(html_content, encoding="utf-8")


def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.name] = counts.get(f.severity.name, 0) + 1
    return counts


def _count_by_category(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.category] = counts.get(f.category, 0) + 1
    return counts
