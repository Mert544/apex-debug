# Apex Debug

**AST-first static analysis for Python, JavaScript, TypeScript, Go, Rust, and more.**

[![Tests](https://img.shields.io/badge/tests-27%2F27-brightgreen)](tests/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-yellow)](LICENSE)

> **100% free. No API keys. No cloud calls. Works offline.**

Apex Debug is a lightweight, extensible static analysis tool that detects security vulnerabilities, correctness bugs, performance anti-patterns, and style issues in your code. Built for students, indie developers, and anyone who wants quality code without breaking the bank.

---

## Features

| Feature | Description |
|---------|-------------|
| **15 Detection Patterns** | Security, correctness, performance, style |
| **Multi-Language** | Python (AST), JS/TS/Go/Rust (regex fallback), 25+ file extensions |
| **Parallel Analysis** | Multi-threaded for large codebases |
| **Knowledge Base** | SQLite persistence — remembers past findings |
| **Multiple Outputs** | Terminal, Markdown, SARIF (GitHub Code Scanning), JSON |
| **Interactive Shell** | Breakpoint, step, run, analyze — like a debugger |
| **VS Code Extension** | Sidebar findings panel, one-click analysis |
| **Pre-commit Hook** | Block commits with CRITICAL/HIGH issues |
| **Zero Dependencies** | Core works with stdlib only |

---

## Installation

```bash
pip install -e .
```

Or development setup:

```bash
git clone <repo-url>
cd apex-debug
pip install -e .[dev]
```

---

## Quick Start

```bash
# Analyze a single file
apex-debug analyze app.py

# Analyze a directory with full severity
apex-debug analyze src/ --min-severity info

# Export as SARIF for GitHub Code Scanning
apex-debug analyze src/ --output sarif

# Filter by category
apex-debug analyze src/ --category security

# Interactive debug shell
apex-debug shell
```

---

## Commands

| Command | Description |
|---------|-------------|
| `apex-debug analyze <path>` | Run static analysis |
| `apex-debug analyze --output markdown` | Export Markdown report |
| `apex-debug analyze --output sarif` | Export SARIF for GitHub |
| `apex-debug analyze --output json` | Export JSON report |
| `apex-debug shell` | Interactive debug shell |
| `apex-debug patterns` | List all 15 detection patterns |
| `apex-debug kb stats` | Knowledge base statistics |
| `apex-debug info` | Show version and config |

### Interactive Shell Commands

```
(apex-debug) load app.py     # Load a file
(apex-debug) list            # Show source
(apex-debug) break 14        # Set breakpoint
(apex-debug) step            # Advance line
(apex-debug) run             # Run the file
(apex-debug) analyze         # Static analysis
(apex-debug) quit            # Exit
```

---

## Detection Patterns

### Security (4 patterns)
- `eval()` / `exec()` / `compile()` — arbitrary code execution
- `os.system()` / `subprocess.run(shell=True)` — shell injection
- `pickle.loads()` — insecure deserialization
- SQL injection via f-string / `%` formatting

### Correctness (3 patterns)
- Bare `except:` clauses
- `== None` instead of `is None`
- Unused local variables

### Performance (4 patterns)
- Nested loops (O(n²))
- `range(len(x))` instead of `enumerate()`
- String concatenation in loops
- Global variable access in loops

### Style (4 patterns)
- Missing docstrings
- Functions over 50 lines
- Functions with > 5 arguments
- Unreachable code after return/raise

---

## Configuration

Create `.apex-debug.yaml` in your project root:

```yaml
patterns:
  security: true
  correctness: true
  performance: true
  style: false  # disable style checks

severity:
  min_report: medium  # skip low/info

knowledge_base:
  enabled: true
  path: .apex-debug/knowledge.db
```

Hierarchy: CLI flags > `.apex-debug.yaml` > `~/.apex-debug/config.yaml` > bundled defaults

---

## Pre-commit Hook

```bash
cp scripts/pre-commit.py .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Blocks commits if CRITICAL or HIGH severity findings are found.

---

## VS Code Extension

```bash
cd vscode
npm install
npm run compile
```

Then press F5 in VS Code to launch the extension host.

Features:
- Analyze button in editor toolbar (Python files)
- Apex Findings sidebar panel
- Click finding to jump to line

---

## CI/CD (GitHub Actions)

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
  with:
    python-version: "3.11"
- run: pip install -e .[dev]
- run: pytest tests/ -v
- run: apex-debug analyze src/ --output sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: report.sarif
```

Full workflow: [`.github/workflows/ci.yml`](.github/workflows/ci.yml)

---

## Project Structure

```
apex-debug/
├── apex_debug/
│   ├── core/              # Finding, Session, EventBus
│   ├── engine/
│   │   ├── patterns/      # 15 detection plugins
│   │   ├── runner.py      # Pattern engine + parallel
│   │   └── knowledge.py   # SQLite KB
│   ├── parsers/           # File discovery + multi-language
│   ├── reporter/          # Markdown, SARIF, JSON
│   ├── cli/
│   │   ├── app.py         # CLI commands
│   │   └── interactive.py # Debug shell
│   └── config.py          # Config loader
├── vscode/                # VS Code extension
├── scripts/
│   └── pre-commit.py      # Git hook
├── tests/                 # 27 pytest tests
└── config/default.yaml    # Default configuration
```

---

## Testing

```bash
pytest tests/ -v
```

27 tests covering all patterns, runner, parser, and config.

---

## License

MIT — free for personal and commercial use.

---

> **Built for students, indie devs, and teams who want quality code without the cloud bill.**
