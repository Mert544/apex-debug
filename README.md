# Apex Debug

**AST-first static analysis for Python, JavaScript, TypeScript, Go, Rust, and more.**

[![Tests](https://img.shields.io/badge/tests-73%2F73-brightgreen)](tests/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-yellow)](LICENSE)

> **100% free. No API keys. No cloud calls. Works offline.**

Apex Debug is a lightweight, extensible static analysis tool that detects security vulnerabilities, correctness bugs, performance anti-patterns, and style issues in your code. Built for students, indie developers, and anyone who wants quality code without breaking the bank.

---

## Features

| Feature | Description |
|---------|-------------|
| **27 Detection Patterns** | Security, correctness, performance, style |
| **Multi-Language** | Python (AST), JS/TS/Go/Rust (regex fallback), 25+ file extensions |
| **Parallel Analysis** | Multi-threaded for large codebases |
| **Knowledge Base** | SQLite persistence — remembers past findings |
| **Multiple Outputs** | Terminal, Markdown, SARIF (GitHub Code Scanning), JSON, HTML |
| **Watch Mode** | Auto-reanalyze on file changes |
| **Baseline / Diff** | Filter known issues or analyze only changed lines |
| **Auto-Fix** | Safe, deterministic code corrections |
| **Custom Plugins** | Load your own detection patterns at runtime |
| **Interactive Shell** | Breakpoint, step, run, analyze — like a debugger |
| **Pre-commit Hook** | Block commits with CRITICAL/HIGH issues |
| **Exit Codes** | CI/CD friendly — returns max severity level |
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
apex analyze app.py

# Analyze a directory with full severity
apex analyze src/ --min-severity info

# Export as SARIF for GitHub Code Scanning
apex analyze src/ --output sarif

# Watch mode — auto-reanalyze on save
apex watch src/

# Use a baseline to hide known issues
apex analyze src/ --baseline .apex-debug/baseline.json

# Analyze only changed lines (staged)
apex analyze src/ --diff-staged

# Auto-fix safe issues
apex analyze src/ --fix

# Load custom pattern plugins
apex analyze src/ --plugins ./my-patterns

# Filter by category
apex analyze src/ --category security

# Interactive debug shell
apex shell
```

---

## Commands

| Command | Description |
|---------|-------------|
| `apex analyze <path>` | Run static analysis |
| `apex watch <path>` | Watch files and re-analyze on change |
| `apex patterns` | List all detection patterns |
| `apex plugins list` | List custom pattern plugins |
| `apex kb stats` | Knowledge base statistics |
| `apex info` | Show version and config |

### Output Formats

| Flag | Description |
|------|-------------|
| `--output terminal` | Rich colored terminal output (default) |
| `--output markdown` | Markdown report |
| `--output json` | JSON report |
| `--output html` | Interactive HTML report |
| `--output sarif` | SARIF v2.1.0 for GitHub Code Scanning |

### CI/CD Exit Codes

Use `--exit-code` to return the maximum severity as exit code:

```bash
apex analyze src/ --exit-code
# Exit 1 = INFO, 2 = LOW, 3 = MEDIUM, 4 = HIGH, 5 = CRITICAL
```

---

## Detection Patterns

### Security (14 patterns)
- `eval()` / `exec()` / `compile()` — arbitrary code execution
- `os.system()` / `subprocess.run(shell=True)` — shell injection
- `pickle.loads()` — insecure deserialization
- SQL injection via f-string / `%` formatting
- `hashlib.md5()` / `hashlib.sha1()` — weak cryptographic hash
- Hardcoded passwords, API keys, secrets
- `random.*` for security-sensitive operations
- `open()` with non-literal paths — path traversal
- Hardcoded IP addresses
- `DEBUG = True` in production
- CORS wildcard `origins="*"`
- `yaml.load()` without `Loader` — arbitrary code execution
- `assert` statements — removed with `python -O`
- `urllib.request.urlopen()` without timeout

### Correctness (4 patterns)
- Bare `except:` clauses
- `== None` instead of `is None`
- `type(x) == Y` instead of `isinstance()`
- Unused local variables

### Performance (4 patterns)
- Nested loops (O(n²))
- `range(len(x))` instead of `enumerate()`
- String concatenation in loops
- Global variable access in loops

### Style (5 patterns)
- Missing docstrings
- Functions over 50 lines
- Functions with > 5 arguments
- Unreachable code after return/raise
- Unused functions

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

plugins:
  directory: .apex-debug/plugins
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
- run: apex analyze src/ --output sarif --exit-code
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: report.sarif
```

Full workflow: [`.github/workflows/apex-debug.yml`](.github/workflows/apex-debug.yml)

---

## Project Structure

```
apex-debug/
├── apex_debug/
│   ├── core/              # Finding, Session, EventBus
│   ├── engine/
│   │   ├── patterns/      # 27 detection plugins
│   │   ├── runner.py      # Pattern engine + parallel
│   │   ├── knowledge.py   # SQLite KB
│   │   ├── watcher.py     # File watch mode
│   │   ├── baseline.py    # Baseline filter
│   │   ├── autofix.py     # Safe auto-fixes
│   │   ├── gitdiff.py     # Git diff filtering
│   │   └── plugins.py     # Custom pattern loader
│   ├── parsers/           # File discovery + multi-language
│   ├── reporter/          # Markdown, SARIF, JSON, HTML
│   ├── cli/
│   │   ├── app.py         # CLI commands
│   │   └── interactive.py # Debug shell
│   └── config.py          # Config loader
├── vscode/                # VS Code extension
├── scripts/
│   └── pre-commit.py      # Git hook
├── tests/                 # 73 pytest tests
└── config/default.yaml    # Default configuration
```

---

## Testing

```bash
pytest tests/ -v
```

73 tests covering all patterns, runner, parser, config, watcher, baseline, autofix, and plugins.

---

## License

MIT — free for personal and commercial use.

---

> **Built for students, indie devs, and teams who want quality code without the cloud bill.**
