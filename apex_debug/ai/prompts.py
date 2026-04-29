"""Engineered prompt templates for AI-powered debugging."""

from __future__ import annotations


SYSTEM_PROMPT = """You are Apex Debug AI, an expert code reviewer and security analyst.
You analyze code bugs and provide concise, actionable explanations and fixes.
Always respond in the same language as the user's code comments if present, otherwise English.
Be precise. Do not hallucinate. Only suggest fixes you are confident about."""


def explain_prompt(title: str, message: str, snippet: str, filepath: str, line: int) -> str:
    """Prompt for explaining a finding in natural language."""
    return f"""Explain this code bug to a developer:

**Bug:** {title}
**Location:** {filepath}:{line}
**Description:** {message}

**Code snippet:**
```python
{snippet}
```

Explain:
1. WHY this is a problem (with concrete consequences)
2. WHEN it could be exploited or triggered
3. HOW to fix it (specific code change)

Keep it under 150 words."""


def fix_prompt(title: str, message: str, snippet: str, filepath: str, line: int) -> str:
    """Prompt for generating a fix patch."""
    return f"""Fix this code bug. Provide ONLY the corrected code snippet.

**Bug:** {title}
**Location:** {filepath}:{line}
**Description:** {message}

**Current code:**
```python
{snippet}
```

**Instructions:**
- Replace the buggy code with a safe, correct version
- Keep the same function signature and behavior (except the bug)
- Add brief inline comments explaining the fix
- Return ONLY the corrected code block, no extra explanation

```python
# Fixed code:
"""


def root_cause_prompt(title: str, message: str, snippet: str) -> str:
    """Prompt for 5-whys root cause analysis."""
    return f"""Perform a 5-Whys root cause analysis for this bug:

**Bug:** {title}
**Description:** {message}

**Code:**
```python
{snippet}
```

Analyze:
1. What is the surface risk?
2. Why does it exist in the code?
3. Why wasn't it caught earlier?
4. Why does the architecture allow it?
5. What process/system change would prevent this?

Format as bullet points. Be concise."""
