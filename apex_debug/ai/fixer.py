"""AI-powered fix generator."""

from __future__ import annotations

from apex_debug.ai.client import AIClient
from apex_debug.ai.prompts import SYSTEM_PROMPT, fix_prompt
from apex_debug.core.finding import Finding


def generate_fix(finding: Finding, client: AIClient) -> str:
    """Generate an AI fix for a single finding.

    Args:
        finding: The finding to fix
        client: AI client instance

    Returns:
        AI-generated fixed code snippet
    """
    prompt = fix_prompt(
        title=finding.title,
        message=finding.message,
        snippet=finding.snippet or "# no snippet available",
        filepath=finding.file,
        line=finding.line,
    )
    return client.chat(SYSTEM_PROMPT, prompt)
