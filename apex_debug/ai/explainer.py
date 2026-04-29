"""AI-powered bug explainer."""

from __future__ import annotations

from apex_debug.ai.client import AIClient
from apex_debug.ai.prompts import SYSTEM_PROMPT, explain_prompt
from apex_debug.core.finding import Finding


def explain_finding(finding: Finding, client: AIClient) -> str:
    """Get an AI explanation for a single finding.

    Args:
        finding: The finding to explain
        client: AI client instance

    Returns:
        AI-generated explanation text
    """
    prompt = explain_prompt(
        title=finding.title,
        message=finding.message,
        snippet=finding.snippet or "# no snippet available",
        filepath=finding.file,
        line=finding.line,
    )
    return client.chat(SYSTEM_PROMPT, prompt)
