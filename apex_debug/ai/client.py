"""AI client for Apex Debug — OpenRouter / OpenAI compatible.

Supports any provider via environment variables:
    OPENROUTER_API_KEY=sk-...
    APEX_AI_BASE_URL=https://openrouter.ai/api/v1
    APEX_AI_MODEL=minimax/minimax-m2.5:free

Or DeepSeek:
    DEEPSEEK_API_KEY=sk-...
    APEX_AI_BASE_URL=https://api.deepseek.com
    APEX_AI_MODEL=deepseek-v4-pro
"""

from __future__ import annotations

import os
from typing import Optional

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None  # type: ignore


class AIClient:
    """Lightweight AI client wrapper for OpenAI-compatible APIs."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: int = 2048,
        temperature: float = 0.2,
    ) -> None:
        if OpenAI is None:
            raise RuntimeError("openai package not installed. Run: pip install openai")

        self.api_key = api_key or self._resolve_api_key()
        self.base_url = base_url or os.getenv("APEX_AI_BASE_URL", "https://api.openai.com/v1")
        self.model = model or os.getenv("APEX_AI_MODEL", "gpt-4o-mini")
        self.max_tokens = max_tokens
        self.temperature = temperature

        self._client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
        )

    @staticmethod
    def _resolve_api_key() -> str:
        """Resolve API key from environment variables.

        Priority:
        1. OPENROUTER_API_KEY
        2. DEEPSEEK_API_KEY
        3. OPENAI_API_KEY
        """
        for key in ("OPENROUTER_API_KEY", "DEEPSEEK_API_KEY", "OPENAI_API_KEY"):
            val = os.getenv(key)
            if val:
                return val
        raise RuntimeError(
            "No AI API key found. Set one of: OPENROUTER_API_KEY, DEEPSEEK_API_KEY, OPENAI_API_KEY"
        )

    def chat(self, system: str, user: str) -> str:
        """Send a chat completion request.

        Args:
            system: System prompt
            user: User prompt

        Returns:
            AI response text
        """
        response = self._client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            max_tokens=self.max_tokens,
            temperature=self.temperature,
        )
        return response.choices[0].message.content or ""

    def is_available(self) -> bool:
        """Check if the client can make requests."""
        return self.api_key is not None and self.api_key != ""
