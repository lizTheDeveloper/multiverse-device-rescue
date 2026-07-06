from __future__ import annotations

try:
    import openai
except ImportError:  # pragma: no cover
    openai = None

from rescue.ai.providers.base import (
    AIMessage,
    AIProvider,
    AIProviderUnavailable,
    AIRequestError,
)

DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_MAX_TOKENS = 1024


class OpenAIProvider(AIProvider):
    provider_name = "openai"

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ):
        if openai is None:
            raise AIProviderUnavailable(
                "The 'openai' package is not installed. Install it with "
                "`pip install multiverse-device-rescue[ai]` to use the OpenAI provider."
            )
        self.model = model
        self.max_tokens = max_tokens
        self._client = openai.OpenAI(api_key=api_key)

    def complete(self, messages: list[AIMessage], system: str | None = None) -> str:
        chat_messages = []
        if system:
            chat_messages.append({"role": "system", "content": system})
        chat_messages.extend({"role": m.role, "content": m.content} for m in messages)

        try:
            response = self._client.chat.completions.create(
                model=self.model,
                max_tokens=self.max_tokens,
                messages=chat_messages,
            )
        except Exception as exc:  # pragma: no cover — network/SDK errors
            raise AIRequestError(f"OpenAI request failed: {exc}") from exc
        return response.choices[0].message.content
