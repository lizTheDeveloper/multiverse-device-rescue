from __future__ import annotations

try:
    import anthropic
except ImportError:  # pragma: no cover
    anthropic = None

from rescue.ai.providers.base import (
    AIMessage,
    AIProvider,
    AIProviderUnavailable,
    AIRequestError,
)

DEFAULT_MODEL = "claude-sonnet-5"
DEFAULT_MAX_TOKENS = 1024


class AnthropicProvider(AIProvider):
    provider_name = "anthropic"

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ):
        if anthropic is None:
            raise AIProviderUnavailable(
                "The 'anthropic' package is not installed. Install it with "
                "`pip install multiverse-device-rescue[ai]` to use the Anthropic provider."
            )
        self.model = model
        self.max_tokens = max_tokens
        self._client = anthropic.Anthropic(api_key=api_key)

    def complete(self, messages: list[AIMessage], system: str | None = None) -> str:
        try:
            response = self._client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=system or "",
                messages=[{"role": m.role, "content": m.content} for m in messages],
            )
        except Exception as exc:  # pragma: no cover — network/SDK errors
            raise AIRequestError(f"Anthropic request failed: {exc}") from exc
        return response.content[0].text
