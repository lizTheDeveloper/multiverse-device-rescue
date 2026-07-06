from __future__ import annotations

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None

from rescue.ai.providers.base import (
    AIMessage,
    AIProvider,
    AIProviderUnavailable,
    AIRequestError,
)

DEFAULT_MODEL = "llama3.1"
DEFAULT_TIMEOUT = 60.0
DEFAULT_HOST = "http://localhost:11434"


class OllamaProvider(AIProvider):
    provider_name = "ollama"

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        model: str = DEFAULT_MODEL,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        if httpx is None:
            raise AIProviderUnavailable(
                "The 'httpx' package is not installed. Install it with "
                "`pip install multiverse-device-rescue[ai]` to use the Ollama provider."
            )
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout

    def complete(self, messages: list[AIMessage], system: str | None = None) -> str:
        chat_messages = []
        if system:
            chat_messages.append({"role": "system", "content": system})
        chat_messages.extend({"role": m.role, "content": m.content} for m in messages)

        try:
            response = httpx.post(
                f"{self.host}/api/chat",
                json={
                    "model": self.model,
                    "messages": chat_messages,
                    "stream": False,
                },
                timeout=self.timeout,
            )
            response.raise_for_status()
        except Exception as exc:  # pragma: no cover — network errors
            raise AIRequestError(f"Ollama request failed: {exc}") from exc
        data = response.json()
        return data["message"]["content"]
