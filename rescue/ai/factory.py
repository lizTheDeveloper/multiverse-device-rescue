from __future__ import annotations

import os

from rescue.ai.providers.anthropic_provider import AnthropicProvider
from rescue.ai.providers.base import AIProvider, AIProviderUnavailable
from rescue.ai.providers.ollama_provider import DEFAULT_HOST as OLLAMA_DEFAULT_HOST
from rescue.ai.providers.ollama_provider import OllamaProvider
from rescue.ai.providers.openai_provider import OpenAIProvider

PROVIDER_ANTHROPIC = "anthropic"
PROVIDER_OPENAI = "openai"
PROVIDER_OLLAMA = "ollama"
_ALL_PROVIDERS = (PROVIDER_ANTHROPIC, PROVIDER_OPENAI, PROVIDER_OLLAMA)


def get_provider(preferred: str | None = None) -> AIProvider | None:
    """Return the first configured AI provider, or None if none is configured.

    Order of preference: the `preferred` argument, then the RESCUE_AI_PROVIDER
    env var, then Anthropic, then OpenAI, then Ollama. A provider only counts
    as "configured" if its required environment variable is set — except
    Ollama, which also counts as configured if it was explicitly requested
    (via `preferred` or RESCUE_AI_PROVIDER), in which case it defaults to
    http://localhost:11434.
    """
    env_pref = os.environ.get("RESCUE_AI_PROVIDER")

    order: list[str] = []
    if preferred:
        order.append(preferred)
    if env_pref:
        order.append(env_pref)
    order.extend(_ALL_PROVIDERS)

    explicit = {name for name in (preferred, env_pref) if name}

    seen: set[str] = set()
    for name in order:
        if name in seen or name not in _ALL_PROVIDERS:
            continue
        seen.add(name)
        provider = _build(name, explicit=name in explicit)
        if provider is not None:
            return provider
    return None


def _build(name: str, explicit: bool) -> AIProvider | None:
    try:
        if name == PROVIDER_ANTHROPIC:
            api_key = os.environ.get("ANTHROPIC_API_KEY")
            if not api_key:
                return None
            return AnthropicProvider(api_key=api_key)

        if name == PROVIDER_OPENAI:
            api_key = os.environ.get("OPENAI_API_KEY")
            if not api_key:
                return None
            return OpenAIProvider(api_key=api_key)

        if name == PROVIDER_OLLAMA:
            host = os.environ.get("OLLAMA_HOST")
            if host is None:
                if not explicit:
                    return None
                host = OLLAMA_DEFAULT_HOST
            return OllamaProvider(host=host)
    except AIProviderUnavailable:
        return None
    return None
