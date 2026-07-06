from unittest.mock import MagicMock, patch

import rescue.ai.factory as factory
from rescue.ai.providers.base import AIProviderUnavailable


def test_no_provider_configured_returns_none(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    monkeypatch.delenv("RESCUE_AI_PROVIDER", raising=False)

    assert factory.get_provider() is None


def test_prefers_anthropic_when_key_present(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    monkeypatch.delenv("RESCUE_AI_PROVIDER", raising=False)

    fake_instance = MagicMock()
    with patch.object(factory, "AnthropicProvider", return_value=fake_instance) as MockAnthropic:
        provider = factory.get_provider()

    assert provider is fake_instance
    MockAnthropic.assert_called_once_with(api_key="sk-ant-test")


def test_falls_back_to_openai_when_no_anthropic_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-test")
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    monkeypatch.delenv("RESCUE_AI_PROVIDER", raising=False)

    fake_instance = MagicMock()
    with patch.object(factory, "OpenAIProvider", return_value=fake_instance) as MockOpenAI:
        provider = factory.get_provider()

    assert provider is fake_instance
    MockOpenAI.assert_called_once_with(api_key="sk-openai-test")


def test_ollama_used_when_host_set(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("OLLAMA_HOST", "http://localhost:11434")
    monkeypatch.delenv("RESCUE_AI_PROVIDER", raising=False)

    fake_instance = MagicMock()
    with patch.object(factory, "OllamaProvider", return_value=fake_instance) as MockOllama:
        provider = factory.get_provider()

    assert provider is fake_instance
    MockOllama.assert_called_once_with(host="http://localhost:11434")


def test_ollama_not_used_without_host_or_explicit_request(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    monkeypatch.delenv("RESCUE_AI_PROVIDER", raising=False)

    with patch.object(factory, "OllamaProvider") as MockOllama:
        provider = factory.get_provider()

    assert provider is None
    MockOllama.assert_not_called()


def test_explicit_preferred_ollama_defaults_host(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    monkeypatch.delenv("RESCUE_AI_PROVIDER", raising=False)

    fake_instance = MagicMock()
    with patch.object(factory, "OllamaProvider", return_value=fake_instance) as MockOllama:
        provider = factory.get_provider(preferred="ollama")

    assert provider is fake_instance
    MockOllama.assert_called_once_with(host="http://localhost:11434")


def test_preferred_overrides_default_order(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-test")
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    monkeypatch.delenv("RESCUE_AI_PROVIDER", raising=False)

    fake_instance = MagicMock()
    with patch.object(factory, "OpenAIProvider", return_value=fake_instance) as MockOpenAI, \
         patch.object(factory, "AnthropicProvider") as MockAnthropic:
        provider = factory.get_provider(preferred="openai")

    assert provider is fake_instance
    MockOpenAI.assert_called_once()
    MockAnthropic.assert_not_called()


def test_unavailable_sdk_falls_through_to_next(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-test")
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    monkeypatch.delenv("RESCUE_AI_PROVIDER", raising=False)

    fake_openai_instance = MagicMock()
    with patch.object(factory, "AnthropicProvider", side_effect=AIProviderUnavailable("no sdk")), \
         patch.object(factory, "OpenAIProvider", return_value=fake_openai_instance):
        provider = factory.get_provider()

    assert provider is fake_openai_instance
