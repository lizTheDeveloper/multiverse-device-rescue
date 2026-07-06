from unittest.mock import MagicMock, patch

import rescue.ai.providers.openai_provider as openai_provider_module
from rescue.ai.providers.openai_provider import OpenAIProvider
from rescue.ai.providers.base import AIMessage, AIProviderUnavailable, AIRequestError


def test_raises_when_sdk_missing():
    with patch.object(openai_provider_module, "openai", None):
        try:
            OpenAIProvider(api_key="test-key")
            assert False, "Should have raised AIProviderUnavailable"
        except AIProviderUnavailable:
            pass


def test_complete_returns_text():
    fake_sdk = MagicMock()
    fake_client = MagicMock()
    fake_response = MagicMock()
    fake_choice = MagicMock()
    fake_choice.message.content = "This is the AI explanation."
    fake_response.choices = [fake_choice]
    fake_client.chat.completions.create.return_value = fake_response
    fake_sdk.OpenAI.return_value = fake_client

    with patch.object(openai_provider_module, "openai", fake_sdk):
        provider = OpenAIProvider(api_key="test-key")
        result = provider.complete(
            messages=[AIMessage(role="user", content="Why is my disk full?")],
            system="You are a helpful diagnostic assistant.",
        )

    assert result == "This is the AI explanation."
    call_kwargs = fake_client.chat.completions.create.call_args.kwargs
    assert call_kwargs["messages"][0] == {
        "role": "system",
        "content": "You are a helpful diagnostic assistant.",
    }
    assert call_kwargs["messages"][1] == {
        "role": "user",
        "content": "Why is my disk full?",
    }


def test_complete_wraps_sdk_errors():
    fake_sdk = MagicMock()
    fake_client = MagicMock()
    fake_client.chat.completions.create.side_effect = RuntimeError("network down")
    fake_sdk.OpenAI.return_value = fake_client

    with patch.object(openai_provider_module, "openai", fake_sdk):
        provider = OpenAIProvider(api_key="test-key")
        try:
            provider.complete(messages=[AIMessage(role="user", content="hi")])
            assert False, "Should have raised AIRequestError"
        except AIRequestError:
            pass
