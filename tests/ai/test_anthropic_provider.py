from unittest.mock import MagicMock, patch

import rescue.ai.providers.anthropic_provider as anthropic_provider_module
from rescue.ai.providers.anthropic_provider import AnthropicProvider
from rescue.ai.providers.base import AIMessage, AIProviderUnavailable, AIRequestError


def test_raises_when_sdk_missing():
    with patch.object(anthropic_provider_module, "anthropic", None):
        try:
            AnthropicProvider(api_key="test-key")
            assert False, "Should have raised AIProviderUnavailable"
        except AIProviderUnavailable:
            pass


def test_complete_returns_text():
    fake_sdk = MagicMock()
    fake_client = MagicMock()
    fake_response = MagicMock()
    fake_content_block = MagicMock()
    fake_content_block.text = "This is the AI explanation."
    fake_response.content = [fake_content_block]
    fake_client.messages.create.return_value = fake_response
    fake_sdk.Anthropic.return_value = fake_client

    with patch.object(anthropic_provider_module, "anthropic", fake_sdk):
        provider = AnthropicProvider(api_key="test-key")
        result = provider.complete(
            messages=[AIMessage(role="user", content="Why is my disk full?")],
            system="You are a helpful diagnostic assistant.",
        )

    assert result == "This is the AI explanation."
    fake_client.messages.create.assert_called_once()
    call_kwargs = fake_client.messages.create.call_args.kwargs
    assert call_kwargs["system"] == "You are a helpful diagnostic assistant."
    assert call_kwargs["messages"] == [
        {"role": "user", "content": "Why is my disk full?"}
    ]


def test_complete_wraps_sdk_errors():
    fake_sdk = MagicMock()
    fake_client = MagicMock()
    fake_client.messages.create.side_effect = RuntimeError("network down")
    fake_sdk.Anthropic.return_value = fake_client

    with patch.object(anthropic_provider_module, "anthropic", fake_sdk):
        provider = AnthropicProvider(api_key="test-key")
        try:
            provider.complete(messages=[AIMessage(role="user", content="hi")])
            assert False, "Should have raised AIRequestError"
        except AIRequestError:
            pass
