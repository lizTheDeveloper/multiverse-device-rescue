from unittest.mock import MagicMock, patch

import rescue.ai.providers.ollama_provider as ollama_provider_module
from rescue.ai.providers.ollama_provider import OllamaProvider
from rescue.ai.providers.base import AIMessage, AIProviderUnavailable, AIRequestError


def test_raises_when_httpx_missing():
    with patch.object(ollama_provider_module, "httpx", None):
        try:
            OllamaProvider()
            assert False, "Should have raised AIProviderUnavailable"
        except AIProviderUnavailable:
            pass


def test_complete_posts_to_correct_endpoint():
    fake_httpx = MagicMock()
    fake_response = MagicMock()
    fake_response.json.return_value = {"message": {"content": "Because of X."}}
    fake_httpx.post.return_value = fake_response

    with patch.object(ollama_provider_module, "httpx", fake_httpx):
        provider = OllamaProvider(host="http://localhost:11434", model="llama3.1")
        result = provider.complete(
            messages=[AIMessage(role="user", content="why?")], system="sys"
        )

    assert result == "Because of X."
    fake_httpx.post.assert_called_once()
    args, kwargs = fake_httpx.post.call_args
    assert args[0] == "http://localhost:11434/api/chat"
    assert kwargs["json"]["model"] == "llama3.1"
    assert kwargs["json"]["messages"][0] == {"role": "system", "content": "sys"}
    assert kwargs["json"]["stream"] is False


def test_complete_wraps_http_errors():
    fake_httpx = MagicMock()
    fake_httpx.post.side_effect = RuntimeError("connection refused")

    with patch.object(ollama_provider_module, "httpx", fake_httpx):
        provider = OllamaProvider()
        try:
            provider.complete(messages=[AIMessage(role="user", content="hi")])
            assert False, "Should have raised AIRequestError"
        except AIRequestError:
            pass
