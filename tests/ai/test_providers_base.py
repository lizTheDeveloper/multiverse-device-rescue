import asyncio

from rescue.ai.providers.base import (
    AIMessage,
    AIProvider,
    AIProviderUnavailable,
    AIRequestError,
)


class FakeProvider(AIProvider):
    provider_name = "fake"

    def complete(self, messages, system=None):
        return f"echo:{messages[-1].content}"


def test_ai_message_fields():
    msg = AIMessage(role="user", content="hello")
    assert msg.role == "user"
    assert msg.content == "hello"


def test_complete_sync():
    provider = FakeProvider()
    result = provider.complete([AIMessage(role="user", content="hi")])
    assert result == "echo:hi"


def test_complete_async_wraps_sync():
    provider = FakeProvider()
    result = asyncio.run(provider.complete_async([AIMessage(role="user", content="hi")]))
    assert result == "echo:hi"


def test_exceptions_are_exceptions():
    assert issubclass(AIProviderUnavailable, Exception)
    assert issubclass(AIRequestError, Exception)
