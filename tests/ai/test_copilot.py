import asyncio
from unittest.mock import MagicMock

from rescue.ai.copilot import WalkthroughCopilot

GUIDE_TEXT = """## Step 2: Turn on two-factor authentication
Go to Settings > Security and enable 2FA using an authenticator app, not SMS."""


def test_answer_grounds_prompt_in_guide_and_context():
    fake_provider = MagicMock()
    fake_provider.complete.return_value = "SMS 2FA can be intercepted via SIM swap; an app is safer."

    copilot = WalkthroughCopilot(
        provider=fake_provider,
        guide_content=GUIDE_TEXT,
        context_data={"phone_number_on_file": True},
    )
    answer = copilot.answer("Why not just use SMS?")

    assert answer == "SMS 2FA can be intercepted via SIM swap; an app is safer."
    fake_provider.complete.assert_called_once()
    _, kwargs = fake_provider.complete.call_args
    assert "two-factor authentication" in kwargs["system"]
    assert "phone_number_on_file" in kwargs["system"]
    assert kwargs["messages"][0].content == "Why not just use SMS?"


def test_answer_with_no_context_data():
    fake_provider = MagicMock()
    fake_provider.complete.return_value = "Because it protects your account even if your password leaks."

    copilot = WalkthroughCopilot(provider=fake_provider, guide_content=GUIDE_TEXT)
    answer = copilot.answer("Why do I need to do this at all?")

    assert answer == "Because it protects your account even if your password leaks."
    _, kwargs = fake_provider.complete.call_args
    assert "No additional system context" in kwargs["system"]


def test_answer_async_returns_provider_text():
    fake_provider = MagicMock()

    async def fake_complete_async(messages, system=None):
        return "Async answer about 2FA."

    fake_provider.complete_async = fake_complete_async

    copilot = WalkthroughCopilot(provider=fake_provider, guide_content=GUIDE_TEXT)
    answer = asyncio.run(copilot.answer_async("Why?"))

    assert answer == "Async answer about 2FA."
