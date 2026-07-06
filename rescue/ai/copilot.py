from __future__ import annotations

from typing import Any

from rescue.ai.providers.base import AIMessage, AIProvider

_INSTRUCTIONS_TEMPLATE = """You are a walkthrough copilot embedded in a computer security and privacy tool. \
The user is currently working through this guide step:

---
{guide}
---

Relevant system context (from automated scans, may be empty):
{context}

Answer the user's question about this step in plain language, grounded in the guide text and the \
system context above. If the answer isn't covered by the guide or context, say so honestly instead \
of guessing. Never instruct the user to run a destructive command themselves without a clear warning, \
and never claim that you (the AI) have made any changes — you only explain, you don't act."""


class WalkthroughCopilot:
    def __init__(
        self,
        provider: AIProvider,
        guide_content: str,
        context_data: dict[str, Any] | None = None,
    ):
        self.provider = provider
        self.guide_content = guide_content
        self.context_data = context_data or {}

    def answer(self, question: str) -> str:
        return self.provider.complete(
            messages=[AIMessage(role="user", content=question)],
            system=self._system_prompt(),
        )

    async def answer_async(self, question: str) -> str:
        return await self.provider.complete_async(
            messages=[AIMessage(role="user", content=question)],
            system=self._system_prompt(),
        )

    def _system_prompt(self) -> str:
        if self.context_data:
            context_str = "\n".join(f"- {k}: {v}" for k, v in self.context_data.items())
        else:
            context_str = "No additional system context provided."
        return _INSTRUCTIONS_TEMPLATE.format(guide=self.guide_content, context=context_str)
