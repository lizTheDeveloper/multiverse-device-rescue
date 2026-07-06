from __future__ import annotations

import json
from dataclasses import dataclass

from rescue.ai.providers.base import AIMessage, AIProvider

PROFILE_DESCRIPTIONS: dict[str, str] = {
    "digital_security_reset": "Post-compromise recovery for someone who's been hacked or suspects compromise.",
    "six_roses": "Partner or ex-partner threat model — stalkerware, shared accounts, location sharing.",
    "activist_security": "State-level threat model — hardened OS, encrypted comms, metadata scrubbing.",
    "journalist_security": "Source protection — secure comms verification, device compartmentalization.",
    "home_for_the_holidays": "Helping a family member get their device in shape, with a take-home checklist.",
    "personal_lockdown": "Maximum everyday privacy — disable telemetry, tighten permissions, harden the browser.",
    "creator": "Selective openness for public figures — public persona stays visible, personal data locks down.",
    "family_device": "Kid-safe defaults, parental controls, guest accounts, restricted installs.",
    "work_machine": "Respecting corporate policy while hardening what the user controls.",
}

_INSTRUCTIONS_TEMPLATE = """You are a calm, non-judgmental intake assistant for a computer security and \
privacy tool. Have a short conversation with someone who just started the tool to figure out their \
situation, then recommend exactly one of these threat-model profiles:

{profiles}

Ask at most 2-3 short clarifying questions before recommending a profile. Never ask for sensitive \
details you don't need (passwords, exact addresses, legal names). Respond with ONLY a JSON object, \
no other text, in one of these two forms:

To ask a clarifying question:
{{"type": "question", "message": "<your question>"}}

To give a final recommendation:
{{"type": "recommendation", "message": "<one short paragraph explaining why, in plain language>", "profile": "<profile_slug>"}}
"""


@dataclass
class RecommenderTurn:
    message: str
    is_recommendation: bool = False
    profile_slug: str | None = None


class ProfileRecommender:
    def __init__(self, provider: AIProvider, profiles: dict[str, str] | None = None):
        self.provider = provider
        self.profiles = profiles or PROFILE_DESCRIPTIONS
        self.history: list[AIMessage] = []

    def ask(self, user_message: str) -> RecommenderTurn:
        self.history.append(AIMessage(role="user", content=user_message))
        raw = self.provider.complete(messages=self.history, system=self._system_prompt())
        self.history.append(AIMessage(role="assistant", content=raw))
        return self._parse_turn(raw)

    async def ask_async(self, user_message: str) -> RecommenderTurn:
        self.history.append(AIMessage(role="user", content=user_message))
        raw = await self.provider.complete_async(
            messages=self.history, system=self._system_prompt()
        )
        self.history.append(AIMessage(role="assistant", content=raw))
        return self._parse_turn(raw)

    def _system_prompt(self) -> str:
        profile_lines = "\n".join(
            f"- {slug}: {desc}" for slug, desc in self.profiles.items()
        )
        return _INSTRUCTIONS_TEMPLATE.format(profiles=profile_lines)

    @staticmethod
    def _parse_turn(raw: str) -> RecommenderTurn:
        try:
            data = json.loads(raw)
            message = data.get("message", raw)
            is_recommendation = data.get("type") == "recommendation"
            profile_slug = data.get("profile") if is_recommendation else None
            return RecommenderTurn(
                message=message,
                is_recommendation=is_recommendation,
                profile_slug=profile_slug,
            )
        except (json.JSONDecodeError, AttributeError, TypeError):
            return RecommenderTurn(message=raw, is_recommendation=False, profile_slug=None)
