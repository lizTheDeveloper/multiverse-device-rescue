from __future__ import annotations

from dataclasses import dataclass

from rescue.ai.providers.base import AIMessage, AIProvider
from rescue.models import CheckResult
from rescue.module_base import ModuleBase

_SYSTEM_PROMPT = (
    "You are a friendly computer diagnostic assistant. You are given a list of "
    "findings from an automated system scan, one per line, in the format "
    "'[category/module] (severity) title: description'. Write a short, plain-"
    "language narrative (2-4 sentences) explaining what's wrong and why it "
    "matters, grouping related findings together where it makes sense. Do not "
    "suggest shell commands to run and do not claim you will fix anything — "
    "you are explaining, not acting. Avoid jargon where possible."
)


@dataclass
class Explanation:
    narrative: str
    provider_name: str


class DiagnosticExplainer:
    def __init__(self, provider: AIProvider):
        self.provider = provider

    def explain(self, results: list[tuple[ModuleBase, CheckResult]]) -> Explanation:
        summary = build_findings_summary(results)
        if not summary:
            return Explanation(
                narrative="No issues found — nothing to explain.",
                provider_name=self.provider.provider_name,
            )
        narrative = self.provider.complete(
            messages=[AIMessage(role="user", content=summary)],
            system=_SYSTEM_PROMPT,
        )
        return Explanation(narrative=narrative, provider_name=self.provider.provider_name)

    async def explain_async(
        self, results: list[tuple[ModuleBase, CheckResult]]
    ) -> Explanation:
        summary = build_findings_summary(results)
        if not summary:
            return Explanation(
                narrative="No issues found — nothing to explain.",
                provider_name=self.provider.provider_name,
            )
        narrative = await self.provider.complete_async(
            messages=[AIMessage(role="user", content=summary)],
            system=_SYSTEM_PROMPT,
        )
        return Explanation(narrative=narrative, provider_name=self.provider.provider_name)


def build_findings_summary(results: list[tuple[ModuleBase, CheckResult]]) -> str:
    lines = []
    for mod, check in results:
        for finding in check.findings:
            lines.append(
                f"[{mod.category}/{mod.name}] ({finding.severity.value}) "
                f"{finding.title}: {finding.description}"
            )
    return "\n".join(lines)
