"""Optional AI layer — diagnostic explanations, profile recommendations, and a
walkthrough copilot.

This package is entirely optional. The tool works fully without any AI
provider configured. These classes are only invoked when a user explicitly
passes --copilot (or runs `rescue recommend`) and an API key or local Ollama
instance is available. Nothing here ever calls ModuleBase.fix(),
Orchestrator.run_fixes(), or subprocess — the AI layer only reads structured
findings and guide text and returns strings.
"""

from rescue.ai.copilot import WalkthroughCopilot
from rescue.ai.explainer import DiagnosticExplainer, Explanation, build_findings_summary
from rescue.ai.factory import get_provider
from rescue.ai.recommender import PROFILE_DESCRIPTIONS, ProfileRecommender, RecommenderTurn

__all__ = [
    "WalkthroughCopilot",
    "DiagnosticExplainer",
    "Explanation",
    "build_findings_summary",
    "get_provider",
    "ProfileRecommender",
    "RecommenderTurn",
    "PROFILE_DESCRIPTIONS",
]
