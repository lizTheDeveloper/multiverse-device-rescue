import asyncio
import json
from unittest.mock import MagicMock

from rescue.ai.recommender import PROFILE_DESCRIPTIONS, ProfileRecommender, RecommenderTurn


def test_ask_returns_question_turn():
    fake_provider = MagicMock()
    fake_provider.complete.return_value = json.dumps(
        {
            "type": "question",
            "message": "Are you worried about a specific person having access to your accounts?",
        }
    )

    recommender = ProfileRecommender(fake_provider)
    turn = recommender.ask("Something feels off with my accounts.")

    assert isinstance(turn, RecommenderTurn)
    assert turn.is_recommendation is False
    assert turn.profile_slug is None
    assert "specific person" in turn.message


def test_ask_returns_recommendation_turn():
    fake_provider = MagicMock()
    fake_provider.complete.return_value = json.dumps(
        {
            "type": "recommendation",
            "message": "It sounds like someone you used to trust may have access to your accounts.",
            "profile": "digital_security_reset",
        }
    )

    recommender = ProfileRecommender(fake_provider)
    turn = recommender.ask("My ex still knows all my passwords.")

    assert turn.is_recommendation is True
    assert turn.profile_slug == "digital_security_reset"


def test_ask_falls_back_to_raw_text_on_invalid_json():
    fake_provider = MagicMock()
    fake_provider.complete.return_value = "Sorry, I didn't understand that — can you say more?"

    recommender = ProfileRecommender(fake_provider)
    turn = recommender.ask("???")

    assert turn.is_recommendation is False
    assert turn.profile_slug is None
    assert turn.message == "Sorry, I didn't understand that — can you say more?"


def test_history_accumulates_across_turns():
    fake_provider = MagicMock()
    fake_provider.complete.side_effect = [
        json.dumps({"type": "question", "message": "Tell me more?"}),
        json.dumps(
            {"type": "recommendation", "message": "Got it.", "profile": "personal_lockdown"}
        ),
    ]

    recommender = ProfileRecommender(fake_provider)
    recommender.ask("I just want more privacy day to day.")
    recommender.ask("No specific threat, just general caution.")

    assert len(recommender.history) == 4  # 2 user turns + 2 assistant turns
    assert recommender.history[0].role == "user"
    assert recommender.history[1].role == "assistant"


def test_ask_async_returns_turn():
    fake_provider = MagicMock()

    async def fake_complete_async(messages, system=None):
        return json.dumps(
            {"type": "recommendation", "message": "Six Roses fits.", "profile": "six_roses"}
        )

    fake_provider.complete_async = fake_complete_async

    recommender = ProfileRecommender(fake_provider)
    turn = asyncio.run(recommender.ask_async("My ex is tracking my location."))

    assert turn.is_recommendation is True
    assert turn.profile_slug == "six_roses"


def test_profile_descriptions_cover_all_spec_profiles():
    expected_slugs = {
        "digital_security_reset",
        "six_roses",
        "activist_security",
        "journalist_security",
        "home_for_the_holidays",
        "personal_lockdown",
        "creator",
        "family_device",
        "work_machine",
    }
    assert expected_slugs == set(PROFILE_DESCRIPTIONS.keys())
