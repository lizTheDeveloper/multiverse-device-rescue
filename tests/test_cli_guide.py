from unittest.mock import patch

from click.testing import CliRunner

from rescue.cli import main
from rescue.guides import Guide, GuideStep
from rescue.profiles import Profile


FAKE_PROFILE = Profile(
    name="test_profile",
    display_name="Test Profile",
    description="A profile for testing guides.",
    guides=["test_profile"],
)

FAKE_GUIDE = Guide(
    profile="test_profile",
    phase=0,
    title="Getting Started",
    estimated_time="10 minutes",
    steps=[
        GuideStep(number=1, title="Automated check", body="...", automatable=True),
        GuideStep(number=2, title="Manual review", body="...", automatable=False),
    ],
    automatable_steps=[1],
    human_only_steps=[2],
)

# Regression fixture: a guide set whose only phase is numbered 1, not 0.
# A fresh SessionState always starts at current_phase=0, so the CLI must
# detect that 0 doesn't match any authored phase and jump to phase 1
# *before* recording any --complete step against the (wrong) phase 0.
FAKE_GUIDE_PHASE_1 = Guide(
    profile="test_profile",
    phase=1,
    title="Only Phase",
    estimated_time="5 minutes",
    steps=[
        GuideStep(number=1, title="First step", body="...", automatable=False),
        GuideStep(number=2, title="Second step", body="...", automatable=False),
    ],
    automatable_steps=[],
    human_only_steps=[1, 2],
)


def test_profiles_command_lists_profiles():
    with patch("rescue.cli.discover_profiles", return_value={"test_profile": FAKE_PROFILE}):
        runner = CliRunner()
        result = runner.invoke(main, ["profiles"])

    assert result.exit_code == 0
    assert "test_profile" in result.output
    assert "Test Profile" in result.output


def test_guide_command_unknown_profile():
    with patch("rescue.cli.discover_profiles", return_value={}):
        runner = CliRunner()
        result = runner.invoke(main, ["guide", "nonexistent"])

    assert result.exit_code != 0


def test_guide_command_renders_steps(tmp_path):
    with patch("rescue.cli.discover_profiles", return_value={"test_profile": FAKE_PROFILE}), \
         patch("rescue.cli.discover_guides", return_value=[FAKE_GUIDE]), \
         patch("rescue.cli._get_session_dir", return_value=tmp_path):
        runner = CliRunner()
        result = runner.invoke(main, ["guide", "test_profile"])

    assert result.exit_code == 0
    assert "Getting Started" in result.output
    assert "[automatable] [pending] Step 1" in result.output
    assert "[human] [pending] Step 2" in result.output


def test_guide_command_mark_step_complete_persists(tmp_path):
    with patch("rescue.cli.discover_profiles", return_value={"test_profile": FAKE_PROFILE}), \
         patch("rescue.cli.discover_guides", return_value=[FAKE_GUIDE]), \
         patch("rescue.cli._get_session_dir", return_value=tmp_path):
        runner = CliRunner()
        runner.invoke(main, ["guide", "test_profile", "--complete", "2"])
        result = runner.invoke(main, ["guide", "test_profile"])

    assert result.exit_code == 0
    assert "[human] [done] Step 2" in result.output


def test_guide_command_fresh_session_jumps_to_first_authored_phase(tmp_path):
    """Regression test: a guide set starting at phase 1 (not 0) must not be
    reported as already complete on a fresh session, and completing a step
    must be recorded against phase 1, not the stale default phase 0."""
    with patch("rescue.cli.discover_profiles", return_value={"test_profile": FAKE_PROFILE}), \
         patch("rescue.cli.discover_guides", return_value=[FAKE_GUIDE_PHASE_1]), \
         patch("rescue.cli._get_session_dir", return_value=tmp_path):
        runner = CliRunner()

        first = runner.invoke(main, ["guide", "test_profile"])
        assert "All phases complete!" not in first.output
        assert "Only Phase" in first.output
        assert "[human] [pending] Step 1" in first.output

        runner.invoke(main, ["guide", "test_profile", "--complete", "1"])
        second = runner.invoke(main, ["guide", "test_profile"])

    assert "[human] [done] Step 1" in second.output


def test_auto_mode_with_unknown_profile_exits_nonzero():
    with patch("rescue.cli.discover_profiles", return_value={}):
        runner = CliRunner()
        result = runner.invoke(main, ["--auto", "--profile", "nonexistent"])

    assert result.exit_code != 0


def test_auto_mode_with_known_profile_passes_to_orchestrator():
    with patch("rescue.cli.discover_profiles", return_value={"test_profile": FAKE_PROFILE}), \
         patch("rescue.cli.Orchestrator") as MockOrch:
        instance = MockOrch.return_value
        instance.run_auto.return_value = []
        runner = CliRunner()
        result = runner.invoke(main, ["--auto", "--profile", "test_profile"])

    assert result.exit_code == 0
    _, kwargs = MockOrch.call_args
    assert kwargs["profile"] is FAKE_PROFILE
    assert "Test Profile" in result.output
