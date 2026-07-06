from pathlib import Path

from rescue.guides import Guide, GuideStep, discover_guides, load_guide, parse_guide_markdown


SAMPLE_GUIDE = """---
profile: digital_security_reset
phase: 3
title: "Systematic Cleanup"
automatable_steps: [1, 2, 5]
human_only_steps: [3, 4, 6]
estimated_time: "45 minutes"
---

## Step 1: Reset your primary email password

Use a long, unique passphrase and store it in your password manager.

## Step 2: Reset passwords for your top 5 accounts

Banking, primary social, cloud storage, and work accounts first.

## Step 3: Clean up saved browser passwords

Remove anything tied to accounts you no longer use.

## Step 4: Contact your bank

Flag potential compromise with your financial institutions.

## Step 5: Run the 2FA audit

Enable two-factor authentication wherever it's missing.

## Step 6: Write down your progress

Keep a paper list of every account you've secured so far.
"""


def test_parse_guide_markdown_frontmatter():
    guide = parse_guide_markdown(SAMPLE_GUIDE)

    assert guide.profile == "digital_security_reset"
    assert guide.phase == 3
    assert guide.title == "Systematic Cleanup"
    assert guide.estimated_time == "45 minutes"
    assert guide.automatable_steps == [1, 2, 5]
    assert guide.human_only_steps == [3, 4, 6]


def test_parse_guide_markdown_steps():
    guide = parse_guide_markdown(SAMPLE_GUIDE)

    assert len(guide.steps) == 6
    assert guide.steps[0].number == 1
    assert guide.steps[0].title == "Reset your primary email password"
    assert "passphrase" in guide.steps[0].body
    assert guide.steps[0].automatable is True

    assert guide.steps[2].number == 3
    assert guide.steps[2].automatable is False


def test_load_guide(tmp_path):
    guide_path = tmp_path / "phase_3.md"
    guide_path.write_text(SAMPLE_GUIDE)

    guide = load_guide(guide_path)

    assert guide.phase == 3
    assert len(guide.steps) == 6


def test_discover_guides_sorted_by_phase(tmp_path):
    profile_dir = tmp_path / "digital_security_reset"
    profile_dir.mkdir()

    phase_1 = SAMPLE_GUIDE.replace("phase: 3", "phase: 1").replace(
        '"Systematic Cleanup"', '"Reality Check"'
    )
    phase_0 = SAMPLE_GUIDE.replace("phase: 3", "phase: 0").replace(
        '"Systematic Cleanup"', '"Emergency Grounding"'
    )

    # Written in reverse order on disk to prove sorting is by phase, not filename
    (profile_dir / "z_phase_3.md").write_text(SAMPLE_GUIDE)
    (profile_dir / "a_phase_1.md").write_text(phase_1)
    (profile_dir / "m_phase_0.md").write_text(phase_0)

    guides = discover_guides(tmp_path, "digital_security_reset")

    assert [g.phase for g in guides] == [0, 1, 3]
    assert guides[0].title == "Emergency Grounding"


def test_discover_guides_missing_profile_dir(tmp_path):
    guides = discover_guides(tmp_path, "nonexistent_profile")
    assert guides == []
