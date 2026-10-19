import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "update_checker")


SOFTWAREUPDATE_PENDING = """Software Update Tool

Finding available software
Software Update found the following new or updated software:
* Label: macOS Sequoia 15.3-24D60
\tTitle: macOS Sequoia 15.3, Version: 15.3, Size: 3193980KiB, Recommended: YES,
* Label: Safari18.3-18.3
\tTitle: Safari, Version: 18.3, Size: 43112KiB, Recommended: YES,
"""

SOFTWAREUPDATE_NONE = "No new software available.\n"

BREW_OUTDATED_SOME = """git (2.43.0) < 2.44.0
node (21.6.0) < 21.7.0
"""

BREW_OUTDATED_NONE = ""


def _fake_run(softwareupdate_output, brew_output, brew_missing=False):
    def fake_run(cmd, **kwargs):
        if cmd[0] == "softwareupdate":
            result = MagicMock()
            result.stdout = softwareupdate_output
            result.returncode = 0
            return result
        elif cmd[0] == "brew":
            if brew_missing:
                raise FileNotFoundError("brew not found")
            result = MagicMock()
            result.stdout = brew_output
            result.returncode = 0
            return result
        raise AssertionError(f"unexpected command {cmd}")
    return fake_run


def test_update_checker_discovered():
    mod = _get_module()
    assert mod.name == "update_checker"
    assert mod.risk_level == RiskLevel.SAFE


def test_update_checker_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(SOFTWAREUPDATE_NONE, BREW_OUTDATED_NONE)):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_update_checker_pending_os_updates():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(SOFTWAREUPDATE_PENDING, BREW_OUTDATED_NONE)):
        result = mod.check(_make_profile())
    assert result.has_issues
    finding = next(f for f in result.findings if f.data["check"] == "os_updates")
    assert len(finding.data["updates"]) == 2
    assert finding.severity == Severity.WARNING


def test_update_checker_outdated_brew():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(SOFTWAREUPDATE_NONE, BREW_OUTDATED_SOME)):
        result = mod.check(_make_profile())
    assert result.has_issues
    finding = next(f for f in result.findings if f.data["check"] == "brew_outdated")
    assert finding.data["packages"] == ["git", "node"]


def test_update_checker_brew_not_installed():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(SOFTWAREUPDATE_NONE, "", brew_missing=True)):
        result = mod.check(_make_profile())
    assert not result.has_issues  # no crash — brew check silently skipped


def test_update_checker_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(SOFTWAREUPDATE_PENDING, BREW_OUTDATED_SOME)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)
    assert fix.all_succeeded
    assert len(fix.actions) == 2


# --- Regression: `softwareupdate -l` had no timeout. It asks Apple's servers
# and took over 60 s on a real Mac, so the whole check hit the engine's limit
# and was reported as "couldn't run", and the Homebrew part never ran.

def test_every_command_has_a_timeout_that_fits_the_engine_limit():
    import subprocess as sp

    mod = _get_module()
    timeouts = {}

    def fake(cmd, **kw):
        timeouts[cmd[0]] = kw.get("timeout")
        return _fake_run(SOFTWAREUPDATE_NONE, BREW_OUTDATED_NONE)(cmd, **kw)

    with patch.object(sp, "run", side_effect=fake):
        mod.check(_make_profile())
    assert timeouts["softwareupdate"] and timeouts["brew"]
    assert timeouts["softwareupdate"] + timeouts["brew"] < 60


def test_hanging_softwareupdate_is_not_checked_and_brew_still_runs():
    import subprocess as sp
    import time

    mod = _get_module()
    inner = _fake_run(SOFTWAREUPDATE_NONE, BREW_OUTDATED_SOME)

    def fake(cmd, **kw):
        if cmd[0] == "softwareupdate":
            raise sp.TimeoutExpired(cmd, kw["timeout"])
        return inner(cmd, **kw)

    start = time.monotonic()
    with patch.object(sp, "run", side_effect=fake):
        result = mod.check(_make_profile())
    assert time.monotonic() - start < 2

    by_check = {f.data["check"]: f for f in result.findings}
    note = by_check["os_updates_not_checked"]
    assert note.severity == Severity.INFO
    assert "doesn't mean your Mac is up to date" in note.description
    assert "os_updates" not in by_check
    # What it could check is kept.
    assert "brew_outdated" in by_check


def test_failed_softwareupdate_is_not_read_as_no_updates():
    import subprocess as sp

    mod = _get_module()

    def fake(cmd, **kw):
        result = MagicMock()
        result.stdout = ""
        result.returncode = 1 if cmd[0] == "softwareupdate" else 0
        return result

    with patch.object(sp, "run", side_effect=fake):
        result = mod.check(_make_profile())
    assert [f.data["check"] for f in result.findings] == ["os_updates_not_checked"]


def test_hanging_brew_is_not_checked():
    import subprocess as sp

    mod = _get_module()
    inner = _fake_run(SOFTWAREUPDATE_NONE, "")

    def fake(cmd, **kw):
        if cmd[0] == "brew":
            raise sp.TimeoutExpired(cmd, kw["timeout"])
        return inner(cmd, **kw)

    with patch.object(sp, "run", side_effect=fake):
        result = mod.check(_make_profile())
    assert [f.data["check"] for f in result.findings] == ["brew_not_checked"]
