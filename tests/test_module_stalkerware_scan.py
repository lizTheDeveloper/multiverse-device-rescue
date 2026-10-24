import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import (
    Mode,
    Platform,
    ProcessInfo,
    RiskLevel,
    Severity,
    SystemProfile,
)
from rescue.registry import discover_modules

DATA_FILE = (
    Path(__file__).parent.parent
    / "modules" / "security" / "stalkerware_scan" / "data" / "known_stalkerware.json"
)


def _make_profile(processes=(), installed=(), platform=Platform.DARWIN):
    return SystemProfile(
        platform=platform,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
        processes=list(processes),
        installed_software=list(installed),
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "stalkerware_scan")


def _namespace(mod):
    return sys.modules[type(mod).__module__]


def _process(name, command=""):
    return ProcessInfo(
        pid=42, name=name, cpu_percent=1.0, memory_bytes=1024, command=command or name
    )


def _check(mod, profile):
    """Run check with the filesystem and registry scans stubbed out."""
    namespace = _namespace(mod)
    with patch("subprocess.run", return_value=MagicMock(stdout="", returncode=0)):
        with patch.object(namespace, "_DARWIN_APP_DIRS", []):
            with patch.object(namespace, "_DARWIN_PERSISTENCE_DIRS", []):
                return mod.check(profile)


def test_module_discovered():
    mod = _get_module()
    assert mod.name == "stalkerware_scan"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert set(mod.platforms) == {Platform.DARWIN, Platform.WIN32, Platform.LINUX}


def test_data_file_is_valid_and_categorised():
    with open(DATA_FILE) as f:
        data = json.load(f)
    entries = data["entries"]
    assert len(entries) >= 20
    valid_categories = {
        "stalkerware",
        "employee_monitoring",
        "parental_control",
        "remote_access",
    }
    for entry in entries:
        assert entry["category"] in valid_categories
        assert entry["severity"] in {"critical", "warning", "info"}
        assert entry["platforms"]
        assert entry["description"]


def test_clean_machine_has_no_findings():
    mod = _get_module()
    result = _check(mod, _make_profile(processes=[_process("Finder")]))
    assert not result.has_issues


def test_stalkerware_process_is_critical():
    mod = _get_module()
    result = _check(
        mod,
        _make_profile(processes=[_process("mSpy Agent", "/Applications/mSpy.app/agent")]),
    )

    findings = result.findings
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].data["stalkerware_category"] == "stalkerware"
    assert findings[0].data["confidence"] == "high"


def test_remote_access_tool_is_reported_on_linux_without_calling_it_malware():
    # remote_access_tools covers macOS and Windows; on Linux this check still
    # lists the remote tools, so nothing goes unreported there.
    mod = _get_module()
    result = _check(mod, _make_profile(installed=["TeamViewer Host"], platform=Platform.LINUX))

    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.INFO
    assert result.findings[0].data["stalkerware_category"] == "remote_access"


def test_stalkerware_scan_no_longer_reports_teamviewer():
    # On macOS and Windows remote tools are remote_access_tools' job: one tool, one report.
    mod = _get_module()
    for platform in (Platform.DARWIN, Platform.WIN32):
        result = _check(mod, _make_profile(processes=[_process("TeamViewer"), _process("AnyDesk.exe")],
                                           installed=["TeamViewer Host", "AnyDesk"], platform=platform))
        assert not result.findings, platform


def test_remote_access_entries_are_linux_only():
    with open(DATA_FILE) as f:
        entries = json.load(f)["entries"]
    remote = [e for e in entries if e["category"] == "remote_access"]
    assert remote
    assert all(e["platforms"] == ["linux"] for e in remote)


def test_short_product_names_do_not_match_inside_longer_words():
    mod = _get_module()
    # "bark" is a parental-control product; "barkeeper" is not it.
    result = _check(mod, _make_profile(processes=[_process("barkeeper")]))
    assert not result.has_issues


def test_platform_specific_entries_are_skipped_on_other_platforms():
    mod = _get_module()
    # Spyrix is a Windows-only product in the dataset.
    result = _check(
        mod, _make_profile(processes=[_process("spyrix")], platform=Platform.DARWIN)
    )
    assert not result.has_issues

    result = _check(
        mod, _make_profile(processes=[_process("spyrix")], platform=Platform.LINUX)
    )
    assert not result.has_issues


def test_the_same_product_found_twice_is_reported_once_per_location():
    mod = _get_module()
    result = _check(
        mod,
        _make_profile(
            processes=[_process("mSpy Agent", "/Applications/mSpy.app/agent")],
            installed=["mSpy"],
        ),
    )
    locations = {f.data["location"] for f in result.findings}
    assert len(result.findings) == len(locations) == 2


def test_fix_leads_with_safety_guidance_before_removal():
    mod = _get_module()
    result = _check(
        mod,
        _make_profile(processes=[_process("mSpy Agent", "/Applications/mSpy.app/agent")]),
    )

    fix = mod.fix(result, Mode.CLI)
    titles = [action.title for action in fix.actions]

    assert titles[0] == "Read this before removing the monitoring software"
    assert "1-800-799-7233" in fix.actions[0].description
    removal_index = next(i for i, t in enumerate(titles) if t.startswith("Remove mSpy"))
    assert removal_index > 0
    assert all(action.kind.value == "guidance" for action in fix.actions)


def test_remote_access_only_findings_skip_the_stalkerware_safety_preamble():
    mod = _get_module()
    # Linux: on macOS and Windows remote tools are remote_access_tools' job.
    result = _check(mod, _make_profile(installed=["AnyDesk"], platform=Platform.LINUX))

    fix = mod.fix(result, Mode.CLI)
    titles = [action.title for action in fix.actions]

    assert titles == ["Account for the remote access tool AnyDesk"]


def test_fix_does_nothing_without_findings():
    mod = _get_module()
    result = _check(mod, _make_profile())
    assert mod.fix(result, Mode.CLI).actions == []


def test_missing_data_file_is_reported_as_unavailable_not_healthy():
    mod = _get_module()
    namespace = _namespace(mod)
    with patch.object(namespace, "DATA_FILE", Path("/does/not/exist.json")):
        result = mod.check(_make_profile())
    assert result.error is not None
    assert not result.findings


# Dual-use products: what they are made for, and how the person can tell
# whether this one is theirs (the owner's rule: worried -> treat it as
# monitoring; work or a child's computer and not worried -> most likely that).

def _desc(mod, profile):
    findings = _check(mod, profile).findings
    assert len(findings) == 1
    return findings[0]


def test_employee_monitoring_says_what_it_is_for_and_how_to_tell():
    mod = _get_module()
    ns = _namespace(mod)
    f = _desc(mod, _make_profile(processes=[_process("Teramind Agent")]))
    assert f.data["stalkerware_category"] == "employee_monitoring"
    text = f.description
    # The product's own first sentence still leads.
    assert text.startswith("Workplace monitoring agent recording screen, keystrokes, and application use.")
    for sentence in (ns._PURPOSE_EMPLOYEE, ns._HOW_TO_TELL_WORRIED, ns._HOW_TO_TELL_WORK):
        assert sentence in text
    assert "an employer recording activity on work computers" in ns._PURPOSE_EMPLOYEE
    assert ns._HOW_TO_TELL_WORRIED == (
        "If you're worried someone is watching you, treat it as monitoring software someone put "
        "here without asking: don't remove it yet, and write down what was found and when."
    )
    assert ns._HOW_TO_TELL_WORK == (
        "If this is a work computer and you aren't worried, it's most likely there for work; "
        "your IT department can tell you."
    )
    assert ns._HOW_TO_TELL_CHILD not in text


def test_parental_control_says_what_it_is_for_and_how_to_tell():
    mod = _get_module()
    ns = _namespace(mod)
    f = _desc(mod, _make_profile(processes=[_process("Qustodio")]))
    assert f.data["stalkerware_category"] == "parental_control"
    text = f.description
    assert text.startswith("Parental control software.")
    for sentence in (ns._PURPOSE_PARENTAL, ns._HOW_TO_TELL_WORRIED, ns._HOW_TO_TELL_CHILD):
        assert sentence in text
    assert "a parent watching a child's messages, browsing and screen time" in ns._PURPOSE_PARENTAL
    assert ns._HOW_TO_TELL_CHILD == (
        "If a parent set it up on a child's computer and only that parent gets its reports, it's most likely that."
    )
    assert ns._HOW_TO_TELL_WORK not in text


def test_how_to_tell_avoids_relationship_words():
    ns = _namespace(_get_module())
    import re
    words = re.compile(r"partner|\bex\b|abuser|stalk|housemate|advocate|hotline", re.I)
    for s in (ns._PURPOSE_EMPLOYEE, ns._PURPOSE_PARENTAL, ns._HOW_TO_TELL_WORRIED,
              ns._HOW_TO_TELL_WORK, ns._HOW_TO_TELL_CHILD):
        assert not words.search(s), s


def test_known_product_descriptions_avoid_relationship_words():
    # A product's description is the first sentence of its card in standard mode, where QuietNotes keeps it:
    # "monitoring another adult", never partner, ex, abuser or stalker.
    import re
    words = re.compile(r"partner|\bex\b|\bexes\b|abuser|\bstalker\b|housemate|spouse", re.I)
    data = json.loads((Path(__file__).resolve().parent.parent / "modules" / "security" / "stalkerware_scan" / "data"
                       / "known_stalkerware.json").read_text(encoding="utf-8"))
    entries = [e for v in data.values() if isinstance(v, list) for e in v if isinstance(e, dict)]
    assert entries
    for e in entries:
        assert not words.search(e.get("description", "")), e.get("name")


def test_dual_use_findings_keep_the_removal_warning_sentence():
    mod = _get_module()
    for proc in ("Qustodio", "Teramind Agent"):
        f = _desc(mod, _make_profile(processes=[_process(proc)]))
        assert "Removing it can alert whoever installed it." in f.description
        assert "1-800-799-7233" in f.description


def test_every_parental_control_entry_is_at_least_a_warning():
    # A parental tool on an adult's computer is the commonest repurposed
    # monitoring, so it carries the removal warning like the rest.
    with open(DATA_FILE) as f:
        entries = json.load(f)["entries"]
    parental = [e for e in entries if e["category"] == "parental_control"]
    assert parental
    assert all(e["severity"] in {"warning", "critical"} for e in parental), [
        e["name"] for e in parental if e["severity"] == "info"]


def test_parental_finding_is_a_warning_and_its_screens_treat_it_as_monitoring():
    from rescue import safety_scope
    from rescue.remediation import _removal_warning

    mod = _get_module()
    f = _desc(mod, _make_profile(processes=[_process("Qustodio")]))
    assert f.severity == Severity.WARNING
    # The monitoring checks always carry the removal warning on every screen
    # (rescue/safety_scope.py); the finding code is one of them.
    assert mod.name in safety_scope.MONITORING_MODULES
    assert _removal_warning(mod.name, f.code) == "monitoring check: always"


def test_stalkerware_text_is_unchanged():
    mod = _get_module()
    f = _desc(mod, _make_profile(processes=[_process("mSpy Agent", "/Applications/mSpy.app/agent")]))
    assert f.description == (
        "Covert monitoring suite that records keystrokes, messages, browsing, and location, and hides "
        "itself from the person being monitored.\n\n"
        "Found as running process: mSpy Agent (pid 42).\n\n"
        "This product is sold for watching another person without their knowledge. If nobody told you "
        "it was here, someone installed it to watch what you do on this computer.\n\n"
        "Removing it can alert whoever installed it. If you think that's someone close to you, talk to "
        "an advocate before you touch it (US National Domestic Violence Hotline: 1-800-799-7233, or text "
        "START to 88788).\n\n"
        "What to do: Don't remove it yet. Write down its name, where it was found and today's date, and "
        "make a safety plan first."
    )


def test_remote_access_text_keeps_its_honest_uses_paragraph():
    mod = _get_module()
    f = _desc(mod, _make_profile(installed=["TeamViewer Host"], platform=Platform.LINUX))
    assert "Apps like this have honest uses" in f.description


def test_safety_note_adds_trafficking_and_workers_help_and_keeps_the_dv_hotline():
    ns = _namespace(_get_module())
    note = ns._SAFETY_WARNING
    assert "National Domestic Violence Hotline, 1-800-799-7233" in note
    assert "National Human Trafficking Hotline" in note
    assert "1-888-373-7888, or text 233733" in note
    assert "workers' rights group or legal aid" in note


def test_work_monitoring_fix_guidance_asks_who_sees_it_and_never_says_illegal():
    mod = _get_module()
    result = _check(mod, _make_profile(processes=[_process("Teramind Agent")]))
    fix = mod.fix(result, Mode.CLI)
    text = fix.actions[0].description
    assert "what it records, when, and who sees it" in text
    assert "workers' rights group or legal aid" in text
    assert "1-888-373-7888" in text
    assert "illegal" not in text.lower()
