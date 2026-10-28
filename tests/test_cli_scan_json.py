import json
from unittest.mock import patch
from click.testing import CliRunner
from rescue.cli import main
from rescue.models import CheckResult, Finding, Severity

# click >= 8.2 removed CliRunner(mix_stderr=...): stdout and stderr are always
# captured separately now, and result.stdout is stdout alone. That is exactly what
# these tests need -- 'rescue scan --json' must put one pure JSON document on
# stdout with diagnostics kept off it -- so the runner is constructed bare.


def test_scan_json_is_single_valid_json_document_on_stdout():
    # Mock the Orchestrator to return a small set of results quickly
    mock_mod = type('MockModule', (), {'name': 'test_module', 'report': lambda self, check, fix=None: ''})()
    mock_result = CheckResult(module_name='test_module', findings=[])

    with patch('rescue.cli.Orchestrator') as MockOrch:
        instance = MockOrch.return_value
        instance.run_checks.return_value = [(mock_mod, mock_result)]

        result = CliRunner().invoke(main, ["scan", "--json"])

    assert result.exit_code == 0, result.output
    doc = json.loads(result.stdout)          # must parse: stdout is pure JSON
    assert doc["schema_version"] == 1
    assert isinstance(doc["platform"], str)
    assert isinstance(doc["modules"], list)


def test_scan_json_handles_bytes_and_exotic_values_in_finding_data():
    # Real module data dicts occasionally hold non-JSON-native values (e.g.
    # bytes from a subprocess). A single such value must not crash the whole
    # scan's JSON output. Regression for a real run that raised
    # "TypeError: Object of type bytes is not JSON serializable".
    mock_mod = type('MockModule', (), {'name': 'test_module', 'report': lambda self, check, fix=None: ''})()
    finding = Finding(
        title="Bytes finding",
        description="data holds bytes",
        severity=Severity.INFO,
        category="test",
        data={"volume": b"Macintosh HD", "count": 3},
    )
    mock_result = CheckResult(module_name='test_module', findings=[finding])

    with patch('rescue.cli.Orchestrator') as MockOrch:
        MockOrch.return_value.run_checks.return_value = [(mock_mod, mock_result)]
        result = CliRunner().invoke(main, ["scan", "--json"])

    assert result.exit_code == 0, result.output
    doc = json.loads(result.stdout)          # must not raise
    data = doc["modules"][0]["findings"][0]["data"]
    assert data["volume"] == "Macintosh HD"  # bytes decoded to str
    assert data["count"] == 3


def test_scan_json_enums_are_strings():
    # Mock the Orchestrator and create a mock Finding with an enum Severity
    mock_mod = type('MockModule', (), {'name': 'test_module', 'report': lambda self, check, fix=None: ''})()
    finding = Finding(
        title="Test Finding",
        description="A test finding",
        severity=Severity.WARNING,
        category="test",
        code="test.test.test"
    )
    mock_result = CheckResult(module_name='test_module', findings=[finding])

    with patch('rescue.cli.Orchestrator') as MockOrch:
        instance = MockOrch.return_value
        instance.run_checks.return_value = [(mock_mod, mock_result)]

        result = CliRunner().invoke(main, ["scan", "--json"])

    doc = json.loads(result.stdout)
    for mod in doc["modules"]:
        assert isinstance(mod["status"], str)
        for f in mod["findings"]:
            assert isinstance(f["severity"], str)   # not an Enum repr


def test_scan_json_marks_a_check_that_could_not_run():
    # A check that cannot run here is not a clean result. The text output says
    # "Check unavailable"; the JSON must carry the same signal, or the desktop
    # app and any script reading it report the machine as healthy.
    mock_mod = type('MockModule', (), {'name': 'needs_root', 'report': lambda self, check, fix=None: ''})()
    mock_result = CheckResult(
        module_name='needs_root', supported=False,
        unsupported_reason='The neighbour table could not be read.')

    with patch('rescue.cli.Orchestrator') as MockOrch:
        MockOrch.return_value.run_checks.return_value = [(mock_mod, mock_result)]
        result = CliRunner().invoke(main, ["scan", "--json"])

    assert result.exit_code == 0, result.output
    mod = json.loads(result.stdout)["modules"][0]
    assert mod["supported"] is False
    assert mod["unsupported_reason"] == 'The neighbour table could not be read.'


def test_scan_profile_limits_the_scan_to_that_profile():
    # The desktop app's "what are you worried about?" screen runs one
    # situation's checks, not all of them.
    with patch('rescue.cli.Orchestrator') as MockOrch, \
         patch('rescue.cli._load_profile_or_exit') as load:
        load.return_value = 'loaded-profile'
        MockOrch.return_value.run_checks.return_value = []
        result = CliRunner().invoke(main, ["scan", "--json", "--profile", "digital_security_reset"])

    assert result.exit_code == 0, result.output
    load.assert_called_once_with("digital_security_reset")
    assert MockOrch.call_args.kwargs["profile"] == 'loaded-profile'


def test_scan_progress_reports_each_check_on_stderr_and_keeps_stdout_pure():
    # The desktop app shows "Checking X (3 of 120)" from these lines; stdout
    # must still be exactly one JSON document.
    mod = type('MockModule', (), {'name': 'disk_space', 'category': 'performance',
                                  'report': lambda self, check, fix=None: ''})()
    check = CheckResult(module_name='disk_space')

    def fake_run_checks(on_progress=None):
        on_progress('start', 1, 1, mod, None)
        on_progress('done', 1, 1, mod, check)
        return [(mod, check)]

    with patch('rescue.cli.Orchestrator') as MockOrch:
        MockOrch.return_value.run_checks.side_effect = fake_run_checks
        result = CliRunner().invoke(main, ["scan", "--json", "--progress"])

    assert result.exit_code == 0, result.output
    json.loads(result.stdout)
    events = [json.loads(line)["progress"] for line in result.stderr.splitlines()
              if line.startswith('{"progress"')]
    assert [e["phase"] for e in events] == ["start", "done"]
    assert events[0] == {"phase": "start", "index": 1, "total": 1,
                         "module": "disk_space", "category": "performance"}
    assert events[1]["findings"] == 0 and events[1]["error"] is None
    assert events[1]["supported"] is True


def test_scan_progress_says_when_a_check_could_not_run_here():
    # The sweep's log must never show a check that couldn't run as "0 noted".
    mod = type('MockModule', (), {'name': 'disk_space', 'category': 'performance',
                                  'report': lambda self, check, fix=None: ''})()
    check = CheckResult(module_name='disk_space', supported=False, unsupported_reason='no tool')

    def fake_run_checks(on_progress=None):
        on_progress('done', 1, 1, mod, check)
        return [(mod, check)]

    with patch('rescue.cli.Orchestrator') as MockOrch:
        MockOrch.return_value.run_checks.side_effect = fake_run_checks
        result = CliRunner().invoke(main, ["scan", "--json", "--progress"])

    events = [json.loads(line)["progress"] for line in result.stderr.splitlines()
              if line.startswith('{"progress"')]
    assert events[0]["supported"] is False


def test_scan_trace_reports_commands_under_the_module_that_ran_them():
    import subprocess
    import sys
    mod = type('MockModule', (), {'name': 'disk_space', 'category': 'performance',
                                  'report': lambda self, check, fix=None: ''})()
    check = CheckResult(module_name='disk_space')

    def fake_run_checks(on_progress=None):
        on_progress('start', 1, 1, mod, None)
        subprocess.run([sys.executable, '-c', 'pass'])
        on_progress('done', 1, 1, mod, check)
        return [(mod, check)]

    with patch('rescue.cli.Orchestrator') as MockOrch:
        MockOrch.return_value.run_checks.side_effect = fake_run_checks
        result = CliRunner().invoke(main, ["scan", "--json", "--trace"])

    assert result.exit_code == 0, result.output
    json.loads(result.stdout)
    execs = [json.loads(line)["exec"] for line in result.stderr.splitlines()
             if line.startswith('{"exec"')]
    assert len(execs) == 1 and execs[0]["module"] == "disk_space"
    assert any(line.startswith('{"progress"') for line in result.stderr.splitlines())


def test_scan_json_attaches_the_fix_walkthrough_to_coded_findings():
    # The app shows "How to fix this" from these steps; a finding whose code
    # has no walkthrough simply has no "remediation" key.
    from rescue.guides import Guide, GuideStep
    mod = type('MockModule', (), {'name': 'clamav_scanner', 'report': lambda self, check, fix=None: ''})()
    coded = Finding(title="ClamAV missing", description="d", severity=Severity.WARNING,
                    category="security", code="security.clamav_scanner.clamav_not_installed")
    uncoded = Finding(title="Other", description="d", severity=Severity.WARNING, category="security")
    guide = Guide(profile=None, phase=None, title="Act on ClamAV scanner findings",
                  estimated_time="20 minutes",
                  steps=[GuideStep(number=1, title="Install ClamAV", body="brew install clamav", automatable=False)],
                  remediates=["security.clamav_scanner.clamav_not_installed"])

    with patch('rescue.cli.Orchestrator') as MockOrch, \
         patch('rescue.cli.load_remediation_walkthroughs', return_value={coded.code: guide}):
        MockOrch.return_value.run_checks.return_value = [
            (mod, CheckResult(module_name='clamav_scanner', findings=[coded, uncoded]))]
        result = CliRunner().invoke(main, ["scan", "--json"])

    assert result.exit_code == 0, result.output
    findings = json.loads(result.stdout)["modules"][0]["findings"]
    assert findings[0]["remediation"] == {
        "title": "Act on ClamAV scanner findings",
        "estimated_time": "20 minutes",
        "steps": [{"number": 1, "title": "Install ClamAV", "body": "brew install clamav"}],
        "all_steps": True,
    }
    assert "remediation" not in findings[1]
