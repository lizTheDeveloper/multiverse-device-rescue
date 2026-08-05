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
