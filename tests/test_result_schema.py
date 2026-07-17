"""Richer, honest result schema (roadmap P1#1): confidence on findings and an
explicit 'unsupported' outcome distinct from a healthy (no-issues) result."""

from rescue.models import (
    CheckResult, CheckStatus, Finding, Severity,
)


def test_finding_confidence_defaults_to_none_and_is_optional():
    f = Finding("t", "d", Severity.INFO, "cat")
    assert f.confidence is None
    f2 = Finding("t", "d", Severity.INFO, "cat", confidence=0.9)
    assert f2.confidence == 0.9


def test_checkresult_status_healthy_when_ran_clean():
    r = CheckResult(module_name="m")
    assert r.status == CheckStatus.HEALTHY
    assert not r.has_issues


def test_checkresult_status_issues_when_findings_present():
    r = CheckResult(
        module_name="m",
        findings=[Finding("t", "d", Severity.WARNING, "cat")],
    )
    assert r.status == CheckStatus.ISSUES


def test_checkresult_status_failed_when_error_set():
    r = CheckResult(module_name="m", error="boom")
    assert r.status == CheckStatus.FAILED


def test_checkresult_unsupported_is_not_a_false_healthy():
    r = CheckResult(module_name="m", supported=False, unsupported_reason="needs admin")
    assert r.status == CheckStatus.UNSUPPORTED
    assert not r.has_issues
    # An unsupported check must be distinguishable from a healthy one.
    assert r.status != CheckStatus.HEALTHY
