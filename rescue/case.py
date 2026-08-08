"""Rescue-case records: what was found, what was done, and what it cost.

Roadmap P1#2: "There is no redacted export containing findings, actions
actually taken, action outcomes, operator confirmations, rollback information,
or post-fix verification." Without one, the output of a rescue lives in a
terminal scrollback — you cannot hand it to someone who can help, diff it
against a later run, or attach it to a support request.

Two properties matter more than the schema:

**It is redacted by construction, not by review.** The tool's whole promise is
that it never collects secrets. An export is the one artifact a user is likely
to paste into a chat window, an email, or a public issue, so the redaction runs
over every string that leaves here — including free-text finding descriptions
written by 280-odd modules that this code cannot audit individually. Patterns
cover the things whose disclosure is immediately harmful: tokens and keys,
authorization headers, private-key blocks, and the user's own account name as
it appears in filesystem paths.

**It is honest about what happened.** Guidance is recorded as guidance even if
a module marked it successful; a mutation is only recorded as a system change
if it executed and succeeded. That mirrors ``FixResult.executed_mutations``,
which exists for the same reason (roadmap P0#6).
"""

from __future__ import annotations

import getpass
import json
import platform
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rescue.models import (
    ActionKind,
    CheckResult,
    CheckStatus,
    FixResult,
    SystemProfile,
)
from rescue.module_base import ModuleBase

CASE_SCHEMA_VERSION = 1

_REDACTED = "[redacted]"

# Ordered most-specific first: a bearer token inside an Authorization header
# should be redacted by the header rule, not partially mangled by the generic
# token rule. Each pattern keeps the identifying prefix so the reader can still
# tell *what kind* of secret was present.
_REDACTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), f"{_REDACTED} private key"),
    # Consumes the rest of the line: an auth header's value is "Bearer <token>",
    # so stopping at the first whitespace would redact the scheme and leave the
    # credential sitting in the export.
    (re.compile(r"(?i)\b(authorization|proxy-authorization)\s*[:=].*"), r"\1: " + _REDACTED),
    (re.compile(r"(?i)\b(api[_-]?key|secret|password|passwd|token|access[_-]?key)\b\s*[:=]\s*\S+"), r"\1=" + _REDACTED),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}"), f"{_REDACTED} github token"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), f"{_REDACTED} api key"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), f"{_REDACTED} slack token"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), f"{_REDACTED} jwt"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), f"{_REDACTED} aws key id"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), f"{_REDACTED} email"),
]


def _home_patterns() -> list[tuple[re.Pattern[str], str]]:
    """Replace the operator's account name and home path with placeholders.

    A path like ``/Users/jsmith/Library/LaunchAgents/x.plist`` identifies a
    person; ``~/Library/LaunchAgents/x.plist`` carries the same diagnostic
    meaning. Computed per call rather than at import so tests (and a tool run
    under a different account) get the right value.
    """
    patterns = []
    try:
        home = str(Path.home())
    except (RuntimeError, OSError):
        home = ""
    if home and home not in ("/", ""):
        patterns.append((re.compile(re.escape(home)), "~"))
    try:
        user = getpass.getuser()
    except Exception:
        user = ""
    # Single-character or very short usernames would match far too much text.
    if user and len(user) >= 3:
        patterns.append((re.compile(rf"\b{re.escape(user)}\b"), "[user]"))
    return patterns


def redact(value: str, extra: list[tuple[re.Pattern[str], str]] | None = None) -> str:
    """Return ``value`` with credential-shaped and identifying text removed."""
    if not isinstance(value, str) or not value:
        return value
    result = value
    for pattern, replacement in _REDACTION_PATTERNS:
        result = pattern.sub(replacement, result)
    for pattern, replacement in extra or []:
        result = pattern.sub(replacement, result)
    return result


def _redact_any(value: Any, extra: list[tuple[re.Pattern[str], str]]) -> Any:
    """Recursively redact strings inside JSON-shaped data.

    Module ``Finding.data`` is free-form, so anything can be in there. Values
    that are not JSON-serializable are stringified first — an export that
    raises on an unexpected type would lose the whole case.
    """
    if isinstance(value, str):
        return redact(value, extra)
    if isinstance(value, dict):
        return {str(k): _redact_any(v, extra) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_any(v, extra) for v in value]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact(str(value), extra)


@dataclass
class CaseEntry:
    """One module's contribution to a case: its check and any fix attempted."""

    module: ModuleBase
    check: CheckResult
    fix: FixResult | None = None
    confirmed_by_operator: bool | None = None


@dataclass
class RescueCase:
    """A complete record of one rescue session."""

    profile: SystemProfile | None = None
    profile_name: str | None = None
    entries: list[CaseEntry] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    notes: list[str] = field(default_factory=list)

    def add(
        self,
        module: ModuleBase,
        check: CheckResult,
        fix: FixResult | None = None,
        confirmed_by_operator: bool | None = None,
    ) -> None:
        self.entries.append(CaseEntry(module, check, fix, confirmed_by_operator))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def case_to_dict(case: RescueCase) -> dict[str, Any]:
    """Build the redacted, JSON-serializable form of a case."""
    extra = _home_patterns()

    system: dict[str, Any] = {}
    if case.profile is not None:
        system = {
            "platform": case.profile.platform.value,
            "os_name": redact(case.profile.os_name, extra),
            "os_version": case.profile.os_version,
            "architecture": case.profile.architecture,
            "cpu_model": case.profile.cpu_model,
            "cpu_cores": case.profile.cpu_cores,
            "ram_bytes": case.profile.ram_bytes,
            # Hostnames are frequently "jane-smiths-macbook-pro"; the diagnostic
            # value is nil and the identifying value is high.
            "hostname": _REDACTED,
        }
    else:
        system = {"platform": platform.system().lower()}

    modules: list[dict[str, Any]] = []
    for entry in case.entries:
        modules.append(_entry_to_dict(entry, extra))

    system_changes = sum(
        len(e.fix.executed_mutations) for e in case.entries if e.fix is not None
    )
    manual_actions = sum(
        len(e.fix.guidance_actions) for e in case.entries if e.fix is not None
    )

    return {
        "schema_version": CASE_SCHEMA_VERSION,
        "generated_at": _now(),
        "started_at": case.started_at,
        "finished_at": case.finished_at or _now(),
        "rescue_profile": case.profile_name,
        "system": system,
        "summary": {
            "modules_run": len(case.entries),
            "modules_with_findings": sum(1 for e in case.entries if e.check.has_issues),
            "modules_failed": sum(1 for e in case.entries if e.check.status is CheckStatus.FAILED),
            "modules_unsupported": sum(
                1 for e in case.entries if e.check.status is CheckStatus.UNSUPPORTED
            ),
            "findings": sum(len(e.check.findings) for e in case.entries),
            "system_changes": system_changes,
            "manual_actions_required": manual_actions,
        },
        "modules": modules,
        "notes": [redact(note, extra) for note in case.notes],
        "redaction": {
            "applied": True,
            "note": (
                "Credential-shaped strings, email addresses, the account name, "
                "and the home-directory path are removed before writing. Review "
                "before sharing anyway: module output is free text."
            ),
        },
    }


def _entry_to_dict(entry: CaseEntry, extra: list[tuple[re.Pattern[str], str]]) -> dict[str, Any]:
    check = entry.check
    record: dict[str, Any] = {
        "module": entry.module.name,
        "category": entry.module.category,
        "risk_level": entry.module.risk_level.value,
        "status": check.status.value,
        "error": redact(check.error, extra) if check.error else None,
        "unsupported_reason": redact(check.unsupported_reason or "", extra) or None,
        "findings": [
            {
                "title": redact(f.title, extra),
                "description": redact(f.description, extra),
                "severity": f.severity.value,
                "category": f.category,
                "code": f.code,
                "confidence": f.confidence,
                "collected_at": f.collected_at,
                "data": _redact_any(f.data, extra),
            }
            for f in check.findings
        ],
        "operator_confirmed": entry.confirmed_by_operator,
    }

    if entry.fix is None:
        record["actions"] = []
        return record

    record["actions"] = [
        {
            "title": redact(action.title, extra),
            "description": redact(action.description, extra),
            "kind": action.kind.value,
            "risk_level": action.risk_level.value,
            # Guidance is never a system change, whatever flags a module set on
            # it. This mirrors FixResult.executed_mutations so the export cannot
            # claim a change the summary does not count.
            "changed_the_system": (
                action.kind is ActionKind.MUTATION and action.executed and action.success
            ),
            "succeeded": action.success if action.kind is ActionKind.MUTATION else None,
            "error": redact(action.error, extra) if action.error else None,
            "rollback": _redact_any(action.data.get("rollback"), extra),
            "verification": _redact_any(action.data.get("verification"), extra),
        }
        for action in entry.fix.actions
    ]
    return record


def case_to_json(case: RescueCase, indent: int = 2) -> str:
    return json.dumps(case_to_dict(case), indent=indent, sort_keys=False)


def case_to_markdown(case: RescueCase) -> str:
    """Human-readable summary of the same redacted data.

    A JSON file is for tooling; this is what a person actually reads, and what
    they can paste into a message asking for help.
    """
    data = case_to_dict(case)
    summary = data["summary"]
    lines = [
        "# Rescue case report",
        "",
        f"- Generated: {data['generated_at']}",
        f"- Profile: {data['rescue_profile'] or 'none (full scan)'}",
        f"- System: {data['system'].get('os_name', '?')} "
        f"{data['system'].get('os_version', '')} ({data['system'].get('architecture', '?')})",
        "",
        "## Summary",
        "",
        f"- Modules run: {summary['modules_run']}",
        f"- Modules reporting findings: {summary['modules_with_findings']}",
        f"- Checks that failed to run: {summary['modules_failed']}",
        f"- Checks not supported here: {summary['modules_unsupported']}",
        f"- Total findings: {summary['findings']}",
        f"- System changes made: {summary['system_changes']}",
        f"- Manual actions still required: {summary['manual_actions_required']}",
        "",
    ]

    with_findings = [m for m in data["modules"] if m["findings"]]
    if with_findings:
        lines += ["## Findings", ""]
        for module in with_findings:
            lines.append(f"### {module['module']} ({module['category']})")
            lines.append("")
            for finding in module["findings"]:
                code = f" `{finding['code']}`" if finding["code"] else ""
                lines.append(f"- **[{finding['severity']}]** {finding['title']}{code}")
                if finding["description"]:
                    lines.append(f"  - {finding['description']}")
            lines.append("")

    failed = [m for m in data["modules"] if m["status"] in ("failed", "unsupported")]
    if failed:
        # Surfaced deliberately: a check that could not run is not a clean bill
        # of health, and a report that hides it is misleading.
        lines += ["## Checks that did not produce a result", ""]
        for module in failed:
            reason = module["error"] or module["unsupported_reason"] or "no reason given"
            lines.append(f"- {module['module']}: {module['status']} — {reason}")
        lines.append("")

    actions = [
        (m["module"], a) for m in data["modules"] for a in m["actions"]
    ]
    if actions:
        lines += ["## Actions", ""]
        for module_name, action in actions:
            if action["changed_the_system"]:
                label = "CHANGED THE SYSTEM"
            elif action["kind"] == "mutation":
                label = "attempted, no change" if not action["succeeded"] else "change reported"
            else:
                label = "manual action required"
            lines.append(f"- [{label}] {module_name}: {action['title']}")
            if action["rollback"]:
                lines.append(f"  - Rollback: {action['rollback']}")
            if action["error"]:
                lines.append(f"  - Error: {action['error']}")
        lines.append("")

    lines += [
        "## Redaction",
        "",
        data["redaction"]["note"],
        "",
    ]
    return "\n".join(lines)


def write_case(case: RescueCase, directory: Path, stem: str | None = None) -> tuple[Path, Path]:
    """Write ``<stem>.json`` and ``<stem>.md`` into ``directory``.

    Files are written with owner-only permissions: even redacted, a case
    describes a machine's security posture, and it lands in a home directory
    that other local accounts may be able to read.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    if stem is None:
        stem = "case-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    json_path = directory / f"{stem}.json"
    md_path = directory / f"{stem}.md"
    json_path.write_text(case_to_json(case), encoding="utf-8")
    md_path.write_text(case_to_markdown(case), encoding="utf-8")
    for path in (json_path, md_path):
        try:
            path.chmod(0o600)
        except OSError:
            # Windows and some network filesystems do not honour this; the
            # export is still worth producing.
            pass
    return json_path, md_path
