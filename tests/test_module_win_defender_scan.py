"""win_defender_scan: Defender's records, who is in charge, and the opt-in quick scan.

PowerShell and MpCmdRun are answered by a fake runner; nothing is run.
"""

import json
from pathlib import Path

import pytest

from rescue.command import CommandResult
from rescue.models import Platform, Severity, SystemProfile
from rescue.registry import discover_modules


def _profile():
    return SystemProfile(platform=Platform.WIN32, os_name="Windows", os_version="11", architecture="x64",
                         cpu_model="x", cpu_cores=8, ram_bytes=16 * 1024**3)


def _res(code=0, out="", timed_out=False):
    return CommandResult(args=[], returncode=None if timed_out else code, stdout=out, stderr="",
                         timed_out=timed_out, error="timed out" if timed_out else None, duration_s=3.0, truncated=False)


ON = {"AMServiceEnabled": True, "AntivirusEnabled": True, "RealTimeProtectionEnabled": True,
      "AMRunningMode": "Normal", "QuickScanEndTime": "/Date(1793000000000)/"}


class FakeWindows:
    def __init__(self, status=ON, detections=(), threats=(), products=(), scan=None, unreadable=()):
        self.answers = {"Get-MpComputerStatus": status, "Get-MpThreatDetection": list(detections),
                        "Get-MpThreat ": list(threats), "SecurityCenter2": list(products)}
        self.scan = scan or _res(0)
        self.unreadable = set(unreadable)
        self.calls = []

    def __call__(self, args, timeout=None):
        self.calls.append(list(args))
        if args[0].endswith("MpCmdRun.exe"):
            return self.scan
        command = args[-1]
        for key, value in self.answers.items():
            if command.startswith(key) or key in command:
                if key in self.unreadable:
                    return _res(1)
                return _res(0, json.dumps(value) if value is not None else "")
        raise AssertionError(command)


def _module(runner, **attrs):
    mod = next(m for m in discover_modules(Path(__file__).parent.parent / "modules") if m.name == "win_defender_scan")
    mod.runner = runner
    mod.program_files = "C:\\Program Files"
    for k, v in attrs.items():
        setattr(mod, k, v)
    return mod


def _codes(result):
    return [f.code.rsplit(".", 1)[1] for f in result.findings]


def test_clean_records():
    res = _module(FakeWindows()).check(_profile())
    assert _codes(res) == ["no_threats"]
    assert res.findings[0].data["last_quick_scan"].startswith("2026-")


def test_a_threat_defender_could_not_remove_is_critical_with_its_file():
    fake = FakeWindows(
        detections=[{"ThreatID": 7, "ThreatStatusID": 103, "ActionSuccess": False,
                     "Resources": ["file:_C:\\Users\\sam\\Downloads\\crack.exe"],
                     "InitialDetectionTime": "2026-10-27T10:00:00Z"}],
        threats=[{"ThreatID": 7, "ThreatName": "Trojan:Win32/Wacatac.B!ml", "SeverityID": 5, "IsActive": True}],
    )
    f = _module(fake).check(_profile()).findings[0]
    assert f.code == "security.win_defender_scan.threat_still_there" and f.severity == Severity.CRITICAL
    assert f.data["path"] == "C:\\Users\\sam\\Downloads\\crack.exe"
    assert f.data["status"] == "removal failed" and f.data["severity_word"] == "severe"
    assert "crack.exe" in f.description and "Protection history" in f.description


def test_an_allowed_threat_says_someone_allowed_it():
    fake = FakeWindows(detections=[{"ThreatID": 2, "ThreatStatusID": 5, "Resources": "file:_C:\\x.exe"}],
                       threats=[{"ThreatID": 2, "ThreatName": "PUA:Win32/Presenoker"}])
    f = _module(fake).check(_profile()).findings[0]
    assert f.code.endswith("threat_still_there") and "Someone chose to allow it" in f.description


def test_a_handled_threat_is_information():
    fake = FakeWindows(detections=[{"ThreatID": 3, "ThreatStatusID": 3, "ActionSuccess": True}],
                       threats=[{"ThreatID": 3, "ThreatName": "Trojan:Script/Wacatac", "IsActive": False}])
    f = _module(fake).check(_profile()).findings[0]
    assert f.code.endswith("threat_handled") and f.severity == Severity.INFO and "quarantined" in f.description


def test_monitoring_software_carries_the_warning():
    fake = FakeWindows(detections=[{"ThreatID": 9, "ThreatStatusID": 1, "Resources": ["file:_C:\\ProgramData\\rf\\rf.exe"]}],
                       threats=[{"ThreatID": 9, "ThreatName": "MonitoringTool:Win32/Refog"}])
    f = _module(fake).check(_profile()).findings[0]
    assert f.code.endswith("monitoring_threat") and "removing it can alert them" in f.description


def test_another_antivirus_in_charge_is_named():
    fake = FakeWindows(status={**ON, "AMRunningMode": "Passive Mode"},
                       products=[{"displayName": "Windows Defender", "productState": 393472},
                                 {"displayName": "Norton 360", "productState": 266240}])
    res = _module(fake).check(_profile())
    assert _codes(res) == ["other_antivirus_in_charge"]
    assert "Norton 360" in res.findings[0].title


def test_defender_off_with_nothing_else_is_a_warning():
    fake = FakeWindows(status={**ON, "AntivirusEnabled": False})
    res = _module(fake).check(_profile())
    assert _codes(res) == ["defender_off"] and res.findings[0].severity == Severity.WARNING


def test_unreadable_status_or_records_is_not_clean():
    res = _module(FakeWindows(unreadable={"Get-MpComputerStatus"})).check(_profile())
    assert _codes(res) == ["could_not_read"]
    res = _module(FakeWindows(unreadable={"Get-MpThreatDetection"})).check(_profile())
    assert _codes(res) == ["could_not_read"]


def test_quick_scan_only_when_asked():
    fake = FakeWindows()
    _module(fake).check(_profile())
    assert not any(c[0].endswith("MpCmdRun.exe") for c in fake.calls)
    mod = _module(fake)
    mod.configure({"quick_scan": True})
    assert mod.check_timeout and mod.check_timeout > 1800
    res = mod.check(_profile())
    scan = next(c for c in fake.calls if c[0].endswith("MpCmdRun.exe"))
    assert scan[1:] == ["-Scan", "-ScanType", "1"]
    assert _codes(res) == ["quick_scan_done", "no_threats"]


@pytest.mark.parametrize("answer", [_res(timed_out=True), _res(code=5)])
def test_a_quick_scan_that_did_not_finish_says_so(answer):
    mod = _module(FakeWindows(scan=answer))
    mod.configure({"quick_scan": True})
    f = mod.check(_profile()).findings[0]
    assert f.code.endswith("quick_scan_failed") and "isn't a clean result" in f.description
