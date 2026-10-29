"""endor_dependency_scan: opt-in Endor Labs scan of the person's code projects.

endorctl is never really run: a fake runner stands in for rescue.command.run.
The projects are fake folders under tmp_path.
"""

import json
import sys
from pathlib import Path

from rescue.command import CommandResult
from rescue.models import Platform, Severity, SystemProfile
from rescue.profiles import load_profile
from rescue.registry import discover_modules

ROOT = Path(__file__).parent.parent
CODE = "security.endor_dependency_scan."


def _profile():
    return SystemProfile(platform=Platform.DARWIN, os_name="macOS", os_version="15.2", architecture="arm64",
                         cpu_model="Apple M2", cpu_cores=8, ram_bytes=16 * 1024**3)


def _module(tmp_path, monkeypatch, scans=None, auth_ok=True, endorctl="/fake/endorctl", signed_in=True):
    mod = next(m for m in discover_modules(ROOT / "modules") if m.name == "endor_dependency_scan")
    mod.home = tmp_path / "home"
    mod.home.mkdir(exist_ok=True)
    mod.endorctl = endorctl
    mod.elevated = False
    monkeypatch.delenv("ENDOR_TOKEN", raising=False)
    monkeypatch.delenv("ENDOR_API_CREDENTIALS_KEY", raising=False)
    monkeypatch.delenv("ENDOR_CONFIG_PATH", raising=False)
    if signed_in:
        (mod.home / ".endorctl").mkdir(exist_ok=True)
        (mod.home / ".endorctl" / "config.yaml").write_text("ENDOR_TOKEN: secret\n")
    pkg = sys.modules[type(mod).__module__]
    calls = []

    def fake_run(args, **kw):
        calls.append((list(args), kw))
        if args[1] == "api":
            return CommandResult(list(args), 0 if auth_ok else 1, "{}" if auth_ok else "", "", False,
                                 None, 0.1, False)
        out = (scans or {}).get(args[3], json.dumps({"all_findings": []}))
        if out == "TIMEOUT":
            return CommandResult(list(args), None, "", "", True, "timed out", 300, False)
        return CommandResult(list(args), 0, out, "", False, None, 0.1, False)

    monkeypatch.setattr(pkg, "run", fake_run)
    return mod, calls


def _project(home: Path, rel: str, files: dict) -> Path:
    folder = home / rel
    folder.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (folder / name).write_text(text)
    return folder


def _endor(*findings):
    return json.dumps({"all_findings": list(findings), "blocking_findings": [], "warning_findings": []})


def _f(name, version, level, cats, aliases=()):
    kind = "malware" if "FINDING_CATEGORY_MALWARE" in cats else "vulnerability"
    return {"uuid": "u", "meta": {"name": "x"}, "spec": {
        "level": level, "finding_categories": cats, "target_dependency_name": name,
        "target_dependency_version": version, "ecosystem": "ECOSYSTEM_NPM",
        "finding_metadata": {kind: {"spec": {"aliases": list(aliases)}}}}}


def _by(result, code):
    return [f for f in result.findings if f.code == CODE + code]


def test_off_by_default_nothing_runs_and_it_says_what_would_be_sent(tmp_path, monkeypatch):
    mod, calls = _module(tmp_path, monkeypatch)
    _project(mod.home, "src/app", {"package.json": "{}", "package-lock.json": "{}"})
    result = mod.check(_profile())
    assert calls == []
    (f,) = result.findings
    assert f.code == CODE + "scan_available" and f.severity == Severity.INFO
    assert "email addresses" in f.description and "stay here" in f.description
    assert "Endor Labs is one of Reclaim City's sponsors" in f.description


def test_no_projects_no_findings(tmp_path, monkeypatch):
    mod, _ = _module(tmp_path, monkeypatch)
    mod.scan_projects = True
    assert mod.check(_profile()).findings == []


def test_project_search_is_depth_limited_and_skips_package_folders(tmp_path, monkeypatch):
    mod, _ = _module(tmp_path, monkeypatch)
    _project(mod.home, "code/a", {"package.json": "{}"})
    _project(mod.home, "code/a/sub", {"package.json": "{}"})           # inside a project
    _project(mod.home, "code/b/node_modules/x", {"package.json": "{}"})  # a package cache
    _project(mod.home, "code/.hidden/y", {"go.mod": ""})
    _project(mod.home, "code/1/2/3/deep", {"Cargo.toml": ""})          # depth 4
    _project(mod.home, "Projects/py", {"pyproject.toml": ""})
    found = {Path(p["path"]).relative_to(mod.home).as_posix() for p in mod._find_projects()}
    assert found == {"code/a", "Projects/py"}


def test_profile_turns_it_on_and_sets_limits(tmp_path, monkeypatch):
    mod, _ = _module(tmp_path, monkeypatch)
    profile = load_profile(ROOT / "profiles" / "dependency_scan.yaml")
    mod.configure(profile.module_config["endor_dependency_scan"])
    assert mod.scan_projects is True and mod.check_timeout > 1800
    worm = load_profile(ROOT / "profiles" / "ai_worm_response.yaml")
    assert worm.module_config["endor_dependency_scan"]["scan_projects"] is False
    assert {"vulnerable_runtimes", "endor_dependency_scan"} <= set(worm.include_modules)


def test_not_installed_and_not_signed_in_are_could_not_check(tmp_path, monkeypatch):
    mod, calls = _module(tmp_path, monkeypatch, endorctl="")
    mod.scan_projects = True
    _project(mod.home, "src/app", {"package.json": "{}", "yarn.lock": ""})
    (f,) = mod.check(_profile()).findings
    assert f.code == CODE + "could_not_check" and f.data["reason"] == "not_installed"
    assert "doesn't mean they're fine" in f.description and "docs.endorlabs.com" in f.description

    mod, calls = _module(tmp_path, monkeypatch, signed_in=False)
    mod.scan_projects = True
    (mod.home / ".endorctl" / "config.yaml").unlink(missing_ok=True)
    (f,) = mod.check(_profile()).findings
    assert f.data["reason"] == "not_signed_in" and calls == []
    assert "`endorctl init`" in f.description

    mod, calls = _module(tmp_path, monkeypatch, auth_ok=False)
    mod.scan_projects = True
    (f,) = mod.check(_profile()).findings
    assert f.data["reason"] == "not_signed_in"
    assert [c[0][1:] for c in calls] == [["api", "list", "-r", "Project", "--page-size=1"]]


def test_never_reads_the_credentials_file_or_passes_credentials(tmp_path, monkeypatch):
    mod, calls = _module(tmp_path, monkeypatch)
    mod.scan_projects = True
    _project(mod.home, "src/app", {"package.json": "{}", "package-lock.json": "{}"})
    opened = []
    real_open = open

    def watch(path, *a, **kw):
        opened.append(str(path))
        return real_open(path, *a, **kw)

    monkeypatch.setattr("builtins.open", watch)
    mod.check(_profile())
    assert not any("config.yaml" in p for p in opened)
    for args, kw in calls:
        assert not any("secret" in a or "token" in a.lower() for a in args)
        assert "env" not in kw


def test_malicious_package_is_critical_and_vulnerabilities_are_grouped(tmp_path, monkeypatch):
    home = tmp_path / "home"
    app = _project(home, "src/app", {"package.json": "{}", "package-lock.json": "{}"})
    out = _endor(
        _f("evil-pkg", "1.0.1", "FINDING_LEVEL_CRITICAL", ["FINDING_CATEGORY_MALWARE"], ["MAL-2026-1"]),
        _f("lodash", "4.17.0", "FINDING_LEVEL_HIGH", ["FINDING_CATEGORY_VULNERABILITY"], ["CVE-2021-23337"]),
        _f("tiny", "1.0.0", "FINDING_LEVEL_LOW", ["FINDING_CATEGORY_VULNERABILITY"]),
    )
    mod, calls = _module(tmp_path, monkeypatch, scans={str(app): out})
    mod.scan_projects = True
    result = mod.check(_profile())
    (bad,) = _by(result, "malicious_dependency")
    assert bad.severity == Severity.CRITICAL and bad.data["package"] == "evil-pkg"
    assert bad.data["ids"] == ["MAL-2026-1"] and "What to do:" in bad.description
    (vul,) = _by(result, "vulnerable_dependencies")
    assert vul.severity == Severity.WARNING and vul.data["count"] == 1
    assert vul.data["packages"][0]["ids"] == ["CVE-2021-23337"]
    (summary,) = _by(result, "scan_summary")
    assert summary.data["projects"][0]["other"] == 1
    scan = [c for c in calls if c[0][1] == "scan"][0]
    assert scan[0][1:] == ["scan", "--path", str(app), "--dependencies", "--quick-scan", "--output-type", "json"]
    assert scan[1]["timeout"] <= 300


def test_projects_that_would_be_built_are_not_scanned(tmp_path, monkeypatch):
    mod, calls = _module(tmp_path, monkeypatch)
    mod.scan_projects = True
    _project(mod.home, "src/nolock", {"package.json": "{}"})
    _project(mod.home, "src/py", {"requirements.txt": "requests\n"})
    _project(mod.home, "src/java", {"pom.xml": "<project/>"})
    result = mod.check(_profile())
    assert not [c for c in calls if c[0][1] == "scan"]
    (skipped,) = _by(result, "not_scanned")
    assert {p["reason"] for p in skipped.data["projects"]} == {"would_build"}
    assert len(skipped.data["projects"]) == 3
    assert "doesn't" not in skipped.title and "we don't know" in skipped.description


def test_timeouts_limits_and_bad_output_are_reported_not_clean(tmp_path, monkeypatch):
    home = tmp_path / "home"
    a = _project(home, "src/a", {"package.json": "{}", "package-lock.json": "{}"})
    b = _project(home, "src/b", {"package.json": "{}", "package-lock.json": "{}"})
    _project(home, "src/c", {"package.json": "{}", "package-lock.json": "{}"})
    mod, _ = _module(tmp_path, monkeypatch, scans={str(a): "TIMEOUT", str(b): "not json"})
    mod.scan_projects = True
    mod.max_scans = 0
    result = mod.check(_profile())
    assert {p["reason"] for p in _by(result, "not_scanned")[0].data["projects"]} == {"limit"}
    mod.max_scans = 5
    result = mod.check(_profile())
    reasons = {Path(p["path"]).name: p["reason"] for p in _by(result, "not_scanned")[0].data["projects"]}
    assert reasons == {"a": "timed_out", "b": "tool_failed"}
    assert _by(result, "scan_summary")[0].data["projects"][0]["path"].endswith("c")


def test_elevated_never_runs_endorctl(tmp_path, monkeypatch):
    mod, calls = _module(tmp_path, monkeypatch)
    mod.scan_projects = True
    mod.elevated = True
    _project(mod.home, "src/app", {"package.json": "{}", "package-lock.json": "{}"})
    (f,) = mod.check(_profile()).findings
    assert f.data["reason"] == "elevated" and calls == []
