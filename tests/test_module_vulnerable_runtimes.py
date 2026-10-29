"""vulnerable_runtimes: every Node.js and PHP copy, compared with the KEV advisories.

The copies are fake folder trees under tmp_path; a fake runner stands in for
rescue.command.run, so no program is really run.
"""

import os
import sys
from pathlib import Path

import pytest

from rescue.command import CommandResult
from rescue.models import Platform, Severity, SystemProfile
from rescue.registry import discover_modules

ROOT = Path(__file__).parent.parent
CODE = "security.vulnerable_runtimes."


def _profile(platform=Platform.DARWIN):
    return SystemProfile(platform=platform, os_name="macOS", os_version="15.2", architecture="arm64",
                         cpu_model="Apple M2", cpu_cores=8, ram_bytes=16 * 1024**3)


def _module(tmp_path, monkeypatch, outputs=None, elevated=False):
    mod = next(m for m in discover_modules(ROOT / "modules") if m.name == "vulnerable_runtimes")
    mod.home = tmp_path / "home"
    mod.path_env = ""
    mod.fixed_dirs = []
    mod.system_roots = []
    mod.elevated = elevated
    pkg = sys.modules[type(mod).__module__]
    calls = []

    def fake_run(args, **kw):
        calls.append(list(args))
        out = (outputs or {}).get(args[0])
        return CommandResult(args=list(args), returncode=0 if out else 1, stdout=out or "", stderr="",
                             timed_out=False, error=None, duration_s=0.01, truncated=False)

    monkeypatch.setattr(pkg, "run", fake_run)
    return mod, pkg, calls


def _program(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n")
    path.chmod(0o755)
    return path


def _node_header(prefix: Path, version: str):
    major, minor, patch = version.split(".")
    h = prefix / "include" / "node" / "node_version.h"
    h.parent.mkdir(parents=True, exist_ok=True)
    h.write_text(f"#define NODE_MAJOR_VERSION {major}\n#define NODE_MINOR_VERSION {minor}\n"
                 f"#define NODE_PATCH_VERSION {patch}\n")


def _php_header(prefix: Path, version: str):
    h = prefix / "include" / "php" / "main" / "php_version.h"
    h.parent.mkdir(parents=True, exist_ok=True)
    h.write_text(f'#define PHP_MAJOR_VERSION 8\n#define PHP_VERSION "{version}"\n')


def _by_code(result, code):
    return [f for f in result.findings if f.code == CODE + code]


# --- the advisory table -------------------------------------------------------------


@pytest.mark.parametrize("version,affected,fix", [
    ((22, 23, 3), True, "22.23.4"),
    ((22, 23, 4), False, None),
    ((24, 22, 0), True, "24.22.1"),
    ((24, 22, 1), False, None),
    ((26, 3, 1), True, "26.12.1"),
    ((26, 12, 1), False, None),
    ((25, 8, 1), True, None),   # end of life: affected, no fix on its line
    ((20, 20, 2), True, None),
    ((23, 11, 1), True, None),
])
def test_node_ranges(tmp_path, monkeypatch, version, affected, fix):
    _, pkg, _ = _module(tmp_path, monkeypatch)
    hits = pkg.matching_advisories("node", version)
    assert bool(hits) is affected
    if affected:
        assert hits[0]["cves"] == ["CVE-2026-111497"]
        assert pkg.fixed_version("node", version, hits) == fix


@pytest.mark.parametrize("version,cves,fix", [
    ((8, 4, 26), ["CVE-2026-109618", "CVE-2026-109619"], "8.4.27"),
    ((8, 4, 27), [], None),
    ((8, 5, 11), ["CVE-2026-109618", "CVE-2026-109619"], "8.5.12"),
    ((8, 2, 34), ["CVE-2026-109618", "CVE-2026-109619"], "8.2.35"),
    ((8, 1, 34), ["CVE-2026-109618", "CVE-2026-109619"], None),
    ((7, 2, 0), ["CVE-2026-109619"], None),  # NVD: 109618 starts at 7.3.0
    ((5, 3, 0), [], None),
])
def test_php_ranges(tmp_path, monkeypatch, version, cves, fix):
    _, pkg, _ = _module(tmp_path, monkeypatch)
    hits = pkg.matching_advisories("php", version)
    assert sorted(c for a in hits for c in a["cves"]) == cves
    if hits:
        assert pkg.fixed_version("php", version, hits) == fix


def test_every_advisory_is_well_formed(tmp_path, monkeypatch):
    _, pkg, _ = _module(tmp_path, monkeypatch)
    for adv in pkg.ADVISORIES:
        assert adv["runtime"] in pkg.RUNTIMES
        assert adv["cves"] and adv["advisory"].startswith("https://")
        for lo, hi in adv["affected"]:
            assert pkg._vtuple(lo) < pkg._vtuple(hi)
        for line, fixed in adv["fixed"].items():
            assert fixed.startswith(line + ".")
        assert pkg.RUNTIMES[adv["runtime"]]["upgrade_line"] in adv["fixed"]


# --- finding the copies -----------------------------------------------------------------


def test_nvm_versions_are_read_from_their_headers_without_running_them(tmp_path, monkeypatch):
    mod, _, calls = _module(tmp_path, monkeypatch)
    for v in ("22.23.3", "22.23.4"):
        prefix = mod.home / ".nvm" / "versions" / "node" / f"v{v}"
        _program(prefix / "bin" / "node")
        _node_header(prefix, v)
    result = mod.check(_profile())
    assert calls == []
    (hit,) = _by_code(result, "exploited_rce")
    assert hit.severity == Severity.CRITICAL
    assert hit.data["version"] == "22.23.3" and hit.data["installed_with"] == "nvm"
    assert hit.data["cves"] == ["CVE-2026-111497"] and hit.data["version_source"] == "version header"
    assert "`nvm install 22.23.4`" in hit.description and "What to do:" in hit.description
    assert "CVE-2026-111497" in hit.description
    (inv,) = _by_code(result, "runtime_inventory")
    assert [c["version"] for c in inv.data["copies"]] == ["22.23.3", "22.23.4"]
    assert inv.data["not_covered"] == ["Node.js inside Electron apps"]


def test_homebrew_current_keg_is_critical_and_an_old_keg_is_a_warning(tmp_path, monkeypatch):
    mod, pkg, _ = _module(tmp_path, monkeypatch)
    brew = tmp_path / "brew"
    for v in ("22.23.2", "22.23.3"):
        _program(brew / "Cellar" / "node@22" / v / "bin" / "node")
        _node_header(brew / "Cellar" / "node@22" / v, v)
    (brew / "opt").mkdir(parents=True)
    (brew / "opt" / "node@22").symlink_to(brew / "Cellar" / "node@22" / "22.23.3")
    mod.system_roots = mod._cellar_roots(brew / "Cellar")
    result = mod.check(_profile())
    (current,) = _by_code(result, "exploited_rce")
    assert current.data["version"] == "22.23.3"
    assert "`brew update && brew upgrade node@22`" in current.description
    (old,) = _by_code(result, "old_copy_affected")
    assert old.severity == Severity.WARNING and old.data["version"] == "22.23.2"
    assert "`brew cleanup node@22`" in old.description


def test_end_of_life_line_says_there_is_no_fix_and_moves_to_a_supported_line(tmp_path, monkeypatch):
    mod, _, _ = _module(tmp_path, monkeypatch)
    prefix = mod.home / ".nvm" / "versions" / "node" / "v20.20.2"
    _program(prefix / "bin" / "node")
    _node_header(prefix, "20.20.2")
    (hit,) = _by_code(mod.check(_profile()), "exploited_rce")
    assert hit.data["fixed_version"] is None and hit.data["upgrade_to"] == "24.22.1"
    assert "no longer gets fixes" in hit.description
    assert "`nvm install 24.22.1`" in hit.description


def test_mamp_php_from_its_header(tmp_path, monkeypatch):
    mod, _, _ = _module(tmp_path, monkeypatch)
    mamp = tmp_path / "Applications" / "MAMP" / "bin" / "php"
    prefix = mamp / "php8.3.30"
    _program(prefix / "bin" / "php")
    _php_header(prefix, "8.3.30")
    mod.system_roots = [(mamp, "php")]
    (hit,) = _by_code(mod.check(_profile()), "exploited_rce")
    assert hit.data["runtime"] == "php" and hit.data["installed_with"] == "mamp"
    assert hit.data["cves"] == ["CVE-2026-109618", "CVE-2026-109619"]
    assert hit.data["fixed_version"] == "8.3.36" and "PHP 8.3.36" in hit.description


def test_a_copy_without_a_header_is_asked_its_version_php_without_settings(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    php = _program(bindir / "php")
    node = _program(bindir / "node")
    mod, _, calls = _module(tmp_path, monkeypatch, outputs={
        str(php.resolve()): "PHP 8.4.27 (cli) (built: Oct 22 2026)\n",
        str(node.resolve()): "v24.22.1\n"})
    mod.path_env = str(bindir)
    result = mod.check(_profile())
    assert sorted(calls) == sorted([[str(node.resolve()), "--version"], [str(php.resolve()), "-n", "-v"]])
    assert not _by_code(result, "exploited_rce")
    (inv,) = _by_code(result, "runtime_inventory")
    assert {c["version"] for c in inv.data["copies"]} == {"8.4.27", "24.22.1"}


def test_nothing_is_run_with_administrator_rights(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    _program(bindir / "node")
    mod, _, calls = _module(tmp_path, monkeypatch, outputs={}, elevated=True)
    mod.path_env = str(bindir)
    result = mod.check(_profile())
    assert calls == []
    (unknown,) = _by_code(result, "version_unknown")
    assert unknown.severity == Severity.INFO and "doesn't mean it's fine" in unknown.description


def test_php_tools_that_are_not_php_are_skipped_and_links_are_counted_once(tmp_path, monkeypatch):
    prefix = tmp_path / "home" / ".asdf" / "installs" / "php" / "8.4.20"
    _program(prefix / "bin" / "php")
    _program(prefix / "bin" / "php-config")
    _program(prefix / "bin" / "phpize")
    _php_header(prefix, "8.4.20")
    bindir = tmp_path / "shims"
    bindir.mkdir()
    (bindir / "php").symlink_to(prefix / "bin" / "php")
    mod, _, _ = _module(tmp_path, monkeypatch)
    mod.path_env = str(bindir)
    result = mod.check(_profile())
    (hit,) = _by_code(result, "exploited_rce")
    assert hit.data["path"] == str(bindir / "php")
    assert "`asdf install php 8.4.27`" in hit.description


def test_linux_distro_php_is_a_warning_that_mentions_backports(tmp_path, monkeypatch):
    mod, _, _ = _module(tmp_path, monkeypatch, outputs={"/usr/bin/php8.2": "PHP 8.2.29 (cli)"})
    copy = {"runtime": "php", "path": "/usr/bin/php8.2", "real_path": "/usr/bin/php8.2",
            "version": None, "version_source": None}
    monkeypatch.setattr(mod, "_find_copies", lambda platform: [copy])
    (hit,) = _by_code(mod.check(_profile(Platform.LINUX)), "exploited_rce")
    assert hit.severity == Severity.WARNING and hit.data["distro_may_backport"] is True
    assert "sudo apt update && sudo apt upgrade" in hit.description


def test_no_copies_no_findings(tmp_path, monkeypatch):
    mod, _, _ = _module(tmp_path, monkeypatch)
    assert mod.check(_profile()).findings == []


def test_finding_names_the_program_for_made_by(tmp_path, monkeypatch):
    from rescue.attribution import subjects_for_finding

    mod, _, _ = _module(tmp_path, monkeypatch)
    prefix = mod.home / ".nvm" / "versions" / "node" / "v22.1.0"
    _program(prefix / "bin" / "node")
    _node_header(prefix, "22.1.0")
    (hit,) = _by_code(mod.check(_profile()), "exploited_rce")
    assert str(prefix / "bin" / "node") in subjects_for_finding(hit)


@pytest.mark.skipif(os.environ.get("RESCUE_LIVE_RUNTIMES") != "1", reason="set RESCUE_LIVE_RUNTIMES=1")
def test_live_on_this_machine():
    mod = next(m for m in discover_modules(ROOT / "modules") if m.name == "vulnerable_runtimes")
    platform = Platform(sys.platform if sys.platform in ("darwin", "win32") else "linux")
    for f in mod.check(_profile(platform)).findings:
        print(f.severity.value, f.title)
