"""ai_agent_audit: HackMyAgent's `detect`, fetched into the user cache and run read-only.

node and npm are never really run here: a fake runner stands in for
rescue.command.run and records every call. The live test at the bottom does
the real fetch and run, and only when RESCUE_LIVE_HMA=1.
"""

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

from rescue.command import CommandResult
from rescue.models import Platform, RiskLevel, Severity, SystemProfile
from rescue.registry import discover_modules

ROOT = Path(__file__).parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "hackmyagent" / "detect-mac.json"
CODE = "security.ai_agent_audit."


def _profile(platform=Platform.DARWIN):
    return SystemProfile(
        platform=platform, os_name="macOS", os_version="15.2", architecture="arm64",
        cpu_model="Apple M2", cpu_cores=8, ram_bytes=16 * 1024**3,
    )


def _result(args, rc=0, out="", err="", timed_out=False, error=None):
    return CommandResult(
        args=list(args), returncode=None if timed_out else rc, stdout=out, stderr=err,
        timed_out=timed_out, error=error or ("timed out" if timed_out else None),
        duration_s=0.1, truncated=False,
    )


def _write_install(directory: Path, version="0.33.2"):
    pkg = directory / "node_modules" / "hackmyagent"
    (pkg / "dist").mkdir(parents=True, exist_ok=True)
    (pkg / "package.json").write_text(json.dumps({"name": "hackmyagent", "version": version}))
    (pkg / "dist" / "cli.js").write_text("// fake\n")


class FakeRunner:
    """Answers `node --version`, `npm ci` and `detect` the way the real tools do."""

    def __init__(self, node_version="v22.1.0", npm=None, detect=None):
        self.node_version = node_version
        self.npm = npm or (lambda args, cwd, env: (_write_install(Path(cwd)), _result(args))[1])
        self.detect = detect or (lambda args, cwd, env: _result(args, 1, FIXTURE.read_text()))
        self.calls = []

    def __call__(self, args, *, timeout=20.0, env=None, cwd=None, **kw):
        args = [str(a) for a in args]
        call = {"args": args, "timeout": timeout, "env": dict(env) if env else None, "cwd": cwd}
        # Snapshot what the tool would see while it runs.
        if env and env.get("OPENA2A_HOME"):
            call["opena2a_home_existed"] = Path(env["OPENA2A_HOME"]).is_dir()
        if "--cache" in args:
            call["npm_cache_existed"] = Path(args[args.index("--cache") + 1]).is_dir()
        if cwd:
            call["cwd_listing"] = sorted(p.name for p in Path(cwd).iterdir())
        self.calls.append(call)
        if args[1:] == ["--version"]:
            return _result(args, 0, self.node_version + "\n")
        if "ci" in args[1:3]:
            return self.npm(args, cwd, env)
        if "detect" in args:
            return self.detect(args, cwd, env)
        raise AssertionError(f"unexpected command {args}")

    def named(self, word):
        return [c for c in self.calls if word in c["args"]]


@pytest.fixture
def env(tmp_path, monkeypatch):
    """A fake home, a fake cache, a fake node on PATH, downloads allowed."""
    home = tmp_path / "home"
    home.mkdir()
    cache = tmp_path / "cache"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for tool in ("node", "npm"):
        exe = bindir / tool
        exe.write_text("#!/bin/sh\n")
        exe.chmod(0o755)
    monkeypatch.setenv("RESCUE_CACHE_DIR", str(cache))
    monkeypatch.delenv("RESCUE_NO_DOWNLOADS", raising=False)
    monkeypatch.setenv("PATH", str(bindir))
    return {"home": home, "cache": cache, "bin": bindir, "tmp": tmp_path}


def _module(env, runner, monkeypatch):
    mod = next(m for m in discover_modules(ROOT / "modules") if m.name == "ai_agent_audit")
    monkeypatch.setattr(sys.modules[type(mod).__module__], "run", runner)
    mod.home = env["home"]
    mod.system_node_dirs = []
    return mod


def _install_dir(env):
    return env["cache"] / "ReclaimCity" / "hackmyagent-0.33.2"


def _codes(result):
    return [f.code for f in result.findings]


def _one(result, slug):
    found = [f for f in result.findings if f.code == CODE + slug]
    assert len(found) == 1, _codes(result)
    return found[0]


# --- the module itself -------------------------------------------------------


def test_module_is_discovered_read_only_on_every_platform(env, monkeypatch):
    mod = _module(env, FakeRunner(), monkeypatch)
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert set(mod.platforms) == {Platform.DARWIN, Platform.LINUX, Platform.WIN32}
    assert set(mod.emits_codes) == {
        CODE + "credentials_in_ai_config", CODE + "risky_mcp_server",
        CODE + "ai_inventory", CODE + "could_not_check",
    }
    # Fetch (180 s) plus detect (60 s) must fit inside the orchestrator's limit.
    assert mod.check_timeout >= 180 + 60


# --- the detect command --------------------------------------------------------


def test_detect_argv_and_environment_exactly(env, monkeypatch):
    _write_install(_install_dir(env))
    runner = FakeRunner()
    mod = _module(env, runner, monkeypatch)
    mod.check(_profile())

    [call] = runner.named("detect")
    cli = _install_dir(env) / "node_modules" / "hackmyagent" / "dist" / "cli.js"
    assert call["args"] == [
        str(env["bin"] / "node"), str(cli), "detect", str(env["home"]), "--json", "--depth", "0",
    ]
    assert call["timeout"] == 60
    assert call["env"]["OPENA2A_TELEMETRY"] == "off"
    home_dir = Path(call["env"]["OPENA2A_HOME"])
    assert call["opena2a_home_existed"]
    assert env["home"] not in home_dir.parents
    assert not home_dir.exists(), "the tool's settings folder is removed afterwards"


def test_only_detect_ever_runs(env, monkeypatch):
    runner = FakeRunner()
    mod = _module(env, runner, monkeypatch)
    mod.check(_profile())
    forbidden = {"secure", "--fix", "rollback", "attack", "red-team", "--deep", "--nanomind",
                 "--contribute", "--publish", "init-mcp", "harden-soul", "install"}
    for call in runner.calls:
        assert not forbidden & set(call["args"]), call["args"]
    assert len(runner.named("detect")) == 1


def test_nothing_is_written_to_the_home_folder(env, monkeypatch):
    runner = FakeRunner()
    mod = _module(env, runner, monkeypatch)
    mod.check(_profile())
    assert list(env["home"].iterdir()) == []


# --- reading a real result ------------------------------------------------------


def test_real_mac_output_becomes_the_four_kinds_of_finding(env, monkeypatch):
    _write_install(_install_dir(env))
    mod = _module(env, FakeRunner(), monkeypatch)
    result = mod.check(_profile())

    assert result.supported and result.error is None
    assert sorted(_codes(result)) == sorted([
        CODE + "credentials_in_ai_config", CODE + "risky_mcp_server", CODE + "ai_inventory",
    ])

    cred = _one(result, "credentials_in_ai_config")
    assert cred.severity == Severity.WARNING
    assert cred.data["file"] == "~/.claude/settings.json"
    assert cred.data["line"] == 3
    assert cred.data["variable"] == "EXAMPLE_API_KEY"
    assert cred.data["tool"] == "Claude Code"
    assert "EXAMPLE_API_KEY" in cred.description
    assert "What to do:" in cred.description

    mcp = _one(result, "risky_mcp_server")
    assert mcp.severity == Severity.WARNING
    assert mcp.data["name"] == "postgres"
    assert mcp.data["tool"] == "Cursor (global)"
    assert mcp.data["capabilities"] == ["database"]
    assert mcp.data["config_file"] == "~/.cursor/mcp.json"
    assert "database" in mcp.description
    assert "What to do:" in mcp.description

    inv = _one(result, "ai_inventory")
    assert inv.severity == Severity.INFO
    assert [a["name"] for a in inv.data["tools"]] == [
        "Claude Code", "LM Studio", "Claude Desktop", "Cursor", "GitHub Copilot",
    ]
    assert inv.data["tools"][0]["state"] == "running"
    by_tool = inv.data["mcp_servers_by_tool"]
    assert by_tool["Claude Code (user)"] == ["chat-bridge"]
    assert "postgres" in by_tool["Cursor (global)"]
    assert inv.data["mcp_server_count"] == 16


def test_governance_findings_and_opena2a_advice_are_dropped(env, monkeypatch):
    _write_install(_install_dir(env))
    mod = _module(env, FakeRunner(), monkeypatch)
    result = mod.check(_profile())
    text = json.dumps([[f.title, f.description, f.data] for f in result.findings])
    text = text.replace(str(env["tmp"]), "<tmp>")  # pytest names the temp dir after the test
    for word in ("SOUL", "governance", "Governance", "opena2a", "harden-soul",
                 "hackmyagent secure", "/Users/sam", "36 chars"):
        assert word not in text, word


def test_no_ai_tools_found_means_no_findings(env, monkeypatch):
    _write_install(_install_dir(env))
    empty = {"summary": {}, "agents": [], "mcpServers": [], "aiConfigs": [], "findings": [],
             "coverage": {"measured": True}}
    runner = FakeRunner(detect=lambda a, c, e: _result(a, 0, json.dumps(empty)))
    result = _module(env, runner, monkeypatch).check(_profile())
    assert result.findings == [] and result.supported and result.error is None


def test_a_credential_reported_only_as_a_config_finding_still_counts(env, monkeypatch):
    _write_install(_install_dir(env))
    doc = json.loads(FIXTURE.read_text())
    doc["aiConfigs"] = []
    runner = FakeRunner(detect=lambda a, c, e: _result(a, 1, json.dumps(doc)))
    result = _module(env, runner, monkeypatch).check(_profile())
    cred = _one(result, "credentials_in_ai_config")
    assert cred.data["file"] == "~/.claude/settings.json"
    assert cred.data["line"] == 3
    assert cred.data["variable"] == "EXAMPLE_API_KEY"


def test_a_value_shaped_token_is_never_repeated(env, monkeypatch):
    _write_install(_install_dir(env))
    doc = json.loads(FIXTURE.read_text())
    doc["aiConfigs"][0]["evidence"]["token"] = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    doc["findings"] = []
    runner = FakeRunner(detect=lambda a, c, e: _result(a, 1, json.dumps(doc)))
    result = _module(env, runner, monkeypatch).check(_profile())
    cred = _one(result, "credentials_in_ai_config")
    assert "variable" not in cred.data
    assert "ghp_" not in json.dumps([cred.title, cred.description, cred.data])


def test_a_filesystem_server_open_at_the_root_is_risky(env, monkeypatch):
    _write_install(_install_dir(env))
    doc = {"agents": [], "aiConfigs": [], "findings": [], "mcpServers": [
        {"name": "files", "transport": "stdio", "source": "Claude Desktop", "verified": False,
         "capabilities": ["filesystem"], "risk": "critical"},
        {"name": "browser", "transport": "stdio", "source": "Claude Desktop", "verified": False,
         "capabilities": ["browser"], "risk": "medium"},
    ]}
    runner = FakeRunner(detect=lambda a, c, e: _result(a, 0, json.dumps(doc)))
    result = _module(env, runner, monkeypatch).check(_profile())
    mcp = _one(result, "risky_mcp_server")
    assert mcp.data["name"] == "files"
    assert "files" in mcp.description


# --- exit codes and bad output ---------------------------------------------------


@pytest.mark.parametrize("rc, reason", [(2, "not_measured"), (3, "integrity_failed"), (7, "tool_failed")])
def test_exit_codes_that_mean_not_measured(env, monkeypatch, rc, reason):
    _write_install(_install_dir(env))
    runner = FakeRunner(detect=lambda a, c, e: _result(a, rc, FIXTURE.read_text()))
    result = _module(env, runner, monkeypatch).check(_profile())
    f = _one(result, "could_not_check")
    assert f.severity == Severity.INFO
    assert result.supported is True
    assert f.data["reason"] == reason
    assert len(result.findings) == 1


@pytest.mark.parametrize("rc", [0, 1])
def test_exit_0_and_1_are_measured(env, monkeypatch, rc):
    _write_install(_install_dir(env))
    runner = FakeRunner(detect=lambda a, c, e: _result(a, rc, FIXTURE.read_text()))
    result = _module(env, runner, monkeypatch).check(_profile())
    assert CODE + "could_not_check" not in _codes(result)


def test_unparseable_output_is_could_not_check(env, monkeypatch):
    _write_install(_install_dir(env))
    runner = FakeRunner(detect=lambda a, c, e: _result(a, 0, "Scanning...\nnot json"))
    f = _one(_module(env, runner, monkeypatch).check(_profile()), "could_not_check")
    assert f.data["reason"] == "bad_output"


def test_detect_timeout_is_could_not_check(env, monkeypatch):
    _write_install(_install_dir(env))
    runner = FakeRunner(detect=lambda a, c, e: _result(a, timed_out=True))
    f = _one(_module(env, runner, monkeypatch).check(_profile()), "could_not_check")
    assert f.data["reason"] == "timed_out"


# --- Node.js ----------------------------------------------------------------------


def test_no_node_is_could_not_check_with_where_to_get_it(env, monkeypatch):
    for tool in ("node", "npm"):
        (env["bin"] / tool).unlink()
    runner = FakeRunner()
    f = _one(_module(env, runner, monkeypatch).check(_profile()), "could_not_check")
    assert f.data["reason"] == "node_missing"
    assert "nodejs.org" in f.description
    assert runner.calls == []


def test_old_node_is_could_not_check(env, monkeypatch):
    runner = FakeRunner(node_version="v16.20.0")
    f = _one(_module(env, runner, monkeypatch).check(_profile()), "could_not_check")
    assert f.data["reason"] == "node_too_old"
    assert runner.named("ci") == [] and runner.named("detect") == []


def test_node_found_where_a_desktop_app_path_misses_it(env, monkeypatch):
    for tool in ("node", "npm"):
        (env["bin"] / tool).unlink()
    versions = env["home"] / ".nvm" / "versions" / "node"
    for v in ("v9.0.0", "v20.11.1", "v18.19.0"):
        (versions / v / "bin").mkdir(parents=True)
        for tool in ("node", "npm"):
            exe = versions / v / "bin" / tool
            exe.write_text("#!/bin/sh\n")
            exe.chmod(0o755)
    runner = FakeRunner()
    mod = _module(env, runner, monkeypatch)
    mod.check(_profile())
    newest = versions / "v20.11.1" / "bin"
    assert runner.calls[0]["args"][0] == str(newest / "node")
    assert runner.named("ci")[0]["args"][0] == str(newest / "npm")
    # npm's own `#!/usr/bin/env node` must find that node.
    assert runner.named("ci")[0]["env"]["PATH"].split(os.pathsep)[0] == str(newest)
    # Nothing in the fake home was touched by the discovery.
    assert sorted(p.name for p in env["home"].iterdir()) == [".nvm"]


def test_usual_places_are_listed_for_each_platform(env, monkeypatch):
    mod = _module(env, FakeRunner(), monkeypatch)
    mod.system_node_dirs = None  # the real defaults
    mac = [str(p) for p in mod._node_search_dirs(Platform.DARWIN)]
    assert "/opt/homebrew/bin" in mac and "/usr/local/bin" in mac
    assert str(env["home"] / ".local" / "bin") in mac
    assert str(env["home"] / ".volta" / "bin") in mac
    monkeypatch.setenv("ProgramFiles", r"C:\Program Files")
    win = [str(p) for p in mod._node_search_dirs(Platform.WIN32)]
    assert any(p.endswith("nodejs") and "Program Files" in p for p in win)


# --- fetching -----------------------------------------------------------------------


def test_first_run_fetches_with_npm_ci_into_a_temp_dir_then_renames(env, monkeypatch):
    runner = FakeRunner()
    mod = _module(env, runner, monkeypatch)
    result = mod.check(_profile())

    [ci] = runner.named("ci")
    args = ci["args"]
    assert args[0] == str(env["bin"] / "npm")
    assert args[1:6] == ["ci", "--ignore-scripts", "--no-audit", "--no-fund",
                         "--registry=https://registry.npmjs.org/"]
    assert ci["timeout"] == 180
    # npm's own cache: a temp dir, outside home, gone afterwards.
    npm_cache = Path(args[args.index("--cache") + 1])
    assert ci["npm_cache_existed"] and not npm_cache.exists()
    assert env["home"] not in npm_cache.parents
    # Runs in a temp dir beside the install dir, holding a copy of the vendor files.
    workdir = Path(ci["cwd"])
    assert workdir.parent == _install_dir(env).parent
    assert workdir != _install_dir(env)
    assert ci["cwd_listing"] == ["package-lock.json", "package.json", "stub"]
    assert not workdir.exists()
    # The finished install, renamed into place.
    pkg = json.loads((_install_dir(env) / "node_modules" / "hackmyagent" / "package.json").read_text())
    assert pkg["version"] == "0.33.2"
    assert (_install_dir(env) / "package-lock.json").is_file()
    assert sorted(p.name for p in _install_dir(env).parent.iterdir()) == ["hackmyagent-0.33.2"]
    assert CODE + "ai_inventory" in _codes(result)


def test_installed_copy_is_reused_without_a_fetch(env, monkeypatch):
    _write_install(_install_dir(env))
    runner = FakeRunner()
    _module(env, runner, monkeypatch).check(_profile())
    assert runner.named("ci") == []


def test_wrong_version_installed_is_fetched_again(env, monkeypatch):
    _write_install(_install_dir(env), version="0.33.1")
    runner = FakeRunner()
    _module(env, runner, monkeypatch).check(_profile())
    assert len(runner.named("ci")) == 1
    pkg = json.loads((_install_dir(env) / "node_modules" / "hackmyagent" / "package.json").read_text())
    assert pkg["version"] == "0.33.2"


@pytest.mark.parametrize("npm_result, reason", [
    (lambda a, cwd, e: (_write_install(Path(cwd)), _result(a, 1, err="E404"))[1], "fetch_failed"),
    (lambda a, cwd, e: (_write_install(Path(cwd)), _result(a, timed_out=True))[1], "fetch_failed"),
    (lambda a, cwd, e: (_write_install(Path(cwd), "9.9.9"), _result(a))[1], "fetch_failed"),
])
def test_failed_fetch_leaves_nothing_behind(env, monkeypatch, npm_result, reason):
    runner = FakeRunner(npm=npm_result)
    result = _module(env, runner, monkeypatch).check(_profile())
    f = _one(result, "could_not_check")
    assert f.data["reason"] == reason
    assert result.error is None and result.supported is True
    assert not _install_dir(env).exists()
    assert list(_install_dir(env).parent.iterdir()) == []
    assert runner.named("detect") == []


def test_no_npm_is_could_not_check(env, monkeypatch):
    (env["bin"] / "npm").unlink()
    runner = FakeRunner()
    f = _one(_module(env, runner, monkeypatch).check(_profile()), "could_not_check")
    assert f.data["reason"] == "npm_missing"


# --- the off switch --------------------------------------------------------------------


def test_downloads_off_skips_the_fetch(env, monkeypatch):
    monkeypatch.setenv("RESCUE_NO_DOWNLOADS", "1")
    runner = FakeRunner()
    f = _one(_module(env, runner, monkeypatch).check(_profile()), "could_not_check")
    assert f.data["reason"] == "downloads_off"
    assert runner.calls == []


def test_downloads_off_still_runs_a_copy_already_fetched(env, monkeypatch):
    monkeypatch.setenv("RESCUE_NO_DOWNLOADS", "1")
    _write_install(_install_dir(env))
    runner = FakeRunner()
    result = _module(env, runner, monkeypatch).check(_profile())
    assert runner.named("ci") == []
    assert CODE + "ai_inventory" in _codes(result)


def test_scan_no_downloads_flag(env, monkeypatch):
    from click.testing import CliRunner

    from rescue.cli import main

    out = CliRunner().invoke(main, ["scan", "--json", "--no-attribution", "--no-downloads",
                                    "--module", "ai_agent_audit"])
    assert out.exit_code == 0, out.output
    doc = json.loads(out.stdout)
    [mod] = doc["modules"]
    [finding] = mod["findings"]
    assert finding["code"] == CODE + "could_not_check"
    assert finding["data"]["reason"] == "downloads_off"


# --- vendor files ------------------------------------------------------------------------


def test_vendor_pins_hackmyagent_with_integrity_and_stubs_the_ai_runtime():
    vendor = ROOT / "vendor" / "hackmyagent"
    pkg = json.loads((vendor / "package.json").read_text())
    assert pkg["dependencies"]["hackmyagent"] == "0.33.2"
    lock = json.loads((vendor / "package-lock.json").read_text())
    hma = lock["packages"]["node_modules/hackmyagent"]
    assert hma["version"] == "0.33.2" and hma["integrity"].startswith("sha512-")
    for path, entry in lock["packages"].items():
        if entry.get("resolved", "").startswith("https://"):
            assert entry["resolved"].startswith("https://registry.npmjs.org/"), path
            assert entry.get("integrity"), path
    assert "node_modules/onnxruntime-node/lib" not in lock["packages"]
    assert lock["packages"]["node_modules/onnxruntime-node"].get("link") is True
    assert "throw" in (vendor / "stub" / "index.js").read_text()


def test_frozen_engine_ships_the_vendor_dir():
    spec = (ROOT / "rescue.spec").read_text()
    assert '"vendor"' in spec
    assert '"vendor"' in (ROOT / "setup.py").read_text()


def test_ai_worm_profile_runs_it():
    from rescue.profiles import load_profile

    profile = load_profile(ROOT / "profiles" / "ai_worm_response.yaml")
    assert "ai_agent_audit" in profile.include_modules


# --- live ------------------------------------------------------------------------------------


@pytest.mark.skipif(os.environ.get("RESCUE_LIVE_HMA") != "1", reason="set RESCUE_LIVE_HMA=1")
def test_live_fetch_and_detect(tmp_path, monkeypatch):
    if not shutil.which("node"):
        pytest.skip("needs Node.js")
    monkeypatch.setenv("RESCUE_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.delenv("RESCUE_NO_DOWNLOADS", raising=False)
    mod = next(m for m in discover_modules(ROOT / "modules") if m.name == "ai_agent_audit")
    result = mod.check(_profile())
    assert CODE + "could_not_check" not in _codes(result), [f.description for f in result.findings]
    assert (tmp_path / "cache" / "ReclaimCity" / "hackmyagent-0.33.2").is_dir()


def test_inventory_says_how_to_check_one_project_folder(env, monkeypatch):
    _write_install(_install_dir(env))
    result = _module(env, FakeRunner(), monkeypatch).check(_profile())
    inv = _one(result, "ai_inventory")
    assert "project folder" in inv.description
    assert "OPENA2A_TELEMETRY=off node node_modules/hackmyagent/dist/cli.js detect" in inv.description
    assert f"cd {_install_dir(env)}" in inv.description
    assert inv.data["project_command"].endswith("detect /path/to/project")
