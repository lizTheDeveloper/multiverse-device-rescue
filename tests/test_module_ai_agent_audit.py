"""ai_agent_audit: HackMyAgent's `detect`, fetched into the user cache and run read-only.

node and npm are never really run here: a fake runner stands in for
rescue.command.run and records every call. The live test at the bottom does
the real fetch and run, and only when RESCUE_LIVE_HMA=1.
"""

import json
import os
import shutil
import stat
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


REAL_VENDOR = ROOT / "vendor" / "hackmyagent"


def _write_install(directory: Path, version="0.33.2"):
    """A small stand-in for what npm ci leaves: the vendor files, hackmyagent, the stub link."""
    directory.mkdir(parents=True, exist_ok=True)
    for name in ("package.json", "package-lock.json"):
        if not (directory / name).exists():
            shutil.copy2(REAL_VENDOR / name, directory / name)
    if not (directory / "stub").exists():
        shutil.copytree(REAL_VENDOR / "stub", directory / "stub")
    pkg = directory / "node_modules" / "hackmyagent"
    (pkg / "dist").mkdir(parents=True, exist_ok=True)
    (pkg / "package.json").write_text(json.dumps({"name": "hackmyagent", "version": version}))
    (pkg / "dist" / "cli.js").write_text("// fake\n")
    (directory / "node_modules" / ".package-lock.json").write_text("{}")
    link = directory / "node_modules" / "onnxruntime-node"
    if not link.is_symlink():
        link.symlink_to(Path("..") / "stub")


def _code_module():
    mod = next(m for m in discover_modules(ROOT / "modules") if m.name == "ai_agent_audit")
    return sys.modules[type(mod).__module__]


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
            call["npm_cache_existed"] = Path(args[args.index("--cache") + 1]).parent.is_dir()
        for flag in ("--userconfig", "--globalconfig"):
            if flag in args:
                rc = Path(args[args.index(flag) + 1])
                call[flag[2:] + "_was_empty"] = rc.is_file() and rc.read_text() == ""
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
    # A vendor folder whose tree.sha256 describes the stand-in install.
    vendor = tmp_path / "vendor"
    shutil.copytree(REAL_VENDOR, vendor)
    reference = tmp_path / "reference"
    _write_install(reference)
    code = _code_module()
    files, _, _ = code.tree_hashes(reference)
    (vendor / "tree.sha256").write_text(code.render_manifest(files))
    shutil.rmtree(reference)
    return {"home": home, "cache": cache, "bin": bindir, "tmp": tmp_path, "vendor": vendor}


def _module(env, runner, monkeypatch):
    mod = next(m for m in discover_modules(ROOT / "modules") if m.name == "ai_agent_audit")
    monkeypatch.setattr(sys.modules[type(mod).__module__], "run", runner)
    mod.home = env["home"]
    mod.system_node_dirs = []
    mod.vendor_dir = env["vendor"]
    mod.elevated = False
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
        CODE + "ai_inventory", CODE + "could_not_check", CODE + "changed_during_run",
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
    entry = Path(call["args"][1])
    # It runs Reclaim City's own start-up file in a private copy, which then
    # loads cli.js with module lookup kept inside that copy.
    assert entry.name == "rc-run-detect.cjs"
    assert entry.parent.name == "hackmyagent" and entry.parent.parent.name.startswith(".run-")
    assert _install_dir(env) not in entry.parents and env["home"] not in entry.parents
    assert not entry.exists(), "the run copy is removed afterwards"
    assert call["args"] == [
        str(env["bin"] / "node"), str(entry), "detect", str(env["home"]), "--json", "--depth", "0",
        "--no-contribute",
    ]
    assert call["timeout"] == 60
    assert call["env"]["OPENA2A_TELEMETRY"] == "off"
    home_dir = Path(call["env"]["OPENA2A_HOME"])
    assert call["opena2a_home_existed"]
    assert env["home"] not in home_dir.parents
    # Its telemetry file (~/.config/opena2a) and its temp-folder sweep go there too.
    for var in ("XDG_CONFIG_HOME", "TMPDIR", "TMP", "TEMP"):
        assert call["env"][var] == str(home_dir), var
    assert call["cwd"] == str(home_dir)
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
    # pytest names the temp dir after the test; take it out of each string
    # before JSON escapes it (Windows paths gain doubled backslashes).
    text = json.dumps([[f.title, f.description, f.data] for f in result.findings])
    text = text.replace(json.dumps(str(env["tmp"]))[1:-1], "<tmp>")
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
    mac = mod._node_search_dirs(Platform.DARWIN)
    assert Path("/opt/homebrew/bin") in mac and Path("/usr/local/bin") in mac
    assert env["home"] / ".local" / "bin" in mac
    assert env["home"] / ".volta" / "bin" in mac
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
    assert args[1:7] == ["ci", "--ignore-scripts", "--no-bin-links", "--no-audit", "--no-fund",
                         "--registry=https://registry.npmjs.org/"]
    assert ci["timeout"] == 180
    # The person's .npmrc files (and any npm login token in them) aren't used.
    user_rc = Path(args[args.index("--userconfig") + 1])
    global_rc = Path(args[args.index("--globalconfig") + 1])
    assert ci["userconfig_was_empty"] and ci["globalconfig_was_empty"]
    assert user_rc != global_rc
    assert env["home"] not in user_rc.parents and not user_rc.exists()
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


# --- the saved copy is verified before every run (C1) ---------------------------------


def _cli(env):
    return _install_dir(env) / "node_modules" / "hackmyagent" / "dist" / "cli.js"


def test_vendor_manifest_lists_every_locked_package():
    code = _code_module()
    manifest = code.read_manifest(REAL_VENDOR / "tree.sha256")
    lock = json.loads((REAL_VENDOR / "package-lock.json").read_text())
    for path, entry in lock["packages"].items():
        if not path.startswith("node_modules/") or entry.get("link"):
            continue
        assert f"{path}/package.json" in manifest, path
    assert "node_modules/hackmyagent/dist/cli.js" in manifest
    for name in ("package.json", "package-lock.json", "stub/index.js", "stub/package.json"):
        assert manifest[name] == code._sha256(REAL_VENDOR / name), name
    assert not any(p.startswith("node_modules/.bin/") for p in manifest)
    assert "node_modules/.package-lock.json" not in manifest


def test_manifest_script_uses_the_module_hashing():
    text = (ROOT / "scripts" / "generate_hackmyagent_manifest.py").read_text()
    assert "tree_hashes" in text and "render_manifest" in text and "NPM_CI_ARGS" in text


def test_a_planted_cli_js_never_runs_and_is_fetched_again(env, monkeypatch):
    _write_install(_install_dir(env))
    _cli(env).write_text("console.log('{\"agents\":[],\"mcpServers\":[]}')\n")
    runner = FakeRunner()
    result = _module(env, runner, monkeypatch).check(_profile())
    assert len(runner.named("ci")) == 1
    assert _cli(env).read_text() == "// fake\n"
    assert CODE + "ai_inventory" in _codes(result)


def test_a_planted_cli_js_with_downloads_off_is_deleted_not_run(env, monkeypatch):
    monkeypatch.setenv("RESCUE_NO_DOWNLOADS", "1")
    _write_install(_install_dir(env))
    _cli(env).write_text("// planted\n")
    runner = FakeRunner()
    f = _one(_module(env, runner, monkeypatch).check(_profile()), "could_not_check")
    assert f.data["reason"] == "tampered"
    assert "changed since it was downloaded" in f.description
    assert runner.named("detect") == [] and runner.named("ci") == []
    assert not _install_dir(env).exists()


_POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="POSIX only: chmod 0 doesn't stop "
                                 "reading on Windows, and Windows has no FIFOs (mkfifo)")


@pytest.mark.parametrize("plant", ["changed_file", "missing_file",
                                   pytest.param("unreadable", marks=_POSIX_ONLY),
                                   pytest.param("fifo", marks=_POSIX_ONLY)])
def test_any_change_to_the_saved_copy_counts(env, monkeypatch, plant, tmp_path):
    monkeypatch.setenv("RESCUE_NO_DOWNLOADS", "1")
    install = _install_dir(env)
    _write_install(install)
    nm = install / "node_modules"
    if plant == "changed_file":
        (nm / "hackmyagent" / "package.json").write_text('{"version": "0.33.2", "x": 1}')
    elif plant == "fifo":
        target = install / "stub" / "index.js"
        target.unlink()
        os.mkfifo(target)
    elif plant == "missing_file":
        (install / "stub" / "index.js").unlink()
    runner = FakeRunner()
    mod = _module(env, runner, monkeypatch)
    if plant == "unreadable":
        (nm / "hackmyagent" / "dist" / "cli.js").chmod(0)
    f = _one(mod.check(_profile()), "could_not_check")
    assert f.data["reason"] == "tampered"
    assert runner.named("detect") == []
    assert not install.exists(), "a saved copy that doesn't match is deleted"


def test_extra_files_in_the_saved_copy_are_never_copied_or_run(env, monkeypatch, tmp_path):
    install = _install_dir(env)
    _write_install(install)
    (install / "node_modules" / "commander").mkdir()
    (install / "node_modules" / "commander" / "index.js").write_text("evil()")
    (install / "node_modules" / "evil").symlink_to(tmp_path)
    seen = {}

    def detect(args, cwd, e):
        root = Path(args[1]).parent
        seen["files"] = sorted(p.relative_to(root).as_posix() for p in root.rglob("*")
                               if p.is_file() or p.is_symlink())
        return _result(args, 1, FIXTURE.read_text())

    result = _module(env, FakeRunner(detect=detect), monkeypatch).check(_profile())
    assert CODE + "ai_inventory" in _codes(result)
    assert "node_modules/commander/index.js" not in seen["files"]
    assert "node_modules/evil" not in seen["files"]
    assert "node_modules/onnxruntime-node" in seen["files"]


def test_a_folder_swapped_for_a_link_copies_nothing_from_outside(env, monkeypatch, tmp_path):
    install = _install_dir(env)
    _write_install(install)
    outside = tmp_path / "Messages"
    outside.mkdir()
    (outside / "chat.db").write_text("private messages")
    dist = install / "node_modules" / "hackmyagent" / "dist"
    (outside / "cli.js").write_text("// fake\n")  # even the same bytes are refused
    shutil.rmtree(dist)
    dist.symlink_to(outside)
    code = _code_module()
    expected = code.read_manifest(env["vendor"] / "tree.sha256")
    dest = tmp_path / "copy"
    dest.mkdir()
    for platform in (Platform.DARWIN, Platform.WIN32):  # WIN32: the lstat-based path
        shutil.rmtree(dest)
        dest.mkdir()
        assert code.copy_from_manifest(install, dest, expected, platform) is False
        assert not any(p.name == "chat.db" for p in dest.rglob("*"))
        assert not (dest / "node_modules" / "hackmyagent" / "dist" / "cli.js").exists()


def test_a_saved_copy_that_is_itself_a_link_is_not_read(env, monkeypatch, tmp_path):
    real = tmp_path / "real"
    _write_install(real)
    code = _code_module()
    expected = code.read_manifest(env["vendor"] / "tree.sha256")
    link = tmp_path / "linked"
    link.symlink_to(real)
    dest = tmp_path / "copy"
    dest.mkdir()
    assert code.copy_from_manifest(link, dest, expected, Platform.DARWIN) is False
    assert list(dest.iterdir()) == []
    assert code.copy_from_manifest(link, dest, expected, Platform.WIN32) is False
    assert code.copy_from_manifest(real, dest, expected, Platform.DARWIN) is True
    other = tmp_path / "copy-win"
    other.mkdir()
    assert code.copy_from_manifest(real, other, expected, Platform.WIN32) is True


def test_a_fetch_that_does_not_match_the_manifest_is_not_kept(env, monkeypatch):
    def npm(args, cwd, e):
        _write_install(Path(cwd))
        (Path(cwd) / "node_modules" / "extra.js").write_text("x")
        return _result(args)

    runner = FakeRunner(npm=npm)
    f = _one(_module(env, runner, monkeypatch).check(_profile()), "could_not_check")
    assert f.data["reason"] == "download_mismatch"
    assert not _install_dir(env).exists()
    assert list(_install_dir(env).parent.iterdir()) == []
    assert runner.named("detect") == []


def test_a_good_copy_another_scan_put_in_place_is_kept(env, monkeypatch):
    code = _code_module()
    install = _install_dir(env)
    _write_install(install)
    before = install.stat().st_ino
    runner = FakeRunner()
    mod = _module(env, runner, monkeypatch)
    expected = code.read_manifest(env["vendor"] / "tree.sha256")
    mod._fetch(env["bin"] / "node", install, Platform.DARWIN, expected)
    assert install.stat().st_ino == before
    assert sorted(p.name for p in install.parent.iterdir()) == ["hackmyagent-0.33.2"]


def test_stale_fetch_leftovers_are_cleaned(env, monkeypatch):
    parent = _install_dir(env).parent
    old = parent / ".hackmyagent-old"
    fresh = parent / ".hackmyagent-fresh"
    for d in (old, fresh):
        (d / "node_modules").mkdir(parents=True)
    os.utime(old, (0, 0))
    _module(env, FakeRunner(), monkeypatch).check(_profile())
    assert not old.exists() and fresh.exists()


# --- elevated, HackMyAgent's own settings, node lookups (C1, I2, I4, M8) -----------------


def test_an_elevated_scan_runs_neither_node_nor_npm(env, monkeypatch):
    _write_install(_install_dir(env))
    runner = FakeRunner()
    mod = _module(env, runner, monkeypatch)
    mod.elevated = True
    f = _one(mod.check(_profile()), "could_not_check")
    assert f.data["reason"] == "elevated"
    assert runner.calls == []


def test_elevation_is_asked_of_the_os_by_default(env, monkeypatch):
    mod = _module(env, FakeRunner(), monkeypatch)
    mod.elevated = None
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    assert mod._is_elevated(Platform.LINUX) is True
    monkeypatch.setattr(os, "geteuid", lambda: 501, raising=False)
    assert mod._is_elevated(Platform.DARWIN) is False


def test_hackmyagent_settings_already_here_means_it_is_left_alone(env, monkeypatch):
    legacy = env["home"] / ".hackmyagent" / "config.json"
    legacy.parent.mkdir()
    legacy.write_text('{"contribute": true, "pendingScans": [1]}')
    _write_install(_install_dir(env))
    runner = FakeRunner()
    f = _one(_module(env, runner, monkeypatch).check(_profile()), "could_not_check")
    assert f.data["reason"] == "hackmyagent_settings"
    assert "--no-contribute" in f.description
    assert runner.calls == []
    assert legacy.read_text() == '{"contribute": true, "pendingScans": [1]}'


def test_node_in_the_current_folder_is_never_used(env, monkeypatch, tmp_path):
    here = tmp_path / "downloads"
    here.mkdir()
    for tool in ("node", "npm"):
        (env["bin"] / tool).unlink()
        exe = here / tool
        exe.write_text("#!/bin/sh\n")
        exe.chmod(0o755)
    monkeypatch.chdir(here)
    monkeypatch.setenv("PATH", os.pathsep.join([".", "", "downloads"]))
    runner = FakeRunner()
    f = _one(_module(env, runner, monkeypatch).check(_profile()), "could_not_check")
    assert f.data["reason"] == "node_missing"
    assert runner.calls == []


def test_node_that_fails_to_start_is_not_called_too_old(env, monkeypatch):
    runner = FakeRunner()
    runner.node_version = None
    real = runner.__call__

    def broken(args, **kw):
        if list(map(str, args))[1:] == ["--version"]:
            runner.calls.append({"args": list(map(str, args))})
            return _result(args, 1, err="dyld: Library not loaded")
        return real(args, **kw)

    f = _one(_module(env, broken, monkeypatch).check(_profile()), "could_not_check")
    assert f.data["reason"] == "node_failed"
    assert "didn't start" in f.description


def test_windows_runs_npm_cli_js_through_node_without_cmd(env, monkeypatch, tmp_path):
    mod = _module(env, FakeRunner(), monkeypatch)
    nodejs = tmp_path / "nodejs"
    cli = nodejs / "node_modules" / "npm" / "bin" / "npm-cli.js"
    cli.parent.mkdir(parents=True)
    cli.write_text("")
    node = nodejs / "node.exe"
    argv, extra = mod._npm_command(node, Platform.WIN32, tmp_path / "c", tmp_path / "u", tmp_path / "g")
    assert argv[:3] == [str(node), str(cli), "ci"]
    assert "--ignore-scripts" in argv and "--no-bin-links" in argv
    assert "--registry=https://registry.npmjs.org/" in argv
    assert not any(a in argv for a in ("--cache", "--userconfig", "--globalconfig"))
    assert not any(a.lower().endswith((".cmd", ".bat")) for a in argv)
    assert extra == {"npm_config_cache": str(tmp_path / "c"),
                     "npm_config_userconfig": str(tmp_path / "u"),
                     "npm_config_globalconfig": str(tmp_path / "g")}
    cli.unlink()
    with pytest.raises(Exception) as err:
        mod._npm_command(node, Platform.WIN32, tmp_path / "c", tmp_path / "u", tmp_path / "g")
    assert getattr(err.value, "reason", None) == "npm_missing"


def test_the_stub_link_is_made_per_platform(env, monkeypatch, tmp_path):
    code = _code_module()
    root = tmp_path / "copy"
    (root / "node_modules").mkdir(parents=True)
    (root / "stub").mkdir()
    made = []
    monkeypatch.setattr(code, "_create_junction", lambda target, link: made.append((target, link)))
    code.Module._make_stub_link(root, Platform.WIN32)
    assert made == [(str(root / "stub"), str(root / "node_modules" / "onnxruntime-node"))]
    code.Module._make_stub_link(root, Platform.DARWIN)
    link = root / "node_modules" / "onnxruntime-node"
    assert link.is_symlink() and link.resolve() == (root / "stub").resolve()


def test_a_stub_link_that_cannot_be_made_has_its_own_reason(env, monkeypatch):
    _write_install(_install_dir(env))
    runner = FakeRunner()
    mod = _module(env, runner, monkeypatch)

    def fail(*a, **k):
        raise OSError("links not allowed here")

    monkeypatch.setattr(os, "symlink", fail)
    f = _one(mod.check(_profile()), "could_not_check")
    assert f.data["reason"] == "stub_link_failed"
    assert "not a sign that anything was changed" in f.description
    assert runner.named("detect") == []
    assert _install_dir(env).exists(), "the saved copy is fine and kept"


def test_junctions_are_links_even_without_isjunction(monkeypatch, tmp_path):
    code = _code_module()
    target = tmp_path / "junction"
    target.mkdir()
    monkeypatch.delattr(os.path, "isjunction", raising=False)
    real_lstat = os.lstat

    class Attrs:
        st_file_attributes = 0x400
        st_mode = real_lstat(target).st_mode

    monkeypatch.setattr(os, "lstat", lambda p, *a, **k: Attrs() if Path(p) == target
                        else real_lstat(p, *a, **k))
    assert code._is_link(target) is True
    assert code._is_link(tmp_path) is False


# --- the run copy (N1) ---------------------------------------------------------------------


def _cli_in(args):
    """cli.js inside the run copy whose start-up file is args[1]."""
    return Path(args[1]).parent / "node_modules" / "hackmyagent" / "dist" / "cli.js"


def _changed(result):
    [finding] = result.findings
    assert finding.code == CODE + "changed_during_run"
    return finding


def test_a_copy_changed_while_it_runs_is_a_warning_and_the_saved_copy_goes(env, monkeypatch):
    _write_install(_install_dir(env))

    def detect(args, cwd, e):
        _cli_in(args).write_text("// swapped during the run\n")
        return _result(args, 1, FIXTURE.read_text())

    runner = FakeRunner(detect=detect)
    f = _changed(_module(env, runner, monkeypatch).check(_profile()))
    assert f.severity == Severity.WARNING
    assert "What to do:" in f.description
    assert "may mean another program" in f.description
    assert "threw its results away" in f.description
    assert not Path(runner.named("detect")[0]["args"][1]).exists()
    assert not _install_dir(env).exists(), "the saved copy is deleted too"


def test_a_run_that_fails_after_the_copy_changed_still_says_so(env, monkeypatch):
    _write_install(_install_dir(env))

    def detect(args, cwd, e):
        (Path(args[1]).parent / "node_modules" / "hackmyagent" / "extra.js").write_text("x")
        return _result(args, 5)

    _changed(_module(env, FakeRunner(detect=detect), monkeypatch).check(_profile()))
    assert not _install_dir(env).exists()


def test_a_link_loop_planted_during_the_run_is_a_change_not_a_crash(env, monkeypatch):
    _write_install(_install_dir(env))

    def detect(args, cwd, e):
        link = Path(args[1]).parent / "node_modules" / "onnxruntime-node"
        link.unlink()
        link.symlink_to(link.name)  # points at itself
        return _result(args, 1, FIXTURE.read_text())

    result = _module(env, FakeRunner(detect=detect), monkeypatch).check(_profile())
    assert result.error is None
    _changed(result)


def test_the_run_copy_is_private_and_verified(env, monkeypatch):
    _write_install(_install_dir(env))
    seen = {}

    def detect(args, cwd, e):
        root = Path(args[1]).parent
        seen["mode"] = stat.S_IMODE(root.parent.stat().st_mode)
        link = root / "node_modules" / "onnxruntime-node"
        seen["link"] = link.is_symlink() and link.resolve() == (root / "stub").resolve()
        # Byte for byte (a text-mode write on Windows would add \r).
        seen["bootstrap"] = Path(args[1]).read_bytes() == _code_module().BOOTSTRAP_JS.encode("utf-8")
        return _result(args, 1, FIXTURE.read_text())

    _module(env, FakeRunner(detect=detect), monkeypatch).check(_profile())
    assert seen["link"] is True and seen["bootstrap"] is True
    if sys.platform != "win32":  # POSIX modes don't apply on Windows
        assert seen["mode"] == 0o700


# --- the child environment (N2) ------------------------------------------------------------


def test_node_and_npm_get_only_an_allow_listed_environment(env, monkeypatch):
    monkeypatch.setenv("NODE_OPTIONS", "--require /tmp/evil.js")
    monkeypatch.setenv("NODE_PATH", "/tmp/evil")
    monkeypatch.setenv("npm_config_registry", "https://evil.example/")
    monkeypatch.setenv("SOME_SECRET_TOKEN", "x")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    monkeypatch.setenv("LC_ALL", "en_US.UTF-8")
    runner = FakeRunner()
    _module(env, runner, monkeypatch).check(_profile())
    assert {"--version", "ci", "detect"} <= {a for c in runner.calls for a in c["args"]}
    for call in runner.calls:
        child = call["env"]
        assert child is not None, call["args"]
        for name in ("NODE_OPTIONS", "NODE_PATH", "npm_config_registry", "SOME_SECRET_TOKEN"):
            assert name not in child, (name, call["args"])
        assert child["HTTPS_PROXY"] == "http://proxy.example:3128"
        assert child["LC_ALL"] == "en_US.UTF-8"
        assert child["PATH"].split(os.pathsep)[0] == str(env["bin"])


# --- missing manifest (N8) -----------------------------------------------------------------


def test_a_missing_file_list_is_a_packaging_problem(env, monkeypatch):
    (env["vendor"] / "tree.sha256").unlink()
    runner = FakeRunner()
    f = _one(_module(env, runner, monkeypatch).check(_profile()), "could_not_check")
    assert f.data["reason"] == "manifest_missing"
    assert "Reinstalling or updating Reclaim City" in f.description
    assert runner.calls == []


# --- HackMyAgent's self-check log in ~/.nanomind -----------------------------------------


def _event(when=None):
    from datetime import datetime, timezone

    stamp = (when or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z")
    return json.dumps({"seq": 0, "timestamp": stamp, "eventType": "check_pass",
                       "detail": "All 4 checks passed"}) + "\n"


def _detect_appending_to_nanomind(home, extra=None):
    def detect(args, cwd, env):
        log = home / ".nanomind" / "integrity-events.jsonl"
        log.parent.mkdir(exist_ok=True)
        with open(log, "a") as fh:
            fh.write(_event())
        if extra:
            extra(log)
        return _result(args, 1, FIXTURE.read_text())
    return detect


def test_the_self_check_log_it_creates_is_removed(env, monkeypatch):
    _write_install(_install_dir(env))
    runner = FakeRunner(detect=_detect_appending_to_nanomind(env["home"]))
    result = _module(env, runner, monkeypatch).check(_profile())
    assert CODE + "ai_inventory" in _codes(result)
    assert list(env["home"].iterdir()) == []


def test_an_existing_self_check_log_is_put_back_as_it_was(env, monkeypatch):
    _write_install(_install_dir(env))
    nanomind = env["home"] / ".nanomind"
    nanomind.mkdir()
    (nanomind / "integrity-events.jsonl").write_text('{"seq":0}\n')
    (nanomind / "models").mkdir()
    runner = FakeRunner(detect=_detect_appending_to_nanomind(env["home"]))
    result = _module(env, runner, monkeypatch).check(_profile())
    assert (nanomind / "integrity-events.jsonl").read_text() == '{"seq":0}\n'
    assert sorted(p.name for p in nanomind.iterdir()) == ["integrity-events.jsonl", "models"]
    assert "left_in_home" not in _one(result, "ai_inventory").data


def _left(result):
    return _one(result, "ai_inventory").data.get("left_in_home")


def test_a_line_someone_else_wrote_during_the_run_is_left_alone(env, monkeypatch):
    from datetime import datetime, timezone

    _write_install(_install_dir(env))
    nanomind = env["home"] / ".nanomind"
    nanomind.mkdir()
    log = nanomind / "integrity-events.jsonl"
    log.write_text('{"seq":0}\n')

    def other_writer(path):
        with open(path, "a") as fh:
            fh.write(_event(datetime(2020, 1, 1, tzinfo=timezone.utc)))

    runner = FakeRunner(detect=_detect_appending_to_nanomind(env["home"], other_writer))
    result = _module(env, runner, monkeypatch).check(_profile())
    assert log.read_text().startswith('{"seq":0}\n') and log.read_text().count("\n") == 3
    assert _left(result) == "~/.nanomind/integrity-events.jsonl"
    assert "left it as it is" in _one(result, "ai_inventory").description


def test_a_new_log_with_someone_elses_line_is_kept(env, monkeypatch):
    _write_install(_install_dir(env))

    def other_writer(path):
        with open(path, "a") as fh:
            fh.write("not an event\n")

    runner = FakeRunner(detect=_detect_appending_to_nanomind(env["home"], other_writer))
    result = _module(env, runner, monkeypatch).check(_profile())
    assert (env["home"] / ".nanomind" / "integrity-events.jsonl").exists()
    assert _left(result) == "~/.nanomind/integrity-events.jsonl"


def test_a_log_swapped_for_a_link_truncates_nothing(env, monkeypatch, tmp_path):
    _write_install(_install_dir(env))
    victim = tmp_path / "chat.db"
    victim.write_text("precious data\n" * 10)
    nanomind = env["home"] / ".nanomind"
    nanomind.mkdir()
    log = nanomind / "integrity-events.jsonl"
    log.write_text("")

    def swap(path):
        path.unlink()
        path.symlink_to(victim)

    runner = FakeRunner(detect=_detect_appending_to_nanomind(env["home"], swap))
    result = _module(env, runner, monkeypatch).check(_profile())
    assert victim.read_text() == "precious data\n" * 10
    assert log.is_symlink()
    assert _left(result) == "~/.nanomind/integrity-events.jsonl"


def test_a_log_replaced_by_another_file_is_not_truncated(env, monkeypatch):
    _write_install(_install_dir(env))
    nanomind = env["home"] / ".nanomind"
    nanomind.mkdir()
    log = nanomind / "integrity-events.jsonl"
    log.write_text('{"seq":0}\n')

    def replace(path):
        fresh = path.with_name("new")
        fresh.write_text(path.read_text() + _event())
        os.replace(fresh, path)

    runner = FakeRunner(detect=_detect_appending_to_nanomind(env["home"], replace))
    result = _module(env, runner, monkeypatch).check(_profile())
    assert log.read_text().count("\n") == 3
    assert _left(result) == "~/.nanomind/integrity-events.jsonl"


def test_a_nanomind_folder_without_the_log_keeps_everything_else(env, monkeypatch):
    _write_install(_install_dir(env))
    nanomind = env["home"] / ".nanomind"
    (nanomind / "models").mkdir(parents=True)
    runner = FakeRunner(detect=_detect_appending_to_nanomind(env["home"]))
    _module(env, runner, monkeypatch).check(_profile())
    assert sorted(p.name for p in nanomind.iterdir()) == ["models"]


# --- output shape (M3) -----------------------------------------------------------------------


@pytest.mark.parametrize("doc, reason", [
    ({"agents": 5, "mcpServers": []}, "bad_output"),
    ({"mcpServers": []}, "bad_output"),
    ({"agents": [], "mcpServers": [], "aiConfigs": "x"}, "bad_output"),
    ({"agents": [], "mcpServers": [], "coverage": {"measured": False}}, "not_measured"),
])
def test_output_of_the_wrong_shape_is_could_not_check(env, monkeypatch, doc, reason):
    _write_install(_install_dir(env))
    runner = FakeRunner(detect=lambda a, c, e: _result(a, 0, json.dumps(doc)))
    result = _module(env, runner, monkeypatch).check(_profile())
    assert result.error is None
    assert _one(result, "could_not_check").data["reason"] == reason


def test_capabilities_that_are_not_a_list_are_ignored(env, monkeypatch):
    _write_install(_install_dir(env))
    doc = {"agents": [], "mcpServers": [{"name": "db", "source": "Cursor", "risk": "high",
                                         "capabilities": "database"}]}
    runner = FakeRunner(detect=lambda a, c, e: _result(a, 0, json.dumps(doc)))
    mcp = _one(_module(env, runner, monkeypatch).check(_profile()), "risky_mcp_server")
    assert mcp.data["capabilities"] == []


# --- live ------------------------------------------------------------------------------------


# Every bare name required or imported somewhere in HackMyAgent 0.33.2's tree
# that the tree doesn't contain (found by scanning its .js files).
OPTIONAL_NAMES_NOT_IN_THE_TREE = ['@cfworker/json-schema', '@ljharb/eslint-config', 'ava', 'core-js', 'ejs', 'error-cause', 'es-abstract', 'es-value-fixtures', 'fastify', 'for-each', 'functions-have-names', 'get-own-property-symbols', 'globalthis', 'has-bigints', 'has-override-mistake', 'has-property-descriptors', 'has-proto', 'has-strict-mode', 'has-tostringtag', 'itty-router', 'jsonfile', 'make-arrow-function', 'make-async-function', 'make-async-generator-function', 'make-generator-function', 'mkdirp', 'mock-property', 'neostandard', 'off', 'proxyquire', 're2', 'rimraf', 'semver', 'string.prototype.repeat', 'supports-color', 'tap', 'tape', 'tinybench', 'uri-js', 'vitest']


def _snapshot(root: Path) -> dict:
    return {p.relative_to(root).as_posix(): (p.read_bytes() if p.is_file() else None)
            for p in sorted(root.rglob("*"))}


@pytest.mark.skipif(os.environ.get("RESCUE_LIVE_HMA") != "1", reason="set RESCUE_LIVE_HMA=1")
def test_live_fetch_and_detect_change_nothing_in_home(tmp_path, monkeypatch):
    """The real download and run, with a fake home: nothing in it may change."""
    if not shutil.which("node"):
        pytest.skip("needs Node.js")
    home, xdg, cache = tmp_path / "home", tmp_path / "xdg-config", tmp_path / "cache"
    for d in (home, xdg):
        d.mkdir()
    for var, value in (("HOME", home), ("USERPROFILE", home), ("XDG_CONFIG_HOME", xdg),
                       ("RESCUE_CACHE_DIR", cache)):
        monkeypatch.setenv(var, str(value))
    monkeypatch.delenv("RESCUE_NO_DOWNLOADS", raising=False)
    # Something for detect to find: Cursor with a database add-on.
    (home / ".cursor").mkdir()
    (home / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": {
        "postgres": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres"]}}}))

    def check():
        mod = next(m for m in discover_modules(ROOT / "modules") if m.name == "ai_agent_audit")
        return mod.check(_profile())

    # 1. HackMyAgent's own settings are here: it is left alone, untouched.
    legacy = home / ".hackmyagent" / "config.json"
    legacy.parent.mkdir()
    legacy.write_text('{"contribute": true, "pendingScans": [{"x": 1}]}')
    before = _snapshot(home)
    f = _one(check(), "could_not_check")
    assert f.data["reason"] == "hackmyagent_settings"
    assert _snapshot(home) == before and not cache.exists()
    shutil.rmtree(home / ".hackmyagent")

    # Packages a require in the tree asks for but the tree doesn't have (debug's
    # optional `supports-color`, for one), planted where node would otherwise
    # look: ~/.node_modules, ~/node_modules and node_modules in the cache's
    # parent folders. None of them may load.
    marker = tmp_path / "planted-package-loaded"
    for folder in (home / ".node_modules", home / "node_modules", tmp_path / "node_modules",
                   cache / "node_modules", cache / "ReclaimCity" / "node_modules"):
        for name in OPTIONAL_NAMES_NOT_IN_THE_TREE:
            (folder / name).mkdir(parents=True)
            (folder / name / "package.json").write_text(json.dumps({"name": name, "main": "index.js"}))
            (folder / name / "index.js").write_text(
                f"require('fs').appendFileSync({json.dumps(str(marker))}, {json.dumps(name + ' ')});\n")

    # 2. The real fetch and detect: findings, and home and XDG_CONFIG_HOME unchanged.
    before = _snapshot(home)
    result = check()
    assert CODE + "could_not_check" not in _codes(result), [f.description for f in result.findings]
    assert CODE + "ai_inventory" in _codes(result)
    install = cache / "ReclaimCity" / "hackmyagent-0.33.2"
    assert install.is_dir()
    assert _snapshot(home) == before
    assert list(xdg.iterdir()) == []
    assert not marker.exists(), marker.read_text()

    # 3. A planted cli.js (right version, changed code) is never run.
    marker = tmp_path / "planted-code-ran"
    cli = install / "node_modules" / "hackmyagent" / "dist" / "cli.js"
    cli.write_text(f"require('fs').writeFileSync({json.dumps(str(marker))}, 'x');\n"
                   "console.log(JSON.stringify({agents: [], mcpServers: []}));\n")
    monkeypatch.setenv("RESCUE_NO_DOWNLOADS", "1")
    f = _one(check(), "could_not_check")
    assert f.data["reason"] == "tampered"
    assert not marker.exists() and not install.exists()


def test_every_working_folder_is_inside_the_users_cache_not_shared_tmp(env, monkeypatch):
    """node looks for node_modules in every parent folder; a shared /tmp could plant one."""
    seen = {}

    def npm(args, cwd, e):
        seen["work"] = Path(cwd).parent
        seen["npm_cache"] = Path(args[args.index("--cache") + 1]).parent.parent
        seen["userconfig"] = Path(args[args.index("--userconfig") + 1]).parent.parent
        _write_install(Path(cwd))
        return _result(args)

    def detect(args, cwd, e):
        seen["run"] = Path(args[1]).parents[2]
        seen["settings"] = Path(cwd).parent
        seen["tmpdir"] = Path(e["TMPDIR"]).parent
        return _result(args, 1, FIXTURE.read_text())

    _module(env, FakeRunner(npm=npm, detect=detect), monkeypatch).check(_profile())
    parent = _install_dir(env).parent
    assert seen == {k: parent for k in seen}, seen
    assert sorted(p.name for p in parent.iterdir()) == ["hackmyagent-0.33.2"]


def test_stale_leftovers_of_every_kind_are_cleaned(env, monkeypatch):
    parent = _install_dir(env).parent
    parent.mkdir(parents=True)
    names = [".hackmyagent-a", ".run-b", ".npm-cache-c", ".settings-d"]
    for name in names:
        (parent / name).mkdir()
        os.utime(parent / name, (0, 0))
    _module(env, FakeRunner(), monkeypatch).check(_profile())
    assert sorted(p.name for p in parent.iterdir()) == ["hackmyagent-0.33.2"]


def test_a_link_planted_in_the_run_folder_is_never_written_through(tmp_path):
    """The write side doesn't follow links either: nothing lands outside the run folder."""
    import hashlib

    code = _code_module()
    src = tmp_path / "src"
    (src / "a").mkdir(parents=True)
    (src / "a" / "f.js").write_bytes(b"GOOD")
    (src / "top.js").write_bytes(b"TOP")
    expected = {"a/f.js": hashlib.sha256(b"GOOD").hexdigest(),
                "top.js": hashlib.sha256(b"TOP").hexdigest()}
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    for planted in ("dir", "file"):
        dest = tmp_path / f"dest-{planted}"
        dest.mkdir()
        if planted == "dir":
            os.symlink(outside, dest / "a")       # a folder step swapped for a link
        else:
            os.symlink(victim, dest / "top.js")   # a file swapped for a link
        for platform in (Platform.DARWIN, Platform.WIN32):  # WIN32: the lstat-checked path
            with pytest.raises(Exception) as err:
                code.copy_from_manifest(src, dest, expected, platform)
            assert type(err.value).__name__ == "_DestinationError", platform
            assert list(outside.iterdir()) == []
            assert victim.read_text() == "keep me"
    # A clean run folder: folders 0700, files 0600, nothing else.
    dest = tmp_path / "dest-clean"
    dest.mkdir()
    assert code.copy_from_manifest(src, dest, expected, Platform.DARWIN) is True
    if sys.platform != "win32":  # POSIX modes don't apply on Windows
        assert stat.S_IMODE((dest / "a").stat().st_mode) == 0o700
        assert stat.S_IMODE((dest / "a" / "f.js").stat().st_mode) == 0o600
    assert (dest / "a" / "f.js").read_bytes() == b"GOOD"


def test_changed_during_run_text_with_downloads_off(env, monkeypatch):
    monkeypatch.setenv("RESCUE_NO_DOWNLOADS", "1")
    _write_install(_install_dir(env))

    def detect(args, cwd, e):
        _cli_in(args).write_text("// swapped\n")
        return _result(args, 1, FIXTURE.read_text())

    f = _changed(_module(env, FakeRunner(detect=detect), monkeypatch).check(_profile()))
    assert "next checkup that's allowed to download" in f.description
    assert "downloaded next time" not in f.description


# --- module lookup confined to the run copy -------------------------------------------------


def test_a_start_up_file_changed_during_the_run_counts_as_a_change(env, monkeypatch):
    _write_install(_install_dir(env))

    def detect(args, cwd, e):
        Path(args[1]).write_text("require('/elsewhere/evil.js');\n")
        return _result(args, 1, FIXTURE.read_text())

    _changed(_module(env, FakeRunner(detect=detect), monkeypatch).check(_profile()))


def test_the_start_up_file_is_written_by_reclaim_city_and_confines_lookup():
    code = _code_module()
    text = code.BOOTSTRAP_JS
    for needle in ("_nodeModulePaths", "_resolveLookupPaths", "_resolveFilename",
                   "globalPaths", "registerHooks", "register(", "node_modules', 'hackmyagent', 'dist', 'cli.js'"):
        assert needle in text, needle
    assert code.BOOTSTRAP_NAME == "rc-run-detect.cjs"
    assert code.DETECT_ARGS[1] == code.BOOTSTRAP_NAME


def _node_binaries():
    found = []
    for candidate in [shutil.which("node"), "/opt/homebrew/opt/node@18/bin/node",
                      "/opt/homebrew/opt/node@20/bin/node", "/opt/homebrew/opt/node@22/bin/node",
                      "/usr/local/bin/node", "/opt/homebrew/bin/node"]:
        if not candidate or not os.access(candidate, os.X_OK):
            continue
        import subprocess

        try:
            version = subprocess.run([candidate, "--version"], capture_output=True, text=True,
                                     timeout=10).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            continue
        if version.startswith("v") and version not in {v for v, _ in found}:
            found.append((version, candidate))
    return found


def _canary(folder: Path, name: str):
    (folder / name).mkdir(parents=True)
    (folder / name / "package.json").write_text(json.dumps({"name": name, "main": "index.js"}))
    (folder / name / "index.js").write_text(
        f"require('fs').appendFileSync(process.env.MARK, {json.dumps(name + ' ')});\n")


@pytest.mark.parametrize("version, node", _node_binaries() or [pytest.param(None, None, marks=pytest.mark.skip(reason="needs Node.js"))])
def test_the_start_up_file_loads_nothing_from_outside_the_copy(tmp_path, version, node):
    """Packages planted in a parent folder's node_modules and in ~/.node_modules
    (by require, import(), and a static import inside an ES module) never load."""
    import subprocess

    code = _code_module()
    marks = tmp_path / "marks"
    marks.write_text("")
    for name in ("canary-cjs", "canary-esm", "canary-static", "canary-dynamic"):
        _canary(tmp_path / "node_modules", name)
    _canary(tmp_path / "home" / ".node_modules", "canary-home")
    root = tmp_path / "run" / "hackmyagent"
    nm = root / "node_modules"
    (root).mkdir(parents=True)
    (root / code.BOOTSTRAP_NAME).write_text(code.BOOTSTRAP_JS)
    _canary(nm, "local-cjs")
    (nm / "local-esm").mkdir()
    (nm / "local-esm" / "package.json").write_text('{"name":"local-esm","type":"module","main":"index.js"}')
    (nm / "local-esm" / "index.js").write_text(
        "import 'local-cjs'; try { await import('canary-dynamic'); } catch {} export default 1;\n")
    (nm / "static-esm").mkdir()
    (nm / "static-esm" / "package.json").write_text('{"name":"static-esm","type":"module","main":"index.js"}')
    (nm / "static-esm" / "index.js").write_text("import 'canary-static'; export default 2;\n")
    (nm / "hackmyagent" / "dist").mkdir(parents=True)
    (nm / "hackmyagent" / "dist" / "cli.js").write_text("""
const out = { argv: process.argv.slice(2) };
try { require('canary-cjs'); } catch (e) {}
try { require('canary-home'); } catch (e) {}
(async () => {
  try { await import('canary-esm'); } catch (e) {}
  try { await import('local-esm'); out.localEsm = true; } catch (e) { out.localEsm = String(e); }
  try { require('static-esm'); } catch (e) {}
  try { require('local-cjs'); out.localCjs = true; } catch (e) {}
  console.log(JSON.stringify(out));
})();
""")
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path / "home"),
           "USERPROFILE": str(tmp_path / "home"), "MARK": str(marks)}
    for name in ("SystemRoot", "SYSTEMROOT", "windir", "TEMP", "TMP"):  # node needs these on Windows
        if name in os.environ:
            env[name] = os.environ[name]
    # Control: run cli.js directly, and the planted packages do load.
    subprocess.run([node, str(nm / "hackmyagent" / "dist" / "cli.js")], capture_output=True,
                   text=True, env=env, timeout=60)
    assert "canary-cjs" in marks.read_text() and "canary-home" in marks.read_text()
    marks.write_text("")
    out = subprocess.run([node, str(root / code.BOOTSTRAP_NAME), "detect", "/h", "--json"],
                         capture_output=True, text=True, env=env, timeout=60)
    result = json.loads(out.stdout.strip().splitlines()[-1])
    assert result["argv"] == ["detect", "/h", "--json"]
    assert result["localEsm"] is True and result["localCjs"] is True  # inside the copy still works
    assert "canary" not in marks.read_text(), (version, marks.read_text())


def test_elevated_is_reported_before_downloads_off(env, monkeypatch):
    """Administrator rights are the safety reason, so they win over --no-downloads."""
    monkeypatch.setenv("RESCUE_NO_DOWNLOADS", "1")
    runner = FakeRunner()
    mod = _module(env, runner, monkeypatch)
    mod.elevated = True
    f = _one(mod.check(_profile()), "could_not_check")
    assert f.data["reason"] == "elevated"
    assert runner.calls == []


def test_the_log_is_closed_before_it_is_deleted(env, monkeypatch):
    """Windows can't delete a file that is still open; the undo must close it first."""
    _write_install(_install_dir(env))
    mod = _module(env, FakeRunner(detect=_detect_appending_to_nanomind(env["home"])), monkeypatch)
    code = sys.modules[type(mod).__module__]
    open_fds = set()
    real_open, real_close, real_unlink = os.open, os.close, os.unlink

    def tracking_open(path, *a, **k):
        fd = real_open(path, *a, **k)
        if str(path).endswith("integrity-events.jsonl"):
            open_fds.add(fd)
        return fd

    def tracking_close(fd):
        open_fds.discard(fd)
        return real_close(fd)

    def windows_like_unlink(path, *a, **k):
        if str(path).endswith("integrity-events.jsonl") and open_fds:
            raise PermissionError("the file is still open")
        return real_unlink(path, *a, **k)

    monkeypatch.setattr(code.os, "open", tracking_open)
    monkeypatch.setattr(code.os, "close", tracking_close)
    monkeypatch.setattr(code.os, "unlink", windows_like_unlink)
    result = mod.check(_profile())
    assert list(env["home"].iterdir()) == []
    assert "left_in_home" not in _one(result, "ai_inventory").data
