"""rootkit_scanners: rkhunter and chkrootkit, run as root when installed, false alarms explained.

The tools are never really run: a fake runner stands in for
rescue.command.run. The sample output below is in each tool's real format
(rkhunter 1.4.6 --rwo, chkrootkit 0.59 -q) with warnings Debian and Ubuntu
users commonly see.
"""

import functools
import sys
from pathlib import Path

import pytest

from rescue.command import CommandResult
from rescue.models import Platform, Severity, SystemProfile
from rescue.registry import discover_modules

ROOT = Path(__file__).parent.parent
CODE = "security.rootkit_scanners."

RKHUNTER_UBUNTU = """\
Warning: The command '/usr/bin/lwp-request' has been replaced by a script: /usr/bin/lwp-request: Perl script text executable
Warning: The file properties have changed:
         File: /usr/bin/curl
         Current hash: 3f1a...
         Stored hash : 9b2c...
Warning: Hidden directory found: /etc/.java
Warning: Hidden file found: /etc/.updated: ASCII text
Warning: Process '/usr/sbin/NetworkManager' (PID 812) is using a packet capture socket.
Warning: Suspicious file types found in /dev:
         /dev/shm/PostgreSQL.1804289383: data
         /dev/shm/pulse-shm-2345: data
Warning: The SSH configuration option 'PermitRootLogin' has not been set.
Warning: Invalid SCRIPTWHITELIST configuration option: Non-existent pathname: /usr/bin/groups
"""

RKHUNTER_ROOTKIT = """\
Warning: Found file '/usr/lib/libext-2.so.7'. Possible rootkit: Ebury - SSH Rootkit
Warning: Hidden file found: /usr/lib/.x/sshd: ELF 64-bit LSB executable
"""

CHKROOTKIT_UBUNTU = """\
/usr/lib/debug/.build-id /usr/lib/python3/dist-packages/.path /usr/lib/jvm/.java-1.17.0-openjdk-amd64.jinfo
/usr/lib/debug/.build-id
eth0: PF_PACKET(/sbin/dhclient, /usr/sbin/NetworkManager)
INFECTED PORTS: ( 465)
Checking `bindshell'... INFECTED
user bob deleted or never logged from lastlog!
not tested: can't exec ./chkutmp
"""

CHKROOTKIT_BAD = """\
Warning: Possible Showtee Rootkit installed
You have     2 process hidden for readdir command
chkproc: Warning: Possible LKM Trojan installed
INFECTED: Possible Malicious Linux.Xor.DDoS installed
/tmp/installer-x86_64
eth0: PF_PACKET(/tmp/.cache/kworker)
"""


def _profile(platform=Platform.LINUX):
    return SystemProfile(
        platform=platform, os_name="Ubuntu", os_version="24.04", architecture="x86_64",
        cpu_model="x", cpu_cores=4, ram_bytes=8 * 1024**3,
    )


def _result(args, rc=0, out="", err="", timed_out=False):
    return CommandResult(
        args=list(args), returncode=None if timed_out else rc, stdout=out, stderr=err,
        timed_out=timed_out, error="timed out" if timed_out else None,
        duration_s=0.1, truncated=False,
    )


@functools.lru_cache(maxsize=None)
def _code_module():
    mod = next(m for m in discover_modules(ROOT / "modules") if m.name == "rootkit_scanners")
    return sys.modules[type(mod).__module__]


class FakeRunner:
    def __init__(self, outputs):
        self.outputs = outputs  # tool name -> CommandResult factory or text
        self.calls = []

    def __call__(self, args, *, timeout=20.0, env=None, **kw):
        args = [str(a) for a in args]
        self.calls.append({"args": args, "timeout": timeout, "env": env, "cwd": kw.get("cwd")})
        out = self.outputs[Path(args[0]).name]
        return out(args) if callable(out) else _result(args, 1 if out else 0, out)


@pytest.fixture
def setup(tmp_path, monkeypatch):
    code = _code_module()

    def make(outputs, tools=("rkhunter", "chkrootkit"), run_scanners=True, elevated=True,
             root_owned=True):
        runner = FakeRunner(outputs)
        monkeypatch.setattr(code, "run", runner)
        candidates = {}
        for tool in ("rkhunter", "chkrootkit"):
            exe = tmp_path / "sbin" / tool
            if tool in tools:
                exe.parent.mkdir(exist_ok=True)
                exe.write_text("#!/bin/sh\n")
                exe.chmod(0o755)
            candidates[tool] = (str(exe),)
        mod = code.Module()
        mod.configure({"run_scanners": run_scanners})
        mod.candidates = candidates
        mod.elevated = elevated
        mod.root_owned = lambda path: root_owned
        return mod, runner

    return make


def _codes(result):
    return [f.code.split(".")[-1] for f in result.findings]


def test_off_by_default_runs_nothing_and_says_so(setup):
    mod, runner = setup({}, run_scanners=False)
    result = mod.check(_profile())
    assert runner.calls == []
    [f] = result.findings
    assert f.code == CODE + "not_run" and "checked nothing" in f.description
    assert f.data["installed"] == ["chkrootkit", "rkhunter"]


def test_not_root_is_couldnt_run_not_clean(setup):
    mod, runner = setup({}, elevated=False)
    [f] = mod.check(_profile()).findings
    assert f.code == CODE + "needs_admin" and f.severity == Severity.INFO
    assert "doesn't mean the computer is clean" in f.description
    assert runner.calls == []


def test_not_installed_says_how_to_install(setup):
    mod, _ = setup({}, tools=())
    [f] = mod.check(_profile()).findings
    assert f.code == CODE + "not_installed"
    assert "apt install rkhunter chkrootkit" in f.description


def test_both_run_read_only_with_a_fixed_path(setup):
    mod, runner = setup({"rkhunter": "", "chkrootkit": ""})
    result = mod.check(_profile())
    rk, chk = runner.calls
    assert rk["args"][1:] == ["--check", "--sk", "--rwo", "--nocolors", "--nolog", "--nomow"]
    assert chk["args"][1:] == ["-q"]
    for call in runner.calls:
        assert call["env"]["PATH"] == "/usr/sbin:/usr/bin:/sbin:/bin"
        assert "--propupd" not in call["args"] and "--update" not in call["args"]
    [f] = result.findings
    assert f.code == CODE + "ran_clean"
    assert "without ruling it out" in f.description


def test_the_usual_ubuntu_false_alarms_are_explained_not_raised(setup):
    mod, _ = setup({"rkhunter": RKHUNTER_UBUNTU, "chkrootkit": CHKROOTKIT_UBUNTU})
    result = mod.check(_profile())
    assert _codes(result) == ["known_false_alarms", "ran_clean"]
    note = result.findings[0]
    assert set(note.data["explained"]) == {
        "script_command", "properties_changed", "known_hidden", "network_tools",
        "shared_memory", "ssh_setting", "config_quirk", "ordinary_port", "never_logged"}
    assert "Debian and Ubuntu" in note.description
    assert "debsums" in note.description
    assert note.severity == Severity.INFO
    assert "Apart from the false alarms" in result.findings[1].description


def test_a_real_rootkit_sign_is_a_critical_lead(setup):
    mod, _ = setup({"rkhunter": RKHUNTER_ROOTKIT, "chkrootkit": ""})
    result = mod.check(_profile())
    crit = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert [f.data["warning"] for f in crit] == [
        "Found file '/usr/lib/libext-2.so.7'. Possible rootkit: Ebury - SSH Rootkit"]
    assert crit[0].code == CODE + "possible_rootkit"
    assert "lead, not a verdict" in crit[0].description
    assert "alert" in crit[0].description  # the monitoring safety note
    # A hidden file that isn't one packages leave is worth a look.
    [warn] = [f for f in result.findings if f.code == CODE + "scanner_warning"]
    assert warn.data["kind"] == "hidden_files"
    assert CODE + "ran_clean" not in [f.code for f in result.findings]


def test_chkrootkit_warnings_get_the_right_weight(setup):
    mod, _ = setup({"rkhunter": "", "chkrootkit": CHKROOTKIT_BAD})
    result = mod.check(_profile())
    by_kind = {f.data["kind"]: f for f in result.findings if "kind" in f.data}
    assert by_kind["rootkit_signs"].severity == Severity.CRITICAL
    assert "Showtee" in by_kind["rootkit_signs"].data["warning"]
    # Timing coincidences and programs in /tmp are leads, but not "rootkit!".
    assert by_kind["hidden_process_count"].severity == Severity.WARNING
    assert by_kind["program_in_tmp"].severity == Severity.WARNING
    assert by_kind["program_in_tmp"].data["details"] == ["/tmp/installer-x86_64"]
    # A raw socket held by something that isn't a network-setup program.
    assert by_kind["network_listener"].severity == Severity.WARNING
    # Criticals first.
    assert result.findings[0].severity == Severity.CRITICAL


@pytest.mark.parametrize("block,expected", [
    ({"tool": "chkrootkit", "text": "INFECTED PORTS: ( 465 31337)", "details": []}, ("critical", "bindshell")),
    ({"tool": "rkhunter", "text": "Suspicious file types found in /dev:",
      "details": ["/dev/.hid/x: ELF 64-bit"]}, ("warning", "unrecognised")),
    ({"tool": "rkhunter", "text": "Found preloaded shared library: /lib/libsnoopy.so", "details": []},
     ("critical", "rootkit_signs")),
    ({"tool": "rkhunter", "text": "Something new nobody has seen", "details": []}, ("warning", "unexplained")),
])
def test_classify(block, expected):
    kind, key = _code_module().classify(block)
    if expected[1] == "unrecognised":
        assert kind == "warning"
    else:
        assert (kind, key) == expected


def test_a_tool_anyone_can_change_is_never_run_as_root(setup):
    mod, runner = setup({"rkhunter": "", "chkrootkit": ""}, root_owned=False)
    result = mod.check(_profile())
    assert runner.calls == []
    assert {f.data["reason"] for f in result.findings} == {"unsafe_owner"}
    assert "Homebrew" in result.findings[0].description


def test_a_timeout_or_crash_is_reported_and_the_other_tool_still_counts(setup):
    mod, _ = setup({"rkhunter": lambda a: _result(a, timed_out=True),
                    "chkrootkit": lambda a: _result(a, 2, "", "chkrootkit: segfault")})
    result = mod.check(_profile())
    assert [(f.code.split(".")[-1], f.data["reason"]) for f in result.findings] == [
        ("could_not_check", "timed_out"), ("could_not_check", "tool_failed")]
    assert all("doesn't mean the computer is clean" in f.description for f in result.findings)


def test_on_a_mac_every_note_says_how_little_they_see(setup):
    mod, _ = setup({"rkhunter": "", "chkrootkit": ""})
    [f] = mod.check(_profile(Platform.DARWIN)).findings
    assert "sealed part of the disk" in f.description


@pytest.mark.skipif(sys.platform == "win32", reason="root ownership is a POSIX idea")
def test_owned_by_root_refuses_a_file_others_can_change(tmp_path):
    code = _code_module()
    exe = tmp_path / "tool"
    exe.write_text("x")
    assert code.owned_by_root(str(exe)) is False  # owned by the test user
    # A real file on both systems (Ubuntu's /bin is a link to /usr/bin, so /bin/sh is refused).
    assert code.owned_by_root("/usr/bin/env") is True


@pytest.mark.skipif(sys.platform != "darwin", reason="uses macOS's root-owned /etc -> private/etc link")
def test_owned_by_root_refuses_a_path_through_a_link_even_to_root_files():
    code = _code_module()
    # /private/etc/hosts is root's; /etc is a link to it, so the path is refused.
    assert code.owned_by_root("/private/etc/hosts") is True
    assert code.owned_by_root("/etc/hosts") is False
    # Relative or unnormalised paths are never trusted.
    assert code.owned_by_root("bin/sh") is False
    assert code.owned_by_root("/bin/../bin/sh") is False


def test_a_link_to_the_tool_is_refused(tmp_path):
    code = _code_module()
    link = tmp_path / "rkhunter"
    link.symlink_to("/bin/sh")
    assert code.owned_by_root(str(link)) is False


def test_the_tools_never_run_in_the_scans_own_folder(setup, tmp_path, monkeypatch):
    helpers = tmp_path / "lib" / "chkrootkit"
    helpers.mkdir(parents=True)
    (helpers / "chkproc").write_text("x")
    monkeypatch.setattr(_code_module(), "CHKROOTKIT_HELPER_DIRS", (str(helpers),))
    mod, runner = setup({"rkhunter": "", "chkrootkit": ""})
    mod.check(_profile())
    rk, chk = runner.calls
    assert rk["cwd"] == "/"
    assert chk["cwd"] == str(helpers)


def test_a_helper_folder_with_one_untrusted_helper_is_refused(setup, tmp_path, monkeypatch):
    helpers = tmp_path / "lib" / "chkrootkit"
    helpers.mkdir(parents=True)
    (helpers / "chkproc").write_text("x")
    (helpers / "ifpromisc").write_text("x")
    monkeypatch.setattr(_code_module(), "CHKROOTKIT_HELPER_DIRS", (str(helpers),))
    mod, runner = setup({"rkhunter": "", "chkrootkit": ""})
    # The folder and chkproc check out; ifpromisc (a link, someone else's file...) doesn't.
    mod.root_owned = lambda path: not path.endswith("ifpromisc")
    mod.check(_profile())
    assert [c["cwd"] for c in runner.calls] == ["/", "/"]


def test_chkrootkit_without_trusted_helpers_runs_in_root(setup):
    mod, runner = setup({"rkhunter": "", "chkrootkit": ""})
    mod.check(_profile())
    assert [c["cwd"] for c in runner.calls] == ["/", "/"]


def test_ownership_is_checked_again_right_before_running(setup):
    mod, runner = setup({"rkhunter": "", "chkrootkit": ""})
    seen = []
    # Trusted when picked, not any more when about to run (swapped in between).
    mod.root_owned = lambda path: (seen.append(path) or seen.count(path) < 2)
    result = mod.check(_profile())
    assert runner.calls == []
    assert {f.data["reason"] for f in result.findings} == {"unsafe_owner"}


def test_the_first_trusted_copy_is_the_one_that_runs(setup, tmp_path):
    mod, runner = setup({"rkhunter": "", "chkrootkit": ""}, tools=("rkhunter",))
    good = tmp_path / "good" / "rkhunter"
    good.parent.mkdir()
    good.write_text("#!/bin/sh\n")
    bad = mod.candidates["rkhunter"][0]
    mod.candidates = {"rkhunter": (bad, str(good)), "chkrootkit": ()}
    mod.root_owned = lambda path: not path.startswith(str(Path(bad).parent))
    mod.check(_profile())
    assert [c["args"][0] for c in runner.calls] == [str(good)]
