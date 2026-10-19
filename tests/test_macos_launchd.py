"""parse_launchctl_print: real `launchctl print system/<label>` output, macOS 26.3.1."""

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.macos_launchd import parse_launchctl_print, parse_result


LOADED = "system/com.apple.timed = {\n\tactive count = 4\n\tpath = /System/Library/LaunchDaemons/com.apple.timed.plist\n"
MISSING = 'Bad request.\nCould not find service "com.openssh.sshd" in domain for system\n'


def test_loaded_daemon_is_on():
    assert parse_launchctl_print("com.apple.timed", 0, LOADED) is True


def test_unknown_service_is_off():
    assert parse_launchctl_print("com.openssh.sshd", 113, MISSING) is False
    # some versions print it on stderr
    assert parse_launchctl_print("com.openssh.sshd", 113, "", MISSING) is False


def test_anything_else_is_unknown():
    assert parse_launchctl_print("com.openssh.sshd", 1, "") is None
    assert parse_launchctl_print("com.openssh.sshd", 0, "something new") is None
    assert parse_result("com.openssh.sshd", None) is None


def test_other_label_in_output_does_not_count():
    assert parse_launchctl_print("com.apple.screensharing", 0, LOADED) is None


def test_parse_result_reads_subprocess_result():
    result = SimpleNamespace(returncode=113, stdout=MISSING, stderr="")
    assert parse_result("com.openssh.sshd", result) is False
