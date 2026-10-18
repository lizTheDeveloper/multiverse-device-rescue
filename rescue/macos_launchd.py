"""Is a macOS system daemon loaded? Read from ``launchctl print system/<label>``.

The sharing services (Screen Sharing ``com.apple.screensharing``, File Sharing
``com.apple.smbd``, Remote Login ``com.openssh.sshd``) are system daemons that
launchd loads only while the service is switched on. ``launchctl print
system/<label>`` answers without admin rights:

- loaded:     exit 0, output starts ``system/<label> = {``
- not loaded: exit 113, ``Could not find service "<label>" in domain for system``

A user's ``launchctl list`` shows the user's own domain and never lists these
daemons, and ``systemsetup -getremotelogin`` needs admin, so neither can tell
"on" from "couldn't read". This parser returns True / False / None (couldn't
tell). Modules run the command themselves, with a literal argument list, so
docs/commands.md and ``--trace`` show it.
"""

from __future__ import annotations

# Labels of the daemons behind each sharing switch.
SCREEN_SHARING = "com.apple.screensharing"
FILE_SHARING = "com.apple.smbd"
REMOTE_LOGIN = "com.openssh.sshd"


def parse_launchctl_print(label: str, returncode: int | None, stdout, stderr="") -> bool | None:
    """True if ``launchctl print system/<label>`` shows the daemon loaded,
    False if launchd says it has no such service, None otherwise."""
    out = stdout if isinstance(stdout, str) else ""
    err = stderr if isinstance(stderr, str) else ""
    if returncode == 0 and out.lstrip().startswith(f"system/{label} = {{"):
        return True
    if f'Could not find service "{label}"' in out + err:
        return False
    return None


def parse_result(label: str, result) -> bool | None:
    """``parse_launchctl_print`` for a ``subprocess.run`` result (None → None)."""
    if result is None:
        return None
    return parse_launchctl_print(
        label, getattr(result, "returncode", None),
        getattr(result, "stdout", ""), getattr(result, "stderr", ""),
    )
