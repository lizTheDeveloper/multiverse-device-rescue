"""Read the effective SSH server configuration and flag the settings that turn
a laptop into an internet-facing login prompt.

SSH is the single most common way a Linux machine is taken over: an exposed
sshd with password authentication is guessed at continuously by automated
scanners, and root-with-password is the combination that ends with someone
else's shell on the box.

Two decisions shape this module:

*Effective config, not the file.* ``sshd -T`` prints the configuration sshd
actually resolved, including Include directives, Match blocks and distro
defaults. Reading ``/etc/ssh/sshd_config`` by hand gets the answer wrong on
every modern distro that ships ``Include /etc/ssh/sshd_config.d/*.conf``. The
file is only parsed as a fallback when ``sshd -T`` cannot run (typically
because the check is not root), and a finding derived that way carries lower
confidence and says so.

*Exposure changes severity, not just the finding.* Password authentication on a
host that is not listening for SSH at all is a latent misconfiguration. The same
setting on a host with sshd running and listening on every interface is an open
door. The module checks whether sshd is actually running before deciding how
loudly to complain.
"""

from pathlib import Path

from rescue.command import run
from rescue.fsbounds import is_file_nofollow
from rescue.models import (
    Action,
    ActionKind,
    CheckResult,
    Finding,
    FixResult,
    Mode,
    Platform,
    RiskLevel,
    Severity,
    SystemProfile,
)
from rescue.module_base import ModuleBase

_TIMEOUT = 10.0

# Values of PermitRootLogin that still allow a root session of some kind. Only
# "no" fully closes it; "prohibit-password"/"without-password" allow key-based
# root login, which is a deliberate choice on servers and worth surfacing but
# not worth alarming about.
_ROOT_LOGIN_OPEN = {"yes"}
_ROOT_LOGIN_KEYS_ONLY = {"prohibit-password", "without-password", "forced-commands-only"}


class Module(ModuleBase):
    name = "linux_ssh_hardening"
    category = "security"
    platforms = [Platform.LINUX]
    risk_level = RiskLevel.SAFE
    priority = 84
    depends_on = []
    estimated_duration = "10s"

    emits_codes = [
        "security.linux_ssh_hardening.root_login_permitted",
        "security.linux_ssh_hardening.password_auth_enabled",
        "security.linux_ssh_hardening.empty_passwords_permitted",
        "security.linux_ssh_hardening.listening_on_all_interfaces",
        "security.linux_ssh_hardening.config_unreadable",
    ]

    # Overridable so tests can point at a fixture file instead of the real host.
    sshd_config_path: str = "/etc/ssh/sshd_config"

    def check(self, profile: SystemProfile) -> CheckResult:
        if profile.platform is not Platform.LINUX:
            return CheckResult(
                module_name=self.name,
                supported=False,
                unsupported_reason=(
                    "This check reads OpenSSH server configuration as it is laid out on "
                    f"Linux; this host reports {profile.platform.value}."
                ),
            )

        config, source = self._effective_config()
        if config is None:
            if not is_file_nofollow(self.sshd_config_path):
                # No sshd config at all: no SSH server installed. Nothing to
                # harden, and saying so is more useful than silence.
                return CheckResult(module_name=self.name, findings=[])
            return CheckResult(
                module_name=self.name,
                findings=[
                    Finding(
                        title="SSH server configuration could not be read",
                        description=(
                            "An sshd configuration exists but neither `sshd -T` nor the "
                            "config file could be read, so the server's real settings are "
                            "unknown. Re-run with sudo for a definite answer."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        code="security.linux_ssh_hardening.config_unreadable",
                        confidence=0.5,
                        data={"check": "config_unreadable"},
                    )
                ],
            )

        running = self._sshd_running()
        confidence = 0.95 if source == "sshd -T" else 0.7
        findings: list[Finding] = []

        root_login = config.get("permitrootlogin", "")
        if root_login in _ROOT_LOGIN_OPEN:
            findings.append(
                Finding(
                    title="Root can log in over SSH",
                    description=(
                        "PermitRootLogin is 'yes', so the root account can be logged into "
                        "directly over the network — including with a password if password "
                        "authentication is on. Automated scanners try exactly this "
                        "combination, continuously, on every machine reachable from the "
                        "internet."
                        + (" sshd is running right now." if running else
                           " sshd does not appear to be running, so this is latent rather"
                           " than currently exposed.")
                    ),
                    severity=Severity.CRITICAL if running else Severity.WARNING,
                    category=self.category,
                    code="security.linux_ssh_hardening.root_login_permitted",
                    confidence=confidence,
                    data={"check": "root_login_permitted", "value": root_login, "sshd_running": running, "source": source},
                )
            )
        elif root_login in _ROOT_LOGIN_KEYS_ONLY:
            findings.append(
                Finding(
                    title=f"Root SSH login is allowed with a key (PermitRootLogin {root_login})",
                    description=(
                        "Key-only root login is a normal server configuration and is far "
                        "safer than password root login. It is listed here so you know it "
                        "is on; on a personal machine you probably want 'no'."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.linux_ssh_hardening.root_login_permitted",
                    confidence=confidence,
                    data={"check": "root_login_keys_only", "value": root_login, "source": source},
                )
            )

        if config.get("passwordauthentication") == "yes" or config.get("kbdinteractiveauthentication") == "yes":
            findings.append(
                Finding(
                    title="SSH accepts password authentication",
                    description=(
                        "Anyone who can reach this machine's SSH port can attempt to guess "
                        "a password, indefinitely. Key-based authentication removes that "
                        "entire class of attack."
                        + (" sshd is running right now." if running else
                           " sshd does not appear to be running.")
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.linux_ssh_hardening.password_auth_enabled",
                    confidence=confidence,
                    data={"check": "password_auth_enabled", "sshd_running": running, "source": source},
                )
            )

        if config.get("permitemptypasswords") == "yes":
            findings.append(
                Finding(
                    title="SSH permits accounts with empty passwords",
                    description=(
                        "PermitEmptyPasswords is 'yes'. Any account on this machine with no "
                        "password set can be logged into over the network with no "
                        "credential at all. There is no configuration in which this is the "
                        "intended outcome on a personal machine."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.linux_ssh_hardening.empty_passwords_permitted",
                    confidence=confidence,
                    data={"check": "empty_passwords_permitted", "source": source},
                )
            )

        listen = config.get("listenaddress", "")
        if running and listen in ("0.0.0.0", "::", "0.0.0.0 ::", ""):
            findings.append(
                Finding(
                    title="SSH is listening on every network interface",
                    description=(
                        "sshd is bound to all interfaces, so it answers on whatever network "
                        "this machine joins next — hotel wifi, a conference network, a "
                        "cafe. If you only use SSH on a home LAN, bind it to that interface "
                        "or restrict it in the firewall."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.linux_ssh_hardening.listening_on_all_interfaces",
                    confidence=0.7,
                    data={"check": "listening_on_all_interfaces", "source": source},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def _effective_config(self) -> tuple[dict[str, str] | None, str]:
        """Return sshd's resolved settings, preferring `sshd -T` over the file."""
        result = run(["sshd", "-T"], timeout=_TIMEOUT)
        if result.error is None and result.returncode == 0 and result.stdout.strip():
            return self._parse(result.stdout), "sshd -T"

        try:
            text = Path(self.sshd_config_path).read_text(errors="replace")
        except OSError:
            return None, ""
        return self._parse(text), self.sshd_config_path

    @staticmethod
    def _parse(text: str) -> dict[str, str]:
        """Parse `keyword value` lines; last occurrence wins, as sshd -T emits.

        For a hand-written config file sshd actually honours the *first*
        occurrence, but a file with the same keyword twice is already a
        configuration the operator should look at, and preferring the last line
        errs toward reporting the more permissive value rather than missing it.
        """
        config: dict[str, str] = {}
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            config[parts[0].lower()] = parts[1].strip().lower()
        return config

    def _sshd_running(self) -> bool:
        result = run(["systemctl", "is-active", "sshd"], timeout=_TIMEOUT)
        if result.error is None and result.stdout.strip() == "active":
            return True
        # Debian and Ubuntu name the unit `ssh`, not `sshd`.
        result = run(["systemctl", "is-active", "ssh"], timeout=_TIMEOUT)
        return result.error is None and result.stdout.strip() == "active"

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions: list[Action] = []
        seen: set[str] = set()
        for finding in findings.findings:
            check = finding.data.get("check")
            if check in seen:
                continue
            seen.add(check)

            if check == "root_login_permitted":
                actions.append(self._guidance(
                    "Stop root logging in over SSH",
                    "Add to /etc/ssh/sshd_config.d/99-hardening.conf (create it):\n"
                    "    PermitRootLogin no\n\n"
                    "Then reload:\n"
                    "    sudo sshd -t && sudo systemctl reload ssh || sudo systemctl reload sshd\n\n"
                    "`sshd -t` checks the config before you reload it. Keep your current "
                    "SSH session open and test a new login in a second terminal before "
                    "closing it — a bad SSH config is the classic way to lock yourself "
                    "out of a remote machine.",
                    check,
                ))
            elif check == "password_auth_enabled":
                actions.append(self._guidance(
                    "Switch SSH to key-based authentication",
                    "  1. From the machine you connect *from*:\n"
                    "         ssh-keygen -t ed25519\n"
                    "         ssh-copy-id you@this-machine\n"
                    "  2. Confirm you can log in with the key, in a new terminal.\n"
                    "  3. Only then, in /etc/ssh/sshd_config.d/99-hardening.conf:\n"
                    "         PasswordAuthentication no\n"
                    "         KbdInteractiveAuthentication no\n"
                    "  4. sudo sshd -t && sudo systemctl reload ssh\n\n"
                    "Do step 2 before step 3. Reversing them locks you out.",
                    check,
                ))
            elif check == "empty_passwords_permitted":
                actions.append(self._guidance(
                    "Refuse empty-password SSH logins immediately",
                    "In /etc/ssh/sshd_config.d/99-hardening.conf:\n"
                    "    PermitEmptyPasswords no\n"
                    "    sudo sshd -t && sudo systemctl reload ssh\n\n"
                    "Then check for accounts that actually have no password:\n"
                    "    sudo awk -F: '($2 == \"\") {print $1}' /etc/shadow",
                    check,
                ))
            elif check == "listening_on_all_interfaces":
                actions.append(self._guidance(
                    "Limit which networks can reach SSH",
                    "Either bind sshd to one interface in "
                    "/etc/ssh/sshd_config.d/99-hardening.conf:\n"
                    "    ListenAddress 192.168.1.10\n\n"
                    "or leave it bound and restrict it at the firewall:\n"
                    "    sudo ufw allow from 192.168.1.0/24 to any port 22\n\n"
                    "If you never use SSH into this machine, the simplest fix is to turn "
                    "the server off entirely:\n"
                    "    sudo systemctl disable --now ssh",
                    check,
                ))
            elif check == "config_unreadable":
                actions.append(self._guidance(
                    "Re-run this check as root",
                    "    sudo rescue run linux_ssh_hardening --yes",
                    check,
                ))
        return FixResult(module_name=self.name, actions=actions)

    def _guidance(self, title: str, description: str, check: str) -> Action:
        return Action(
            title=title,
            description=description,
            risk_level=RiskLevel.SAFE,
            kind=ActionKind.GUIDANCE,
            data={"check": check},
        )
