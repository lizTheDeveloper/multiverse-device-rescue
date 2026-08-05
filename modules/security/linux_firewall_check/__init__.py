"""Is anything actually filtering inbound traffic on this Linux machine?

Linux ships four common front-ends over two kernel backends — ufw and firewalld
are wrappers, nftables and iptables are the thing being wrapped — and a machine
can have all four installed while none of them is filtering. Checking only one
of them produces a confident, wrong answer, so this module asks each in turn and
reports what it could and could not determine.

It is deliberately conservative about claiming a machine is unprotected. An
unreadable ruleset (no privileges) is reported as "could not determine", not as
"no firewall": a rescue tool that tells someone their firewall is off when it is
merely unreadable teaches them to distrust the tool.
"""

from rescue.command import run
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


class Module(ModuleBase):
    name = "linux_firewall_check"
    category = "security"
    platforms = [Platform.LINUX]
    risk_level = RiskLevel.SAFE
    priority = 85
    depends_on = []
    estimated_duration = "10s"

    emits_codes = [
        "security.linux_firewall_check.no_firewall",
        "security.linux_firewall_check.firewall_inactive",
        "security.linux_firewall_check.default_allow_inbound",
        "security.linux_firewall_check.undetermined",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        if profile.platform is not Platform.LINUX:
            return CheckResult(
                module_name=self.name,
                supported=False,
                unsupported_reason=(
                    "This check reads Linux firewall front-ends (ufw, firewalld, "
                    f"nftables, iptables); this host reports {profile.platform.value}."
                ),
            )

        states = [self._ufw(), self._firewalld(), self._nftables(), self._iptables()]
        present = [s for s in states if s["installed"]]
        active = [s for s in present if s["active"] is True]
        unknown = [s for s in present if s["active"] is None]

        findings: list[Finding] = []

        if not present:
            findings.append(
                Finding(
                    title="No firewall front-end is installed",
                    description=(
                        "None of ufw, firewalld, nft, or iptables could be found on this "
                        "system. On a laptop or desktop that usually means nothing is "
                        "filtering inbound connections, so any service you start is "
                        "reachable by anything on the same network — a cafe wifi, a "
                        "hotel network, a shared office LAN."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.linux_firewall_check.no_firewall",
                    confidence=0.8,
                    data={"check": "no_firewall"},
                )
            )
        elif not active and not unknown:
            names = ", ".join(s["tool"] for s in present)
            findings.append(
                Finding(
                    title="A firewall is installed but not active",
                    description=(
                        f"Found {names}, but none of them is currently filtering. "
                        "Installed and running are different things; an inactive "
                        "firewall protects nothing."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.linux_firewall_check.firewall_inactive",
                    confidence=0.85,
                    data={"check": "firewall_inactive", "tools": [s["tool"] for s in present]},
                )
            )
        elif not active and unknown:
            names = ", ".join(s["tool"] for s in unknown)
            findings.append(
                Finding(
                    title="Firewall state could not be determined",
                    description=(
                        f"{names} is installed, but its ruleset could not be read — "
                        "this usually means the check needs root. Re-run with sudo to "
                        "get a definite answer. This is not evidence that the firewall "
                        "is off."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.linux_firewall_check.undetermined",
                    confidence=0.5,
                    data={"check": "undetermined", "tools": [s["tool"] for s in unknown]},
                )
            )

        for state in active:
            if state.get("default_allow_inbound"):
                findings.append(
                    Finding(
                        title=f"{state['tool']} is active but allows inbound by default",
                        description=(
                            "The firewall is running, but its default policy for incoming "
                            "traffic is ACCEPT. Unless every port is covered by a specific "
                            "deny rule, that is close to having no inbound filtering."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.linux_firewall_check.default_allow_inbound",
                        confidence=0.75,
                        data={"check": "default_allow_inbound", "tool": state["tool"]},
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def _ufw(self) -> dict:
        result = run(["ufw", "status", "verbose"], timeout=_TIMEOUT)
        if result.error is not None:
            return {"tool": "ufw", "installed": False, "active": None}
        text = result.stdout.lower()
        if result.returncode != 0 or not text.strip():
            # ufw exits non-zero for a non-root caller: installed, unreadable.
            return {"tool": "ufw", "installed": True, "active": None}
        active = "status: active" in text
        return {
            "tool": "ufw",
            "installed": True,
            "active": active,
            "default_allow_inbound": "default: allow (incoming)" in text,
        }

    def _firewalld(self) -> dict:
        result = run(["firewall-cmd", "--state"], timeout=_TIMEOUT)
        if result.error is not None:
            return {"tool": "firewalld", "installed": False, "active": None}
        return {
            "tool": "firewalld",
            "installed": True,
            "active": "running" in result.stdout.lower(),
        }

    def _nftables(self) -> dict:
        result = run(["nft", "list", "ruleset"], timeout=_TIMEOUT)
        if result.error is not None:
            return {"tool": "nftables", "installed": False, "active": None}
        if result.returncode != 0:
            return {"tool": "nftables", "installed": True, "active": None}
        text = result.stdout
        # An empty ruleset is nftables installed and filtering nothing.
        has_input_chain = "hook input" in text
        return {
            "tool": "nftables",
            "installed": True,
            "active": has_input_chain,
            "default_allow_inbound": has_input_chain and "policy accept" in text,
        }

    def _iptables(self) -> dict:
        result = run(["iptables", "-S", "INPUT"], timeout=_TIMEOUT)
        if result.error is not None:
            return {"tool": "iptables", "installed": False, "active": None}
        if result.returncode != 0:
            return {"tool": "iptables", "installed": True, "active": None}
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        rules = [line for line in lines if line.startswith("-A")]
        policy_accept = any(line.startswith("-P INPUT ACCEPT") for line in lines)
        return {
            "tool": "iptables",
            "installed": True,
            # Policy plus no rules is the kernel default, i.e. not filtering.
            "active": bool(rules) or not policy_accept,
            "default_allow_inbound": policy_accept and not rules,
        }

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions: list[Action] = []
        for finding in findings.findings:
            check = finding.data.get("check")

            if check in ("no_firewall", "firewall_inactive"):
                actions.append(
                    Action(
                        title="Turn on an inbound firewall",
                        description=(
                            "On Debian/Ubuntu:\n"
                            "    sudo apt install ufw\n"
                            "    sudo ufw default deny incoming\n"
                            "    sudo ufw default allow outgoing\n"
                            "    sudo ufw enable\n\n"
                            "On Fedora/RHEL/openSUSE:\n"
                            "    sudo systemctl enable --now firewalld\n"
                            "    sudo firewall-cmd --set-default-zone=public\n\n"
                            "Before enabling on a machine you reach over SSH, allow SSH "
                            "first (`sudo ufw allow OpenSSH`) or you will lock yourself "
                            "out of it."
                        ),
                        risk_level=RiskLevel.SAFE,
                        kind=ActionKind.GUIDANCE,
                        data={"check": check},
                    )
                )
            elif check == "default_allow_inbound":
                actions.append(
                    Action(
                        title=f"Change the default inbound policy for {finding.data.get('tool')}",
                        description=(
                            "With ufw:\n"
                            "    sudo ufw default deny incoming\n"
                            "    sudo ufw reload\n\n"
                            "With plain nftables or iptables, set the input chain policy "
                            "to drop and add explicit allow rules for the services you "
                            "actually want reachable. Again: allow SSH before you do this "
                            "on a remote machine."
                        ),
                        risk_level=RiskLevel.SAFE,
                        kind=ActionKind.GUIDANCE,
                        data={"check": check},
                    )
                )
            elif check == "undetermined":
                actions.append(
                    Action(
                        title="Re-run this check with enough privilege to read the ruleset",
                        description=(
                            "    sudo rescue run linux_firewall_check --yes\n\n"
                            "Until then, treat the firewall state as unknown rather than "
                            "as either on or off."
                        ),
                        risk_level=RiskLevel.SAFE,
                        kind=ActionKind.GUIDANCE,
                        data={"check": check},
                    )
                )
        return FixResult(module_name=self.name, actions=actions)
