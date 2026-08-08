"""Who can log in to this machine, and who can become root.

Three questions this answers that nothing else in the toolkit does on Linux:
which accounts can actually log in, which of them have administrative power,
and whether any of them can use that power without proving who they are.

A second UID 0 account is the classic backdoor — it is root, but it is not
called root, so it does not appear anywhere someone would think to look. A
NOPASSWD sudoers rule means a compromised session escalates to root with no
prompt at all. Neither is visible in any desktop settings panel.

Reading /etc/shadow requires root. When it cannot be read the module says so
rather than reporting "no empty passwords found", because those are very
different statements and only one of them is true.
"""

import os
import re
from pathlib import Path

from rescue.command import run
from rescue.fsbounds import is_dir_nofollow, is_file_nofollow
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

# Shells that mean "this account exists to own files, not to be logged into".
_NOLOGIN_SHELLS = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", ""}

# Groups whose members can escalate to root on mainstream distributions.
_ADMIN_GROUPS = ("sudo", "wheel", "admin", "root")

_NOPASSWD = re.compile(r"^\s*(?!#)(\S+)\s+.*NOPASSWD:", re.M)


class Module(ModuleBase):
    name = "linux_account_audit"
    category = "security"
    platforms = [Platform.LINUX]
    risk_level = RiskLevel.SAFE
    priority = 82
    depends_on = []
    estimated_duration = "10s"

    emits_codes = [
        "security.linux_account_audit.extra_uid0_account",
        "security.linux_account_audit.empty_password",
        "security.linux_account_audit.passwordless_sudo",
        "security.linux_account_audit.shadow_unreadable",
        "security.linux_account_audit.admin_inventory",
    ]

    passwd_path: str = "/etc/passwd"
    shadow_path: str = "/etc/shadow"
    group_path: str = "/etc/group"
    sudoers_path: str = "/etc/sudoers"
    sudoers_dir: str = "/etc/sudoers.d"

    def check(self, profile: SystemProfile) -> CheckResult:
        if profile.platform is not Platform.LINUX:
            return CheckResult(
                module_name=self.name,
                supported=False,
                unsupported_reason=(
                    "This check reads /etc/passwd, /etc/shadow and sudoers as laid out on "
                    f"Linux; this host reports {profile.platform.value}."
                ),
            )

        accounts = self._accounts()
        if accounts is None:
            return CheckResult(
                module_name=self.name,
                error=f"{self.passwd_path} could not be read, so no account audit is possible.",
            )

        findings: list[Finding] = []
        findings.extend(self._uid0_findings(accounts))
        findings.extend(self._password_findings(accounts))
        findings.extend(self._sudo_findings())
        findings.append(self._admin_inventory(accounts))
        return CheckResult(module_name=self.name, findings=findings)

    def _accounts(self) -> list[dict] | None:
        try:
            text = Path(self.passwd_path).read_text(errors="replace")
        except OSError:
            return None
        accounts = []
        for line in text.splitlines():
            fields = line.split(":")
            if len(fields) < 7:
                continue
            try:
                uid = int(fields[2])
            except ValueError:
                continue
            accounts.append({
                "name": fields[0],
                "uid": uid,
                "gid": fields[3],
                "home": fields[5],
                "shell": fields[6],
            })
        return accounts

    def _uid0_findings(self, accounts: list[dict]) -> list[Finding]:
        uid0 = [a for a in accounts if a["uid"] == 0 and a["name"] != "root"]
        return [
            Finding(
                title=f"Account '{account['name']}' has root privileges (UID 0)",
                description=(
                    f"'{account['name']}' shares UID 0 with root, which means it *is* root: "
                    "same powers, different name. A handful of appliance distributions ship "
                    "an alias like 'toor' deliberately, but on a normal system a second UID "
                    "0 account is how someone keeps access after you change the root "
                    "password.\n\n"
                    f"  shell: {account['shell']}\n"
                    f"  home:  {account['home']}"
                ),
                severity=Severity.CRITICAL,
                category=self.category,
                code="security.linux_account_audit.extra_uid0_account",
                confidence=0.85,
                data={"check": "extra_uid0_account", "account": account["name"], "shell": account["shell"]},
            )
            for account in uid0
        ]

    def _password_findings(self, accounts: list[dict]) -> list[Finding]:
        try:
            shadow = Path(self.shadow_path).read_text(errors="replace")
        except OSError:
            return [
                Finding(
                    title="Password status could not be checked",
                    description=(
                        f"{self.shadow_path} is readable only by root, so this run could not "
                        "check whether any account has an empty password. Re-run with sudo "
                        "for that answer. Treat this as 'not checked', not as 'nothing "
                        "wrong'."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.linux_account_audit.shadow_unreadable",
                    confidence=1.0,
                    data={"check": "shadow_unreadable"},
                )
            ]

        by_name = {a["name"]: a for a in accounts}
        findings = []
        for line in shadow.splitlines():
            fields = line.split(":")
            if len(fields) < 2 or fields[1] != "":
                continue
            name = fields[0]
            account = by_name.get(name, {})
            # A system account with no password *and* no login shell cannot be
            # logged into; reporting it would be noise.
            if account.get("shell", "") in _NOLOGIN_SHELLS:
                continue
            findings.append(
                Finding(
                    title=f"Account '{name}' has no password set",
                    description=(
                        f"'{name}' can be logged into with no credential at all, from the "
                        "console and — if SSH permits empty passwords — over the network. "
                        "Set a password or lock the account."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.linux_account_audit.empty_password",
                    confidence=0.9,
                    data={"check": "empty_password", "account": name},
                )
            )
        return findings

    def _sudo_findings(self) -> list[Finding]:
        texts: list[tuple[str, str]] = []
        if is_file_nofollow(self.sudoers_path):
            try:
                texts.append((self.sudoers_path, Path(self.sudoers_path).read_text(errors="replace")))
            except OSError:
                pass
        if is_dir_nofollow(self.sudoers_dir):
            try:
                for path in sorted(Path(self.sudoers_dir).iterdir()):
                    if is_file_nofollow(path):
                        texts.append((str(path), path.read_text(errors="replace")))
            except OSError:
                pass

        findings = []
        for path, text in texts:
            for match in _NOPASSWD.finditer(text):
                principal = match.group(1)
                findings.append(
                    Finding(
                        title=f"{principal} can run commands as root without a password",
                        description=(
                            f"{path} contains a NOPASSWD rule for {principal}.\n\n"
                            f"  {match.group(0).strip()[:200]}\n\n"
                            "This is convenient and it is also the difference between "
                            "'someone got into your user session' and 'someone got root'. "
                            "Automation on a server sometimes needs it; a desktop rarely "
                            "does. If it is needed, scope it to specific commands rather "
                            "than ALL."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.linux_account_audit.passwordless_sudo",
                        confidence=0.9,
                        data={
                            "check": "passwordless_sudo",
                            "principal": principal,
                            "path": path,
                            "rule": match.group(0).strip()[:200],
                        },
                    )
                )
        return findings

    def _admin_inventory(self, accounts: list[dict]) -> Finding:
        members: dict[str, list[str]] = {}
        try:
            for line in Path(self.group_path).read_text(errors="replace").splitlines():
                fields = line.split(":")
                if len(fields) < 4 or fields[0] not in _ADMIN_GROUPS:
                    continue
                names = [n for n in fields[3].split(",") if n]
                if names:
                    members[fields[0]] = names
        except OSError:
            pass

        loginable = sorted(
            a["name"] for a in accounts
            if a["shell"] not in _NOLOGIN_SHELLS and a["uid"] >= 1000 or a["uid"] == 0
        )

        lines = ["Accounts that can log in:", "  " + (", ".join(loginable) or "(none found)"), ""]
        if members:
            lines.append("Administrative group membership:")
            for group in sorted(members):
                lines.append(f"  {group}: {', '.join(sorted(members[group]))}")
        else:
            lines.append("No members listed in sudo/wheel/admin groups (or the file was unreadable).")

        return Finding(
            title=f"{len(loginable)} account(s) can log in to this machine",
            description=(
                "\n".join(lines)
                + "\n\nLook for a name you do not recognise. That is the whole point of "
                "this list; there is nothing wrong with any of these entries by default."
            ),
            severity=Severity.INFO,
            category=self.category,
            code="security.linux_account_audit.admin_inventory",
            confidence=1.0,
            data={"check": "admin_inventory", "accounts": loginable, "admin_groups": members},
        )

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions: list[Action] = []
        for finding in findings.findings:
            check = finding.data.get("check")
            account = finding.data.get("account", "")

            if check == "extra_uid0_account":
                actions.append(self._guidance(
                    f"Decide whether '{account}' should exist at all",
                    f"  1. See when it was created and what it owns:\n"
                    f"         sudo grep '^{account}:' /etc/passwd\n"
                    f"         sudo lastlog -u {account}\n"
                    f"         sudo find / -xdev -user {account} 2>/dev/null | head\n"
                    "  2. If you did not create it, lock it immediately (locking is "
                    "reversible; deleting destroys the evidence of how it got there):\n"
                    f"         sudo usermod -L -s /usr/sbin/nologin {account}\n"
                    "  3. Then assume whoever created it had root, and work through the "
                    "digital_security_reset profile: `rescue guide digital_security_reset`.",
                    check, account,
                ))
            elif check == "empty_password":
                actions.append(self._guidance(
                    f"Set or lock the password for '{account}'",
                    f"    sudo passwd {account}        # set one\n"
                    f"    sudo passwd -l {account}     # or lock the account\n\n"
                    "Then confirm:\n"
                    f"    sudo passwd -S {account}",
                    check, account,
                ))
            elif check == "passwordless_sudo":
                actions.append(self._guidance(
                    f"Review the passwordless sudo rule for {finding.data.get('principal')}",
                    f"    sudo visudo -f {finding.data.get('path')}\n\n"
                    "Use `visudo` rather than an editor directly — it validates the file "
                    "before saving, and a broken sudoers file can leave you unable to use "
                    "sudo at all. Narrow the rule to the specific commands that need it, "
                    "or remove it if nothing does.",
                    check, account,
                ))
            elif check == "shadow_unreadable":
                actions.append(self._guidance(
                    "Re-run this check as root to include password status",
                    "    sudo rescue run linux_account_audit --yes",
                    check, account,
                ))
        return FixResult(module_name=self.name, actions=actions)

    def _guidance(self, title: str, description: str, check: str, account: str) -> Action:
        return Action(
            title=title,
            description=description,
            risk_level=RiskLevel.SAFE,
            kind=ActionKind.GUIDANCE,
            data={"check": check, "account": account},
        )
