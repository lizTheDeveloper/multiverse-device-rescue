import subprocess
import os
import stat
from pathlib import Path
from shlex import quote

from rescue.models import (
    Action,
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


class Module(ModuleBase):
    name = "ssh_key_audit"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    emits_codes = [
        "security.ssh_key_audit.dsa_key_found",
        "security.ssh_key_audit.weak_rsa_key",
        "security.ssh_key_audit.ed25519_keys",
        "security.ssh_key_audit.rsa_keys",
        "security.ssh_key_audit.bad_ssh_dir_perms",
        "security.ssh_key_audit.bad_key_perms",
        "security.ssh_key_audit.authorized_keys",
        "security.ssh_key_audit.ssh_agent_running",
        "security.ssh_key_audit.ssh_agent_not_running",
        "security.ssh_key_audit.permit_root_login",
        "security.ssh_key_audit.password_auth_enabled",
        "security.ssh_key_audit.known_hosts",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Scan for SSH keys and check their properties
        key_findings = self._check_ssh_keys()
        findings.extend(key_findings)

        # Check file permissions
        perm_findings = self._check_permissions()
        findings.extend(perm_findings)

        # Check authorized_keys
        auth_findings = self._check_authorized_keys()
        findings.extend(auth_findings)

        # Check SSH agent status
        agent_findings = self._check_ssh_agent()
        findings.extend(agent_findings)

        # Check sshd_config for dangerous settings
        sshd_findings = self._check_sshd_config()
        findings.extend(sshd_findings)

        # Check known_hosts
        known_findings = self._check_known_hosts()
        findings.extend(known_findings)

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Provide informational guidance for fixing SSH key issues."""
        actions = []

        for finding in findings.findings:
            check_type = finding.data.get("check")

            if check_type == "dsa_key_found":
                actions.append(
                    Action(
                        title="Regenerate DSA keys",
                        description=(
                            f"DSA key found: {finding.data.get('key_file')}. "
                            "DSA encryption is cryptographically broken. "
                            "Regenerate with: ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ''"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "weak_rsa_key":
                actions.append(
                    Action(
                        title="Regenerate weak RSA key",
                        description=(
                            f"Weak RSA key found: {finding.data.get('key_file')} "
                            f"({finding.data.get('key_bits')} bits). "
                            "RSA keys should be at least 2048 bits. "
                            "Regenerate with: ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ''"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "bad_ssh_dir_perms":
                actions.append(
                    Action(
                        title="Fix ~/.ssh directory permissions",
                        description=(
                            f"~/.ssh directory has incorrect permissions "
                            f"({finding.data.get('current_perms')}). "
                            "Should be 700 (rwx------). "
                            "Fix with: chmod 700 ~/.ssh"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "bad_key_perms":
                actions.append(
                    Action(
                        title="Fix private key file permissions",
                        description=(
                            f"Private key {finding.data.get('key_file')} has incorrect permissions "
                            f"({finding.data.get('current_perms')}). "
                            "Should be 600 (rw-------). "
                            f"Fix with: chmod 600 {quote(str(finding.data.get('key_file')))}"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "permit_root_login":
                actions.append(
                    Action(
                        title="Disable PermitRootLogin",
                        description=(
                            "sshd_config has PermitRootLogin enabled. "
                            "This allows direct root SSH login, a security risk. "
                            "Edit /etc/ssh/sshd_config: set 'PermitRootLogin no' and run 'sudo sshd -t' to verify syntax, "
                            "then 'sudo launchctl restart com.openssh.sshd'"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "password_auth_enabled":
                actions.append(
                    Action(
                        title="Disable password authentication",
                        description=(
                            "sshd_config has PasswordAuthentication enabled. "
                            "Use key-based authentication instead. "
                            "Edit /etc/ssh/sshd_config: set 'PasswordAuthentication no' and run 'sudo sshd -t' to verify syntax, "
                            "then 'sudo launchctl restart com.openssh.sshd'"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            else:
                # INFO findings - just acknowledge them
                actions.append(
                    Action(
                        title=f"SSH key inventory: {finding.title}",
                        description=finding.description,
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_ssh_keys(self) -> list[Finding]:
        """Scan ~/.ssh/ for key files and check their types/sizes."""
        findings = []
        ssh_dir = Path.home() / ".ssh"

        if not ssh_dir.exists():
            return findings

        key_files = []
        dsa_keys = []
        weak_rsa_keys = []
        ed25519_keys = []
        rsa_keys = []

        try:
            for key_file in ssh_dir.iterdir():
                # Skip public keys and known_hosts
                if key_file.is_file() and not key_file.name.endswith(".pub"):
                    if key_file.name not in ["known_hosts", "authorized_keys", "config"]:
                        key_files.append(key_file)

                        # Check key type and size
                        key_info = self._get_key_info(key_file)
                        if key_info:
                            key_type = key_info.get("type", "unknown")
                            key_bits = key_info.get("bits", 0)

                            if key_type == "DSA":
                                dsa_keys.append(key_file.name)
                            elif key_type == "RSA" and key_bits < 2048:
                                weak_rsa_keys.append((key_file.name, key_bits))
                            elif key_type == "ED25519":
                                ed25519_keys.append(key_file.name)
                            elif key_type == "RSA":
                                rsa_keys.append(key_file.name)
        except OSError:
            pass

        # Flag CRITICAL for DSA keys
        for key_name in dsa_keys:
            findings.append(
                Finding(
                    title=f"Your SSH key {key_name} uses an outdated, broken format",
                    description=(
                        f"We found an SSH key named {key_name} that uses a format called "
                        "DSA. This type of key is no longer considered secure because "
                        "it can be easily broken by modern computers.\n\n"
                        "What to do: Create a new, stronger key to replace it. Open Terminal "
                        "and type: ssh-keygen -t ed25519. Follow the prompts to save "
                        f"it. Then, you can move the old {key_name} file into a folder "
                        "of your own to keep it safe, or delete it if you are sure you "
                        "no longer need it."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.ssh_key_audit.dsa_key_found",
                    data={"check": "dsa_key_found", "key_file": key_name},
                )
            )

        # Flag WARNING for weak RSA keys
        for key_name, bits in weak_rsa_keys:
            findings.append(
                Finding(
                    title=f"Your SSH key {key_name} is too short to be secure",
                    description=(
                        f"We found an SSH key named {key_name} that is {bits} bits long. "
                        "For a key to be considered secure today, it needs to be at least "
                        "2048 bits long. A shorter key is easier for attackers to guess, "
                        "which could let them access your computer or accounts if they "
                        "have the right tools.\n\n"
                        "What to do: Create a new, stronger key to replace it. Open Terminal "
                        "and type: ssh-keygen -t ed25519. Follow the prompts to save "
                        f"it. Then, you can move the old {key_name} file into a folder "
                        "of your own to keep it safe, or delete it if you are sure you "
                        "no longer need it."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.ssh_key_audit.weak_rsa_key",
                    data={"check": "weak_rsa_key", "key_file": key_name, "key_bits": bits},
                )
            )

        # Flag INFO for key inventory
        if ed25519_keys:
            findings.append(
                Finding(
                    title=f"Modern SSH keys: {len(ed25519_keys)}",
                    description=(
                        f"You have {len(ed25519_keys)} Ed25519 SSH key(s): {', '.join(ed25519_keys)}. "
                        f"Ed25519 keys are modern and recommended."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.ssh_key_audit.ed25519_keys",
                    data={"check": "ed25519_keys", "keys": ed25519_keys},
                )
            )

        if rsa_keys:
            findings.append(
                Finding(
                    title=f"Standard SSH keys: {len(rsa_keys)}",
                    description=(
                        f"You have {len(rsa_keys)} strong RSA SSH key(s): {', '.join(rsa_keys)}. "
                        f"RSA keys with 2048+ bits are acceptable."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.ssh_key_audit.rsa_keys",
                    data={"check": "rsa_keys", "keys": rsa_keys},
                )
            )

        return findings

    def _get_key_info(self, key_file: Path) -> dict:
        """Get key type and size using ssh-keygen."""
        try:
            result = subprocess.run(
                ["ssh-keygen", "-l", "-f", str(key_file)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Format: 2048 SHA256:xxx (RSA)
                parts = result.stdout.strip().split()
                if len(parts) >= 2:
                    bits = int(parts[0])
                    key_type = parts[-1].strip("()")
                    return {"bits": bits, "type": key_type}
        except (OSError, ValueError, subprocess.TimeoutExpired):
            pass
        return {}

    def _check_permissions(self) -> list[Finding]:
        """Check ~/.ssh/ directory and key file permissions."""
        findings = []
        ssh_dir = Path.home() / ".ssh"

        if not ssh_dir.exists():
            return findings

        try:
            # Check ~/.ssh directory permissions (should be 700)
            ssh_stat = ssh_dir.stat()
            ssh_mode = stat.S_IMODE(ssh_stat.st_mode)
            ssh_perms = format(ssh_mode, "03o")
            # Only group/other access matters; owner bits are the user's own.
            if ssh_mode & 0o077:
                findings.append(
                    Finding(
                        title="Your SSH folder is open to other users on your Mac",
                        description=(
                            "Your SSH folder (where your secure keys live) has permissions "
                            f"set to {ssh_perms}. This means other people or programs "
                            "on your Mac might be able to see or copy your private keys. "
                            "Private keys are like master keys to your digital identity, "
                            "so they should only be visible to you.\n\n"
                            "What to do: Open Terminal and type: chmod 700 ~/.ssh. This "
                            "locks the folder so only you can access it. You do not need "
                            "to delete anything."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.ssh_key_audit.bad_ssh_dir_perms",
                        data={"check": "bad_ssh_dir_perms", "current_perms": ssh_perms},
                    )
                )

            # Check private key permissions
            for key_file in ssh_dir.iterdir():
                if key_file.is_file() and not key_file.name.endswith(".pub"):
                    if key_file.name not in ["known_hosts", "authorized_keys", "config"]:
                        if not self._looks_like_private_key(key_file):
                            continue
                        key_stat = key_file.stat()
                        key_mode = stat.S_IMODE(key_stat.st_mode)
                        key_perms = format(key_mode, "03o")
                        # Owner read-only (400) is fine; flag group/other access only.
                        if key_mode & 0o077:
                            findings.append(
                                Finding(
                                    title=(
                                        f"Your private key {key_file.name} is open to other users"
                                    ),
                                    description=(
                                        f"Your private key file {key_file.name} has permissions "
                                        f"set to {key_perms}. This means other people "
                                        "or programs on your Mac might be able to read "
                                        "your private key. A private key is a secret "
                                        "code that proves your identity, so it should "
                                        "only be readable by you.\n\n"
                                        "What to do: Open Terminal and type: chmod 600 "
                                        f"~/.ssh/{quote(key_file.name)}. This locks the file "
                                        "so only you can read it. You do not need to "
                                        "delete anything."
                                    ),
                                    severity=Severity.WARNING,
                                    category=self.category,
                                    code="security.ssh_key_audit.bad_key_perms",
                                    data={
                                        "check": "bad_key_perms",
                                        "key_file": key_file.name,
                                        "current_perms": key_perms,
                                    },
                                )
                            )
        except OSError:
            pass

        return findings

    def _looks_like_private_key(self, key_file: Path) -> bool:
        """True if the file is a private key (not a backup config, log, etc.)."""
        try:
            with key_file.open("rb") as fh:
                head = fh.read(256)
            if b"PRIVATE KEY" in head:
                return True
        except (OSError, TypeError):
            pass
        return bool(self._get_key_info(key_file))

    def _check_authorized_keys(self) -> list[Finding]:
        """Check authorized_keys for entries."""
        findings = []
        auth_keys = Path.home() / ".ssh" / "authorized_keys"

        if not auth_keys.exists():
            return findings

        try:
            with open(auth_keys, "r") as f:
                lines = [l.strip() for l in f.readlines() if l.strip() and not l.startswith("#")]

            if lines:
                findings.append(
                    Finding(
                        title=f"Remote access keys: {len(lines)}",
                        description=(
                            f"You have {len(lines)} authorized key(s) in authorized_keys. "
                            f"These allow remote systems to authenticate to your account. "
                            f"Review to ensure all entries are from trusted systems."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        code="security.ssh_key_audit.authorized_keys",
                        data={"check": "authorized_keys", "count": len(lines)},
                    )
                )
        except OSError:
            pass

        return findings

    def _check_ssh_agent(self) -> list[Finding]:
        """Check if SSH agent is running and how many keys are loaded."""
        findings = []

        try:
            result = subprocess.run(
                ["ssh-add", "-l"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0:
                # Count non-empty lines (each line is a loaded key)
                lines = [l for l in result.stdout.strip().split("\n") if l.strip()]
                key_count = len(lines)
                findings.append(
                    Finding(
                        title=f"SSH helper is active ({key_count} keys)",
                        description=(
                            f"SSH agent is active with {key_count} key(s) loaded. "
                            f"This allows applications to use your SSH keys without passwords."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        code="security.ssh_key_audit.ssh_agent_running",
                        data={"check": "ssh_agent_running", "key_count": key_count},
                    )
                )
            elif "Could not open a connection to your authentication agent" in result.stderr:
                findings.append(
                    Finding(
                        title="SSH agent is not running",
                        description=(
                            "SSH agent is not running. You can start it with: eval $(ssh-agent -s)"
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        code="security.ssh_key_audit.ssh_agent_not_running",
                        data={"check": "ssh_agent_not_running"},
                    )
                )
        except (OSError, subprocess.TimeoutExpired):
            pass

        return findings

    def _check_sshd_config(self) -> list[Finding]:
        """Check sshd_config for dangerous settings."""
        findings = []
        sshd_config = Path("/etc/ssh/sshd_config")

        if not sshd_config.exists():
            return findings

        try:
            with open(sshd_config, "r") as f:
                lines = f.readlines()

            permit_root = False
            password_auth = False

            for line in lines:
                line = line.strip()
                if line.startswith("#"):
                    continue

                if line.lower().startswith("permitrootlogin"):
                    if "yes" in line.lower() and "no" not in line.lower():
                        permit_root = True

                if line.lower().startswith("passwordauthentication"):
                    if "yes" in line.lower() and "no" not in line.lower():
                        password_auth = True

            if permit_root:
                findings.append(
                    Finding(
                        title="Your Mac allows direct login as the main administrator",
                        description=(
                            "Your Mac is set up to allow people to log in directly as "
                            "'root' (the main administrator account) over a secure network "
                            "connection. This is risky because if an attacker guesses "
                            "the password, they get full control of your computer. Most "
                            "people do not use this feature, so it is likely a leftover "
                            "setting.\n\n"
                            "What to do: Open Terminal and type: sudo nano /etc/ssh/sshd_config. "
                            "Find the line that says PermitRootLogin and change it to "
                            "PermitRootLogin no. Save the file (Control+O, Enter, Control+X) "
                            "and restart your Mac."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.ssh_key_audit.permit_root_login",
                        data={"check": "permit_root_login"},
                    )
                )

            if password_auth:
                findings.append(
                    Finding(
                        title="Your Mac allows login with just a password over SSH",
                        description=(
                            "Your Mac is set up to allow people to log in over a secure "
                            "network connection using only a password. This makes it easier "
                            "for attackers to try guessing your password until they get "
                            "it right. It is safer to use a special key file for login, "
                            "which is much harder to guess.\n\n"
                            "What to do: Open Terminal and type: sudo nano /etc/ssh/sshd_config. "
                            "Find the line that says PasswordAuthentication and change "
                            "it to PasswordAuthentication no. Save the file (Control+O, "
                            "Enter, Control+X) and restart your Mac."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.ssh_key_audit.password_auth_enabled",
                        data={"check": "password_auth_enabled"},
                    )
                )
        except OSError:
            pass

        return findings

    def _check_known_hosts(self) -> list[Finding]:
        """Check known_hosts for entries."""
        findings = []
        known_hosts = Path.home() / ".ssh" / "known_hosts"

        if not known_hosts.exists():
            return findings

        try:
            with open(known_hosts, "r") as f:
                lines = [l.strip() for l in f.readlines() if l.strip() and not l.startswith("#")]

            if lines:
                findings.append(
                    Finding(
                        title=f"Saved server records: {len(lines)}",
                        description=(
                            f"You have {len(lines)} host(s) in known_hosts. "
                            f"These are SSH server fingerprints that have been verified. "
                            f"Review and remove any hosts you no longer use."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        code="security.ssh_key_audit.known_hosts",
                        data={"check": "known_hosts", "count": len(lines)},
                    )
                )
        except OSError:
            pass

        return findings
