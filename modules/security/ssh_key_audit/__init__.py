import subprocess
import os
import stat
from pathlib import Path

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
                            f"Fix with: chmod 600 {finding.data.get('key_file')}"
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
                    title="DSA key detected (cryptographically broken)",
                    description=(
                        f"SSH key {key_name} is DSA-based. DSA is cryptographically broken and should not be used. "
                        f"Regenerate the key using Ed25519 or RSA (2048+ bits)."
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
                    title=f"Weak RSA key: {bits} bits (should be 2048+)",
                    description=(
                        f"SSH key {key_name} is RSA with {bits} bits. "
                        f"RSA keys should be at least 2048 bits for adequate security. "
                        f"Regenerate with at least 2048 bits (4096 recommended)."
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
                    title=f"Ed25519 keys found: {len(ed25519_keys)}",
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
                    title=f"RSA keys found: {len(rsa_keys)}",
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
            ssh_perms = stat.filemode(ssh_stat.st_mode)[-3:]
            if ssh_perms != "700":
                findings.append(
                    Finding(
                        title=f"SSH directory has incorrect permissions ({ssh_perms})",
                        description=(
                            f"~/.ssh directory has permissions {ssh_perms}. "
                            f"Should be 700 (rwx------) for security."
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
                        key_stat = key_file.stat()
                        key_perms = stat.filemode(key_stat.st_mode)[-3:]
                        if key_perms != "600":
                            findings.append(
                                Finding(
                                    title=f"Private key has incorrect permissions ({key_perms})",
                                    description=(
                                        f"Private key {key_file.name} has permissions {key_perms}. "
                                        f"Should be 600 (rw-------) to prevent unauthorized access."
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
                        title=f"Authorized keys found: {len(lines)} entry(ies)",
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
                        title=f"SSH agent is running with {key_count} key(s) loaded",
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
                        title="sshd allows root login",
                        description=(
                            "sshd_config has PermitRootLogin enabled. "
                            "This allows direct SSH access to the root account, which is a security risk. "
                            "Disable by setting 'PermitRootLogin no' in /etc/ssh/sshd_config."
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
                        title="sshd allows password authentication",
                        description=(
                            "sshd_config has PasswordAuthentication enabled. "
                            "Use key-based authentication instead to reduce brute-force attack risk. "
                            "Disable by setting 'PasswordAuthentication no' in /etc/ssh/sshd_config."
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
                        title=f"Known hosts found: {len(lines)} entry(ies)",
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
