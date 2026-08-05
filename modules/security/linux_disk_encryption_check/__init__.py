"""Is the data on this machine's disks encrypted at rest?

Full-disk encryption is the only control that survives the threat this toolkit
is most often used after: the laptop is gone. Screen locks, passwords, and
firewalls all assume the machine is still yours. Once someone has the physical
drive, an unencrypted filesystem hands over browser sessions, SSH keys, saved
passwords, tax documents, and every message ever synced to the machine — no
password required, because none is asked for.

Linux encryption is layered: LUKS containers under filesystems, or per-directory
encryption via fscrypt (ext4), or ZFS/btrfs native encryption. This checks for
LUKS first (by far the most common), then looks for the others so a machine
using them is not wrongly reported as unencrypted.

The check never asks for, stores, or displays a passphrase or recovery key.
"""

from pathlib import Path

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

_TIMEOUT = 15.0

# Pseudo-filesystems and removable/virtual mounts that say nothing about
# whether the user's data is encrypted.
_IGNORED_FS = {
    "tmpfs", "devtmpfs", "proc", "sysfs", "cgroup", "cgroup2", "overlay",
    "squashfs", "iso9660", "efivarfs", "debugfs", "tracefs", "fuse.portal",
    "autofs", "mqueue", "hugetlbfs", "pstore", "bpf", "configfs", "securityfs",
    "ramfs", "binfmt_misc", "fusectl", "nsfs", "devpts",
}

_PROTECTED_MOUNTS = ("/", "/home")


class Module(ModuleBase):
    name = "linux_disk_encryption_check"
    category = "security"
    platforms = [Platform.LINUX]
    risk_level = RiskLevel.SAFE
    priority = 87
    depends_on = []
    estimated_duration = "15s"

    emits_codes = [
        "security.linux_disk_encryption_check.root_not_encrypted",
        "security.linux_disk_encryption_check.home_not_encrypted",
        "security.linux_disk_encryption_check.encryption_undetermined",
        "security.linux_disk_encryption_check.encrypted",
    ]

    mounts_path: str = "/proc/mounts"

    def check(self, profile: SystemProfile) -> CheckResult:
        if profile.platform is not Platform.LINUX:
            return CheckResult(
                module_name=self.name,
                supported=False,
                unsupported_reason=(
                    "This check reads Linux block-device and mount layout; this host "
                    f"reports {profile.platform.value}."
                ),
            )

        mounts = self._mounts()
        if not mounts:
            return CheckResult(
                module_name=self.name,
                error=f"{self.mounts_path} could not be read, so mount points are unknown.",
            )

        encrypted_devices, determined = self._encrypted_devices()
        if not determined:
            return CheckResult(
                module_name=self.name,
                findings=[
                    Finding(
                        title="Disk encryption status could not be determined",
                        description=(
                            "Neither lsblk nor /dev/mapper could be inspected, so this run "
                            "cannot say whether the disks are encrypted. Re-run with sudo. "
                            "Do not read this as 'not encrypted' — it is 'not checked'."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        code="security.linux_disk_encryption_check.encryption_undetermined",
                        confidence=1.0,
                        data={"check": "encryption_undetermined"},
                    )
                ],
            )

        findings: list[Finding] = []
        protected: list[str] = []

        for mount_point in _PROTECTED_MOUNTS:
            device = mounts.get(mount_point)
            if device is None:
                continue  # /home is often part of / rather than its own mount
            if self._is_encrypted(device, mount_point, encrypted_devices):
                protected.append(mount_point)
                continue

            is_root = mount_point == "/"
            findings.append(
                Finding(
                    title=f"{mount_point} is not encrypted",
                    description=(
                        f"{device} mounted at {mount_point} is stored unencrypted.\n\n"
                        + (
                            "Everything on this machine — saved passwords, browser "
                            "sessions, SSH keys, documents — can be read by anyone who "
                            "gets the drive out of it. That takes a screwdriver and a few "
                            "minutes; your login password is not involved."
                            if is_root
                            else "Your personal files are stored unencrypted, so they can "
                            "be read directly off the drive by anyone who has it, "
                            "regardless of your login password."
                        )
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code=(
                        "security.linux_disk_encryption_check.root_not_encrypted"
                        if is_root
                        else "security.linux_disk_encryption_check.home_not_encrypted"
                    ),
                    confidence=0.85,
                    data={
                        "check": "root_not_encrypted" if is_root else "home_not_encrypted",
                        "mount_point": mount_point,
                        "device": device,
                    },
                )
            )

        if protected:
            findings.append(
                Finding(
                    title=f"Encryption is active on {', '.join(protected)}",
                    description=(
                        "These mount points sit on encrypted storage, so their contents "
                        "are unreadable without the passphrase if the machine is lost or "
                        "stolen while powered off.\n\n"
                        "Two things this does not protect against, worth knowing: it does "
                        "nothing while the machine is unlocked and running, and it does "
                        "nothing if the passphrase is guessable. Encryption plus a weak "
                        "passphrase is a locked door with the key under the mat."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.linux_disk_encryption_check.encrypted",
                    confidence=0.9,
                    data={"check": "encrypted", "mount_points": protected},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def _mounts(self) -> dict[str, str]:
        try:
            text = Path(self.mounts_path).read_text(errors="replace")
        except OSError:
            return {}
        mounts: dict[str, str] = {}
        for line in text.splitlines():
            fields = line.split()
            if len(fields) < 3:
                continue
            device, mount_point, fs_type = fields[0], fields[1], fields[2]
            if fs_type in _IGNORED_FS:
                continue
            mounts.setdefault(mount_point, device)
        return mounts

    def _encrypted_devices(self) -> tuple[set[str], bool]:
        """Names of device-mapper targets backed by LUKS, and whether we know.

        The second element distinguishes "asked, found none" from "could not
        ask" — the difference between a real answer and no answer.
        """
        result = run(["lsblk", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT", "-P"], timeout=_TIMEOUT)
        if result.error is None and result.returncode == 0 and result.stdout.strip():
            encrypted: set[str] = set()
            for line in result.stdout.splitlines():
                fields = dict(
                    part.split("=", 1) for part in line.split() if "=" in part
                )
                name = fields.get("NAME", "").strip('"')
                fstype = fields.get("FSTYPE", "").strip('"')
                type_ = fields.get("TYPE", "").strip('"')
                if fstype.startswith("crypto_LUKS") or type_ == "crypt":
                    encrypted.add(name)
            return encrypted, True

        # Fallback: a mounted LUKS volume always appears under /dev/mapper.
        mapper = Path("/dev/mapper")
        try:
            if mapper.is_dir():
                return {p.name for p in mapper.iterdir() if p.name != "control"}, True
        except OSError:
            pass
        return set(), False

    def _is_encrypted(self, device: str, mount_point: str, encrypted: set[str]) -> bool:
        # A LUKS-backed filesystem is mounted from its mapper device, so the
        # device path itself carries the evidence.
        if device.startswith("/dev/mapper/") or device.startswith("/dev/dm-"):
            name = device.rsplit("/", 1)[-1]
            if name in encrypted or not encrypted:
                # An unopened LUKS volume cannot be mounted, so a mapper mount
                # with an unrecognised name is still most likely encrypted; but
                # only claim it when lsblk actually listed a crypt layer.
                return name in encrypted
        if any(name and name in device for name in encrypted):
            return True
        # ZFS and btrfs native encryption, and ext4 fscrypt, do not use mapper
        # devices. Ask the filesystem rather than assuming.
        return self._native_encryption(mount_point)

    def _native_encryption(self, mount_point: str) -> bool:
        status = run(["fscryptctl", "get_policy", mount_point], timeout=_TIMEOUT)
        if status.error is None and status.returncode == 0 and status.stdout.strip():
            return True
        zfs = run(["zfs", "get", "-H", "-o", "value", "encryption", mount_point], timeout=_TIMEOUT)
        if zfs.error is None and zfs.returncode == 0:
            value = zfs.stdout.strip().lower()
            if value and value not in ("off", "-", "none"):
                return True
        return False

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions: list[Action] = []
        for finding in findings.findings:
            check = finding.data.get("check")

            if check in ("root_not_encrypted", "home_not_encrypted"):
                actions.append(
                    Action(
                        title=f"Encrypt {finding.data.get('mount_point')}",
                        description=(
                            "Be straight with yourself about the cost here: on Linux, "
                            "encrypting an existing root filesystem in place is genuinely "
                            "risky and usually means a reinstall.\n\n"
                            "Realistic options, easiest first:\n\n"
                            "  1. **At the next reinstall**, tick 'Encrypt the new "
                            "installation' in the installer. Every mainstream installer "
                            "offers it and it is the least painful path by a wide margin.\n\n"
                            "  2. **Encrypt /home separately** if it is its own partition. "
                            "Back it up, then:\n"
                            "         sudo cryptsetup luksFormat /dev/sdaX\n"
                            "         sudo cryptsetup open /dev/sdaX home\n"
                            "         sudo mkfs.ext4 /dev/mapper/home\n"
                            "     and restore into it. This destroys the partition — the "
                            "backup is not optional.\n\n"
                            "  3. **Encrypt just the files that matter** today, as an "
                            "interim step: a VeraCrypt or gocryptfs container, or "
                            "`fscrypt` on ext4.\n\n"
                            "Whichever you choose: write the passphrase down and keep it "
                            "somewhere physical and safe. There is no recovery path for a "
                            "forgotten LUKS passphrase — none, at all. This tool will "
                            "never ask you for it."
                        ),
                        risk_level=RiskLevel.SAFE,
                        kind=ActionKind.GUIDANCE,
                        data={"check": check, "mount_point": finding.data.get("mount_point")},
                    )
                )
            elif check == "encryption_undetermined":
                actions.append(
                    Action(
                        title="Re-run this check with enough privilege to read the disk layout",
                        description=(
                            "    sudo rescue run linux_disk_encryption_check --yes\n\n"
                            "Or check by hand:\n"
                            "    lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT\n"
                            "A 'crypt' row above your filesystem means LUKS is in use."
                        ),
                        risk_level=RiskLevel.SAFE,
                        kind=ActionKind.GUIDANCE,
                        data={"check": check},
                    )
                )
        return FixResult(module_name=self.name, actions=actions)
