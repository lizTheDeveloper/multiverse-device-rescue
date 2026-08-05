"""Tests for linux_disk_encryption_check.

The failure mode to avoid is telling someone their disk is unencrypted because
the check could not read the disk layout. "Undetermined" and "not encrypted"
must stay distinct.
"""

import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.command import CommandResult
from rescue.models import Mode, Platform, Severity, SystemProfile
from rescue.registry import discover_modules

PLAIN_MOUNTS = "/dev/vda1 / ext4 rw,relatime 0 0\nproc /proc proc rw 0 0\n"
LUKS_MOUNTS = "/dev/mapper/cryptroot / ext4 rw,relatime 0 0\n"

LSBLK_PLAIN = 'NAME="vda" TYPE="disk" FSTYPE="" MOUNTPOINT=""\n'
LSBLK_LUKS = (
    'NAME="vda1" TYPE="part" FSTYPE="crypto_LUKS" MOUNTPOINT=""\n'
    'NAME="cryptroot" TYPE="crypt" FSTYPE="ext4" MOUNTPOINT="/"\n'
)


def _get_module():
    modules = discover_modules(Path(__file__).parent.parent / "modules")
    return next(m for m in modules if m.name == "linux_disk_encryption_check")


def _profile(platform=Platform.LINUX) -> SystemProfile:
    return SystemProfile(
        platform=platform,
        os_name="Ubuntu 24.04",
        os_version="6.8.0",
        architecture="x86_64",
        cpu_model="Test",
        cpu_cores=4,
        ram_bytes=8 * 1024**3,
    )


def _result(args, stdout="", returncode=0, error=None) -> CommandResult:
    return CommandResult(
        args=list(args), returncode=returncode, stdout=stdout, stderr="",
        timed_out=False, error=error, duration_s=0.01, truncated=False,
    )


def _patched(mod, lsblk=None, zfs=None):
    def fake(args, **kwargs):
        if args[0] == "lsblk":
            if lsblk is None:
                return _result(args, error="No such file or directory")
            return _result(args, lsblk)
        if args[0] == "zfs" and zfs is not None:
            return _result(args, zfs)
        return _result(args, error="No such file or directory")

    return patch.object(sys.modules[type(mod).__module__], "run", side_effect=fake)


def _configure(mod, tmp_path, mounts):
    path = tmp_path / "mounts"
    path.write_text(mounts)
    mod.mounts_path = str(path)
    return mod


def _codes(result):
    return [f.code for f in result.findings]


def test_non_linux_is_unsupported():
    assert _get_module().check(_profile(Platform.DARWIN)).supported is False


def test_unencrypted_root_is_reported(tmp_path):
    mod = _configure(_get_module(), tmp_path, PLAIN_MOUNTS)
    with _patched(mod, lsblk=LSBLK_PLAIN):
        result = mod.check(_profile())
    finding = next(f for f in result.findings if f.code.endswith("root_not_encrypted"))
    assert finding.severity is Severity.WARNING
    assert finding.data["device"] == "/dev/vda1"


def test_luks_root_is_recognised_as_encrypted(tmp_path):
    mod = _configure(_get_module(), tmp_path, LUKS_MOUNTS)
    with _patched(mod, lsblk=LSBLK_LUKS):
        result = mod.check(_profile())
    codes = _codes(result)
    assert "security.linux_disk_encryption_check.encrypted" in codes
    assert "security.linux_disk_encryption_check.root_not_encrypted" not in codes


def test_unreadable_layout_is_undetermined_not_unencrypted(tmp_path):
    mod = _configure(_get_module(), tmp_path, PLAIN_MOUNTS)
    with _patched(mod, lsblk=None):
        with patch.object(Path, "is_dir", return_value=False):
            result = mod.check(_profile())
    codes = _codes(result)
    assert "security.linux_disk_encryption_check.encryption_undetermined" in codes
    assert "security.linux_disk_encryption_check.root_not_encrypted" not in codes


def test_unreadable_mounts_is_an_error(tmp_path):
    mod = _get_module()
    mod.mounts_path = str(tmp_path / "absent")
    with _patched(mod, lsblk=LSBLK_PLAIN):
        result = mod.check(_profile())
    assert result.error is not None


def test_separate_unencrypted_home_is_reported(tmp_path):
    mounts = LUKS_MOUNTS + "/dev/vdb1 /home ext4 rw 0 0\n"
    mod = _configure(_get_module(), tmp_path, mounts)
    with _patched(mod, lsblk=LSBLK_LUKS):
        result = mod.check(_profile())
    assert "security.linux_disk_encryption_check.home_not_encrypted" in _codes(result)


def test_zfs_native_encryption_counts_as_encrypted(tmp_path):
    mod = _configure(_get_module(), tmp_path, "rpool/ROOT / zfs rw 0 0\n")
    with _patched(mod, lsblk=LSBLK_PLAIN, zfs="aes-256-gcm"):
        result = mod.check(_profile())
    assert "security.linux_disk_encryption_check.root_not_encrypted" not in _codes(result)


def test_guidance_never_asks_for_a_passphrase(tmp_path):
    """The tool must never solicit a recovery key or passphrase."""
    mod = _configure(_get_module(), tmp_path, PLAIN_MOUNTS)
    with _patched(mod, lsblk=LSBLK_PLAIN):
        check = mod.check(_profile())
    fix = mod.fix(check, Mode.CLI)
    assert fix.executed_mutations == []
    text = " ".join(a.description for a in fix.actions)
    assert "never ask you for it" in text
