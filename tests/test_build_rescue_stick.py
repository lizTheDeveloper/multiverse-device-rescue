"""scripts/build_rescue_stick.py: checksum checks and --write-to refusals.

Everything here uses fakes: no network, no `gh`, no `diskutil`, no real disks.
"""

import hashlib
import importlib.util
from collections import namedtuple
from pathlib import Path

import pytest
import sys

# --write-to copies to a mounted macOS volume; its paths are POSIX paths.
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="--write-to is macOS-only; POSIX paths")

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "build_rescue_stick.py"
_spec = importlib.util.spec_from_file_location("build_rescue_stick", SCRIPT)
stick = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(stick)

Usage = namedtuple("Usage", "total used free")
GB = 1024 ** 3


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --- checksums ----------------------------------------------------------


def test_parse_sha256sums_reads_text_and_binary_mode_lines():
    a, b = "a" * 64, "B" * 64
    sums = stick.parse_sha256sums(f"{a}  one.dmg\n\n{b} *two.exe\n")
    assert sums == {"one.dmg": a, "two.exe": b.lower()}


@pytest.mark.parametrize("bad", ["nothash  file.dmg", "abc", "z" * 64 + "  f.dmg"])
def test_parse_sha256sums_rejects_malformed_lines(bad):
    with pytest.raises(stick.StickError):
        stick.parse_sha256sums(bad + "\n")


def test_verify_files_accepts_matching_files(tmp_path):
    (tmp_path / "app.dmg").write_bytes(b"real installer")
    stick.verify_files(tmp_path, {"app.dmg": _sha(b"real installer")}, ["app.dmg"])


def test_verify_files_stops_on_mismatch(tmp_path):
    (tmp_path / "app.dmg").write_bytes(b"tampered")
    with pytest.raises(stick.StickError, match="MISMATCH"):
        stick.verify_files(tmp_path, {"app.dmg": _sha(b"real installer")}, ["app.dmg"])


def test_verify_files_stops_when_file_is_unlisted_or_missing(tmp_path):
    (tmp_path / "app.dmg").write_bytes(b"x")
    with pytest.raises(stick.StickError, match="not listed"):
        stick.verify_files(tmp_path, {}, ["app.dmg"])
    with pytest.raises(stick.StickError, match="missing"):
        stick.verify_files(tmp_path, {"gone.exe": "0" * 64}, ["gone.exe"])


# --- --write-to refusals --------------------------------------------------

BOOT = {"MountPoint": "/", "DeviceIdentifier": "disk3s1s1", "ParentWholeDisk": "disk3",
        "Internal": True, "Removable": False, "Ejectable": False, "BusProtocol": "Apple Fabric"}
USB = {"MountPoint": "/Volumes/RESCUE", "DeviceIdentifier": "disk5s1", "ParentWholeDisk": "disk5",
       "Internal": False, "Removable": True, "Ejectable": True, "BusProtocol": "USB",
       "FilesystemType": "exfat", "WritableVolume": True}


def _check(target, *, vol_info=USB, free=8 * GB, needed=400 * 1024 ** 2, realpath=None, mounted=True):
    def info(path):
        return BOOT if path == "/" else vol_info
    return stick.check_write_target(
        target, needed, info=info,
        disk_usage=lambda p: Usage(16 * GB, 16 * GB - free, free),
        is_mount=lambda p: mounted,
        realpath=realpath or (lambda p: p))


@posix_only
def test_accepts_external_usb_volume():
    dest, _ = _check("/Volumes/RESCUE")
    assert dest == Path("/Volumes/RESCUE")


@posix_only
@pytest.mark.parametrize("target", ["/Users/someone/Desktop", "/", "/tmp/Volumes/RESCUE", "/Volumes"])
def test_refuses_paths_outside_volumes(target):
    with pytest.raises(stick.StickError, match="under /Volumes"):
        _check(target)


@posix_only
def test_refuses_relative_path():
    with pytest.raises(stick.StickError, match="full path"):
        _check("Volumes/RESCUE")


@posix_only
def test_refuses_macintosh_hd_symlink_to_root():
    # On macOS, /Volumes/Macintosh HD is a symlink to /.
    with pytest.raises(stick.StickError, match="under /Volumes"):
        _check("/Volumes/Macintosh HD", realpath=lambda p: "/")


@posix_only
def test_refuses_boot_volume_reported_by_diskutil():
    boot_under_volumes = dict(BOOT, MountPoint="/Volumes/Data")
    with pytest.raises(stick.StickError, match="startup disk"):
        _check("/Volumes/Data", vol_info=boot_under_volumes)


@posix_only
def test_refuses_internal_non_removable_disk():
    internal = dict(USB, Internal=True, Removable=False, RemovableMedia=False, Ejectable=False,
                    ParentWholeDisk="disk1", DeviceIdentifier="disk1s2")
    with pytest.raises(stick.StickError, match="internal"):
        _check("/Volumes/RESCUE", vol_info=internal)


@posix_only
def test_refuses_mounted_disk_image():
    dmg = dict(USB, BusProtocol="Disk Image")
    with pytest.raises(stick.StickError, match="disk image"):
        _check("/Volumes/RESCUE", vol_info=dmg)


@posix_only
def test_refuses_unmounted_path():
    with pytest.raises(stick.StickError, match="isn't a mounted drive"):
        _check("/Volumes/RESCUE", mounted=False)


@posix_only
def test_refuses_when_not_enough_free_space():
    with pytest.raises(stick.StickError, match="free"):
        _check("/Volumes/RESCUE", free=100 * 1024 ** 2)


# --- the text the person reads -----------------------------------------


def test_start_here_has_the_safety_note_and_unsigned_app_steps():
    steps = stick.install_steps()
    txt = stick.ascii_text(stick.start_here_txt("v9.9.9", steps, with_cli=False, has_tools=False))
    html = stick.start_here_html("v9.9.9", steps, with_cli=False, has_tools=False)
    for text in (txt, html):
        assert "1-800-799-7233" in text and "88788" in text
        assert "advocate" in text
        assert "Open Anyway" in text and "Run anyway" in text
        assert "About This Mac" in text
        for _, folder in stick.INSTALLERS:
            assert folder in text
    assert txt.isascii()
