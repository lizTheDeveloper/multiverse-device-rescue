import pytest

from rescue.models import Platform
from rescue.profiler.base import gather_target_profile
from rescue.target import TargetError


def test_profile_reads_target_os_release_and_hostname(linux_disk):
    p = gather_target_profile(linux_disk, Platform.LINUX)
    assert p.os_name == "Ubuntu 24.04.1 LTS" and p.hostname == "sams-laptop"
    assert p.os_version == "24.04"
    assert p.target.root == linux_disk and p.processes == []


def test_profile_lists_dpkg_flatpak_snap(linux_disk):
    sw = gather_target_profile(linux_disk, Platform.LINUX).installed_software
    assert "openssh-server" in sw and "oldthing" not in sw
    assert "org.mozilla.firefox" in sw and "spotify" in sw
    assert sw == sorted(set(sw))


def test_profile_startup_items_use_target_paths(linux_disk):
    p = gather_target_profile(linux_disk, Platform.LINUX)
    assert p.startup_items == ["/etc/systemd/system/multi-user.target.wants/ssh.service"]


def test_profile_missing_sources_give_empty_values(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/passwd").write_text("root:x:0:0::/root:/bin/sh\n")
    p = gather_target_profile(tmp_path, Platform.LINUX)
    assert p.os_name == "Linux" and p.os_version == "" and p.hostname == ""
    assert p.installed_software == [] and p.startup_items == []


def test_profile_refuses_non_linux_root(tmp_path):
    with pytest.raises(TargetError, match="doesn't look like a Linux system disk"):
        gather_target_profile(tmp_path, Platform.LINUX)


def test_profile_refuses_windows_and_macos(linux_disk):
    for os_ in (Platform.WIN32, Platform.DARWIN):
        with pytest.raises(TargetError, match="isn't built yet"):
            gather_target_profile(linux_disk, os_)


def test_profile_reads_dpkg_status_past_one_megabyte(linux_disk):
    filler = "".join(
        f"Package: filler{i}\nStatus: install ok installed\nDescription: {'x' * 200}\n\n"
        for i in range(8000)
    )
    status = linux_disk / "var/lib/dpkg/status"
    status.write_text(
        filler + "Package: distinctive-last\nStatus: install ok installed\n"
    )
    assert status.stat().st_size > 1_000_000
    sw = gather_target_profile(linux_disk, Platform.LINUX).installed_software
    assert "distinctive-last" in sw and "filler7999" in sw


def test_profile_refuses_root_whose_os_release_only_resolves_on_host(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").symlink_to("/etc/hosts")
    with pytest.raises(TargetError, match="doesn't look like a Linux system disk"):
        gather_target_profile(tmp_path, Platform.LINUX)


def test_profile_accepts_os_release_symlink_on_disk(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "usr/lib").mkdir(parents=True)
    (tmp_path / "usr/lib/os-release").write_text('PRETTY_NAME="Debian 12"\nVERSION_ID="12"\n')
    (tmp_path / "etc/os-release").symlink_to("/usr/lib/os-release")
    p = gather_target_profile(tmp_path, Platform.LINUX)
    assert p.os_name == "Debian 12"
