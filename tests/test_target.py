import os

import pytest

from rescue.models import CheckResult, Platform, SystemProfile
from rescue.target import Target, TargetError


@pytest.fixture
def disk(tmp_path):
    d = tmp_path / "disk"
    (d / "etc" / "systemd" / "system" / "multi-user.target.wants").mkdir(parents=True)
    (d / "lib" / "systemd" / "system").mkdir(parents=True)
    (d / "usr" / "share" / "alt").mkdir(parents=True)
    (d / "root").mkdir()
    (d / "home" / "sam").mkdir(parents=True)
    (d / "etc" / "passwd").write_text(
        "root:x:0:0::/root:/bin/bash\n"
        "sam:x:1000:1000::/home/sam:/bin/bash\n"
        "daemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n"
    )
    return d


def target(disk):
    return Target(root=disk, os=Platform.LINUX)


def test_resolve_plain_path(disk):
    assert target(disk).resolve("/etc/passwd") == disk / "etc" / "passwd"


def test_resolve_root_itself(disk):
    assert target(disk).resolve("/") == disk


def test_resolve_absolute_symlink_stays_inside_root(disk):
    (disk / "lib" / "systemd" / "system" / "ssh.service").write_text("x")
    link = disk / "etc/systemd/system/multi-user.target.wants/ssh.service"
    os.symlink("/lib/systemd/system/ssh.service", link)
    assert target(disk).resolve(
        "/etc/systemd/system/multi-user.target.wants/ssh.service"
    ) == disk / "lib" / "systemd" / "system" / "ssh.service"


def test_resolve_absolute_symlink_never_uses_host(disk, tmp_path):
    host_dir = tmp_path / "hostdir"
    host_dir.mkdir()
    os.symlink(str(host_dir), disk / "etc" / "escape")
    got = target(disk).resolve("/etc/escape/file")
    assert got == disk / str(host_dir).lstrip("/") / "file"


def test_resolve_relative_symlink(disk):
    os.symlink("../usr/share/alt", disk / "etc" / "alt")
    assert target(disk).resolve("/etc/alt") == disk / "usr" / "share" / "alt"


def test_resolve_dotdot_cannot_escape(disk):
    t = target(disk)
    assert t.resolve("/../../etc/passwd") == disk / "etc" / "passwd"
    os.symlink("../../../../", disk / "etc" / "up")
    assert t.resolve("/etc/up/etc/passwd") == disk / "etc" / "passwd"


def test_resolve_symlink_loop_raises(disk):
    os.symlink("/b", disk / "a")
    os.symlink("/a", disk / "b")
    with pytest.raises(TargetError):
        target(disk).resolve("/a/x")


def test_resolve_missing_final_component_ok(disk):
    assert target(disk).resolve("/etc/nope") == disk / "etc" / "nope"


def test_display_round_trips(disk, tmp_path):
    t = target(disk)
    assert t.display(disk / "etc" / "passwd") == "/etc/passwd"
    assert t.display(disk) == "/"
    with pytest.raises(TargetError):
        t.display(tmp_path / "elsewhere")


def test_user_homes_reads_target_passwd(disk):
    assert target(disk).user_homes() == [
        ("root", disk / "root"),
        ("sam", disk / "home" / "sam"),
    ]


def test_user_homes_skips_missing_and_escaping(disk):
    with open(disk / "etc" / "passwd", "a") as f:
        f.write("ghost:x:1001:1001::/home/ghost:/bin/sh\n")
        f.write("rel:x:1002:1002::home/rel:/bin/sh\n")
    names = [n for n, _ in target(disk).user_homes()]
    assert "ghost" not in names and "rel" not in names and "sam" in names


def test_user_homes_unreadable_passwd(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert target(empty).user_homes() == []


def test_expand_tilde_per_user(disk):
    t = target(disk)
    assert t.expand("~/.bashrc") == [
        disk / "root" / ".bashrc",
        disk / "home" / "sam" / ".bashrc",
    ]
    assert t.expand("/etc/cron.d") == [disk / "etc" / "cron.d"]


def test_check_result_not_checked_defaults_empty():
    assert CheckResult(module_name="x").not_checked == []


def test_profile_target_defaults_none():
    assert SystemProfile(Platform.LINUX, "", "", "", "", 0, 0).target is None


def test_read_text_refuses_fifo(disk):
    (disk / "etc" / "passwd").unlink()
    os.mkfifo(disk / "etc" / "passwd")
    t = target(disk)
    assert t.user_homes() == []
    with pytest.raises(TargetError):
        t.read_text("/etc/passwd")


def test_read_text_caps_size(disk):
    (disk / "etc" / "big").write_text("a" * 5000)
    assert target(disk).read_text("/etc/big", limit=100) == "a" * 100


def test_read_text_missing_raises_target_error(disk):
    with pytest.raises(TargetError):
        target(disk).read_text("/etc/nope")


def test_target_error_is_oserror():
    assert issubclass(TargetError, OSError)


def test_expand_skips_a_home_that_fails_to_resolve(disk):
    os.symlink("/loop2", disk / "home" / "sam" / ".bashrc")
    os.symlink("/home/sam/.bashrc", disk / "loop2")
    assert target(disk).expand("~/.bashrc") == [disk / "root" / ".bashrc"]
