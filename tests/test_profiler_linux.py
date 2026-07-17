from rescue.models import Platform
from rescue.profiler import linux


def test_gather_linux_profile_uses_linux_helpers(monkeypatch):
    monkeypatch.setattr(linux, "_os_name", lambda: "Test Linux")
    monkeypatch.setattr(linux, "_cpu_model", lambda: "Test CPU")
    monkeypatch.setattr(linux, "_ram_bytes", lambda: 1024)
    monkeypatch.setattr(linux, "_disks", lambda: [])
    monkeypatch.setattr(linux, "_processes", lambda: [])

    profile = linux.gather_linux_profile()

    assert profile.platform == Platform.LINUX
    assert profile.os_name == "Test Linux"
    assert profile.cpu_model == "Test CPU"
    assert profile.ram_bytes == 1024
