import sys

from rescue.models import Platform, SystemProfile


def detect_platform() -> Platform:
    if sys.platform == "darwin":
        return Platform.DARWIN
    elif sys.platform == "win32":
        return Platform.WIN32
    elif sys.platform.startswith("linux"):
        return Platform.LINUX
    raise RuntimeError(f"Unsupported platform: {sys.platform}")


def gather_profile() -> SystemProfile:
    plat = detect_platform()
    if plat == Platform.DARWIN:
        from rescue.profiler.darwin import gather_darwin_profile
        return gather_darwin_profile()
    elif plat == Platform.WIN32:
        from rescue.profiler.windows import gather_windows_profile
        return gather_windows_profile()
    elif plat == Platform.LINUX:
        from rescue.profiler.linux import gather_linux_profile
        return gather_linux_profile()
    raise RuntimeError("Unsupported platform (should not be reached)")


def gather_target_profile(root, os: Platform) -> SystemProfile:
    """Describe the disk mounted at `root` instead of the running computer."""
    from pathlib import Path

    from rescue.target import Target, TargetError

    if os != Platform.LINUX:
        raise TargetError(
            "Checking a Windows or Mac disk from outside isn't built yet. "
            "Only --target-os linux works so far."
        )
    root = Path(root)
    target = Target(root=root, os=os)
    if not any((root / "etc" / name).exists() for name in ("os-release", "passwd")):
        raise TargetError(
            f"{root} doesn't look like a Linux system disk "
            "(no /etc/os-release or /etc/passwd)."
        )
    from rescue.profiler.target_linux import gather_linux_target_profile

    return gather_linux_target_profile(target)
