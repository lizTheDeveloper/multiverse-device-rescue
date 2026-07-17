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
