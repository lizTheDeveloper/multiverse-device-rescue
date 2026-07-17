from pathlib import Path

from setuptools import setup


ROOT = Path(__file__).parent
ASSET_ROOT = "share/multiverse-device-rescue"


def runtime_assets() -> list[tuple[str, list[str]]]:
    assets = []
    for source_root in (ROOT / "modules", ROOT / "profiles", ROOT / "guides"):
        for directory, files in _files_by_directory(source_root).items():
            relative = directory.relative_to(ROOT)
            assets.append(
                (
                    str(Path(ASSET_ROOT) / relative),
                    [path.relative_to(ROOT).as_posix() for path in files],
                )
            )
    return assets


def _files_by_directory(source_root: Path) -> dict[Path, list[Path]]:
    grouped: dict[Path, list[Path]] = {}
    for path in sorted(source_root.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        grouped.setdefault(path.parent, []).append(path)
    return grouped


setup(data_files=runtime_assets())
