"""Shared git test fixtures for tests/update/*.

Spins up small real git repositories under tmp_path and shells out to the
real `git` binary. Appropriate here because rescue.update.repo and
rescue.update.sideload are themselves thin wrappers around git subprocess
calls -- testing them against real git is more meaningful than mocking
git itself. Signature verification (a separate concern layered on top) is
mocked in tests/update/test_verify.py and tests/update/test_engine.py.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def _run_git(args: list[str], cwd: Path) -> str:
    result = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return result.stdout


def _init_origin(path: Path) -> Path:
    path.mkdir(parents=True)
    _run_git(["init", "-q", "-b", "main"], cwd=path)
    _run_git(["config", "user.email", "maintainer@example.com"], cwd=path)
    _run_git(["config", "user.name", "Test Maintainer"], cwd=path)
    (path / "manifest.json").write_text(
        '{"content_version": "1", "updated_at": "t", "modules": [], "guides": []}'
    )
    _run_git(["add", "manifest.json"], cwd=path)
    _run_git(["commit", "-q", "-m", "Initial content"], cwd=path)
    return path


@pytest.fixture
def make_origin(tmp_path):
    def _make(name: str = "origin") -> Path:
        return _init_origin(tmp_path / name)
    return _make


@pytest.fixture
def commit_file():
    def _commit(origin: Path, rel_path: str, content: str, message: str) -> str:
        file_path = origin / rel_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content)
        _run_git(["add", rel_path], cwd=origin)
        _run_git(["commit", "-q", "-m", message], cwd=origin)
        return _run_git(["rev-parse", "HEAD"], cwd=origin).strip()
    return _commit


@pytest.fixture
def run_git():
    return _run_git
