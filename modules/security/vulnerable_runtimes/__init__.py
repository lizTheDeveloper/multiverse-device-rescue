"""vulnerable_runtimes: copies of Node.js and PHP with a bug attackers are using now.

Developers' computers often hold several copies of Node.js and PHP: one from
Homebrew, a few from a version manager (nvm, fnm, Volta, asdf, mise), one
inside MAMP, XAMPP or Herd. A web app run with any of them can be taken over
from outside when that copy has a remote-code-execution bug on CISA's Known
Exploited Vulnerabilities (KEV) list. This check finds every copy in the
usual places and compares its version with ``ADVISORIES`` below.

The next bug of this kind is one more entry in ``ADVISORIES`` (and, for a new
program, one in ``RUNTIMES``), not new code. Every range is copied from the
advisory it names; none is worked out here.

A version is read without running the program where the install says it:

- Node.js: ``include/node/node_version.h`` next to its ``bin`` folder;
- PHP: ``include/php/main/php_version.h`` next to its ``bin`` folder;

and otherwise by running the copy found with ``--version`` (Node.js) or
``-n -v`` (PHP, ``-n`` so it loads no settings file and no add-ons). A copy is
never run while Reclaim City has administrator rights: a program in a folder
the person can write to would then run as administrator. The version-manager
folder name is the last resort.

Not covered: copies of Node.js inside desktop apps built on Electron (Slack,
VS Code, Discord...). Their Node.js version can't be read from the app
cheaply, and no advisory gives an Electron version range; the app's own
updates fix it.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from rescue.command import run
from rescue.models import (
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

VERSION_TIMEOUT = 5.0
# No more copies than this are looked at (a version manager can hold dozens).
MAX_COPIES = 80

# The only commands this check runs, when a copy has no version header.
# argv[0] is replaced by the full path of the copy found.
NODE_VERSION_ARGS = ["node", "--version"]
PHP_VERSION_ARGS = ["php", "-n", "-v"]

# What a runtime is called, its program names, and where its installs keep
# a version header. ``version_args`` is the command used when there is none.
RUNTIMES: dict[str, dict[str, Any]] = {
    "node": {
        "label": "Node.js",
        "programs": re.compile(r"^node(\.exe)?$", re.IGNORECASE),
        "header": ("include", "node", "node_version.h"),
        "version_args": NODE_VERSION_ARGS,
        "download": "https://nodejs.org/en/download",
        # The line to move to when a copy's own line gets no fix: an LTS line
        # (https://nodejs.org/en/about/previous-releases).
        "upgrade_line": "24",
    },
    "php": {
        "label": "PHP",
        # php, php8.3, php83 (Herd), php-fpm, php-fpm8.3; not php-config or phpize.
        "programs": re.compile(r"^php(-fpm)?(\d+(\.\d+)?)?(\.exe)?$", re.IGNORECASE),
        "header": ("include", "php", "main", "php_version.h"),
        "version_args": PHP_VERSION_ARGS,
        "download": "https://www.php.net/downloads.php",
        # A line with active support (https://www.php.net/supported-versions.php).
        "upgrade_line": "8.4",
    },
}

# Each entry: the bug, where it's described, and every affected range as
# [first affected, first not affected) copied from the advisory. ``fixed``
# maps a release line to its first fixed version; a range whose line has no
# entry there is a line that gets no fix (end of life). ``kev_added`` is the
# date CISA added it to the KEV catalog.
ADVISORIES: list[dict[str, Any]] = [
    {
        "id": "node2shell",
        "runtime": "node",
        "name": "Node2Shell",
        "cves": ["CVE-2026-111497"],
        "summary": "a bug in the Brotli decoder built into Node.js: compressed data an "
                   "attacker sends can make it write past a buffer and run the attacker's code",
        "kev_added": "2026-10-27",
        # Node.js October 2026 security releases (22.23.4, 24.22.1, 26.12.1);
        # the ranges are NVD's for CVE-2026-111497, which count 23.x, 25.x and
        # everything before 22 as affected with no fix.
        "advisory": "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-111497"],
        "affected": [["0", "22.23.4"], ["23.0.0", "24.22.1"], ["25.0.0", "26.12.1"]],
        "fixed": {"22": "22.23.4", "24": "24.22.1", "26": "26.12.1"},
    },
    {
        "id": "php2shell-oom",
        "runtime": "php",
        "name": "PHP2Shell",
        "cves": ["CVE-2026-109618"],
        "summary": "a bug in how PHP cleans up after running out of memory, which lets "
                   "someone on the internet run their own code through a PHP website",
        "kev_added": "2026-10-26",
        # php-src GHSA-w8hw-w9fx-j79w gives 8.2-8.5; NVD adds 7.3.0 onwards.
        # php.net: 8.1 and older get no fix from the PHP project.
        "advisory": "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-109618",
                       "https://www.php.net/archive/2026.php"],
        "affected": [["7.3.0", "8.2.35"], ["8.3.0", "8.3.36"], ["8.4.0", "8.4.27"],
                     ["8.5.0", "8.5.12"]],
        "fixed": {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"},
    },
    {
        "id": "php2shell-state",
        "runtime": "php",
        "name": "PHP2Shell",
        "cves": ["CVE-2026-109619"],
        "summary": "a bug where one web request can use memory another request already "
                   "freed, which lets someone on the internet run their own code",
        "kev_added": "2026-10-26",
        # php-src GHSA-6wmf-4rv5-p3rp gives 8.2-8.5; NVD adds 5.4.0 onwards.
        "advisory": "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-109619",
                       "https://www.php.net/archive/2026.php"],
        "affected": [["5.4.0", "8.2.35"], ["8.3.0", "8.3.36"], ["8.4.0", "8.4.27"],
                     ["8.5.0", "8.5.12"]],
        "fixed": {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"},
    },
]

_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")
_NODE_HEADER_RE = re.compile(r"#define\s+NODE_(MAJOR|MINOR|PATCH)_VERSION\s+(\d+)")
_PHP_HEADER_RE = re.compile(r'#define\s+PHP_VERSION\s+"([^"]+)"')
# Folders shared by many programs: a version header there may belong to
# another copy, so the program itself is asked.
_SHARED_PREFIXES = {"/usr", "/usr/local", "/opt/homebrew", "/home/linuxbrew/.linuxbrew", "/opt/local"}


def parse_version(text: str) -> tuple[int, int, int] | None:
    """'v22.23.3' -> (22, 23, 3); 'PHP 8.4.13 (cli)' -> (8, 4, 13). None if there's no version."""
    m = _VERSION_RE.search(text or "")
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def _vtuple(text: str) -> tuple[int, int, int]:
    parts = [int(n) for n in re.findall(r"\d+", text)[:3]]
    return tuple(parts + [0] * (3 - len(parts)))  # type: ignore[return-value]


def release_line(runtime: str, version: tuple[int, int, int]) -> str:
    """Node.js lines are majors ('22'); PHP lines are major.minor ('8.3')."""
    return str(version[0]) if runtime == "node" else f"{version[0]}.{version[1]}"


def matching_advisories(runtime: str, version: tuple[int, int, int]) -> list[dict[str, Any]]:
    """Every advisory whose affected ranges include this version."""
    hits = []
    for adv in ADVISORIES:
        if adv["runtime"] != runtime:
            continue
        if any(_vtuple(lo) <= version < _vtuple(hi) for lo, hi in adv["affected"]):
            hits.append(adv)
    return hits


def fixed_version(runtime: str, version: tuple[int, int, int], advisories: list[dict]) -> str | None:
    """The lowest version on this copy's own line that fixes every advisory, or None (no fix on the line)."""
    line = release_line(runtime, version)
    fixes = [adv["fixed"].get(line) for adv in advisories]
    if not fixes or any(f is None for f in fixes):
        return None
    return max(fixes, key=_vtuple)


def upgrade_target(runtime: str, advisories: list[dict]) -> str | None:
    """The fixed version on the runtime's recommended line, for a copy whose line gets no fix."""
    line = RUNTIMES[runtime]["upgrade_line"]
    fixes = [adv["fixed"].get(line) for adv in advisories]
    if not fixes or any(f is None for f in fixes):
        return None
    return max(fixes, key=_vtuple)


class Module(ModuleBase):
    name = "vulnerable_runtimes"
    category = "security"
    platforms = [Platform.DARWIN, Platform.LINUX, Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "about a second"

    emits_codes = [
        "security.vulnerable_runtimes.exploited_rce",
        "security.vulnerable_runtimes.old_copy_affected",
        "security.vulnerable_runtimes.version_unknown",
        "security.vulnerable_runtimes.runtime_inventory",
    ]

    # Seams for tests: the home folder, the PATH, the fixed program folders and
    # the version folders outside the home folder (None = the real defaults),
    # and whether Reclaim City runs as administrator.
    home: Path | None = None
    path_env: str | None = None
    fixed_dirs: list[Path] | None = None
    system_roots: list[tuple[Path, str]] | None = None
    elevated: bool | None = None

    def check(self, profile: SystemProfile) -> CheckResult:
        platform = profile.platform
        copies = self._find_copies(platform)
        findings: list[Finding] = []
        inventory = []
        for copy in copies:
            self._read_version(copy, platform)
            inventory.append(copy)
            if copy["version"] is None:
                findings.append(self._unknown_finding(copy))
                continue
            hits = matching_advisories(copy["runtime"], copy["version"])
            copy["affected_by"] = [cve for adv in hits for cve in adv["cves"]]
            if hits:
                findings.append(self._affected_finding(copy, hits, platform))
        if inventory:
            findings.append(self._inventory_finding(inventory))
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        # Updating a runtime can break the projects that use it: the person
        # runs the update step themselves.
        return FixResult(module_name=self.name, actions=[])

    # --- finding the copies -----------------------------------------------------

    def _home(self) -> Path:
        return Path(self.home) if self.home is not None else Path.home()

    def _is_elevated(self, platform: Platform) -> bool:
        if self.elevated is not None:
            return bool(self.elevated)
        if platform == Platform.WIN32:
            try:
                import ctypes

                return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
            except Exception:
                # Can't tell: assume administrator rights, so nothing gets run.
                return True
        geteuid = getattr(os, "geteuid", None)
        return bool(geteuid is not None and geteuid() == 0)

    def _search_dirs(self, platform: Platform) -> list[Path]:
        """Folders that hold a node or php program directly."""
        home = self._home()
        env = os.environ
        path = self.path_env if self.path_env is not None else env.get("PATH", "")
        # Absolute folders only: never the current one.
        dirs = [Path(d) for d in path.split(os.pathsep) if d and os.path.isabs(d)]
        if self.fixed_dirs is not None:
            fixed = list(self.fixed_dirs)
        elif platform == Platform.WIN32:
            fixed = []
            for var in ("ProgramFiles", "ProgramFiles(x86)"):
                if env.get(var):
                    fixed.append(Path(env[var]) / "nodejs")
            drive = Path(env.get("SystemDrive", "C:") + "\\")
            fixed += [drive / "php", drive / "xampp" / "php", drive / "tools" / "php"]
        else:
            fixed = [Path("/opt/homebrew/bin"), Path("/opt/homebrew/sbin"), Path("/usr/local/bin"),
                     Path("/usr/local/sbin"), Path("/usr/bin"), Path("/usr/sbin"),
                     Path("/home/linuxbrew/.linuxbrew/bin"), Path("/snap/bin"),
                     Path("/Applications/XAMPP/xamppfiles/bin"), Path("/opt/lampp/bin"),
                     home / ".local" / "bin", home / ".volta" / "bin",
                     home / "Library" / "Application Support" / "Herd" / "bin"]
        if platform == Platform.WIN32:
            fixed += [home / ".config" / "herd" / "bin"]
        return dirs + fixed

    def _version_roots(self, platform: Platform) -> list[tuple[Path, str]]:
        """Folders with one sub-folder per installed version, and the runtime they hold."""
        home = self._home()
        env = os.environ
        roots: list[tuple[Path, str]] = [
            (home / ".nvm" / "versions" / "node", "node"),
            (home / ".volta" / "tools" / "image" / "node", "node"),
            (home / ".asdf" / "installs" / "nodejs", "node"),
            (home / ".asdf" / "installs" / "php", "php"),
            (home / ".local" / "share" / "mise" / "installs" / "node", "node"),
            (home / ".local" / "share" / "mise" / "installs" / "php", "php"),
            (home / ".local" / "share" / "fnm" / "node-versions", "node"),
            (home / ".fnm" / "node-versions", "node"),
        ]
        if platform == Platform.DARWIN:
            roots.append((home / "Library" / "Application Support" / "fnm" / "node-versions", "node"))
        if self.system_roots is not None:
            return roots + list(self.system_roots)
        if platform == Platform.DARWIN:
            roots.append((Path("/Applications/MAMP/bin/php"), "php"))
            for cellar in (Path("/opt/homebrew/Cellar"), Path("/usr/local/Cellar")):
                roots += self._cellar_roots(cellar)
        elif platform == Platform.LINUX:
            roots += self._cellar_roots(Path("/home/linuxbrew/.linuxbrew/Cellar"))
            roots += [(p, "php") for p in self._children(Path("/opt/remi"))]
        else:
            for var in ("APPDATA", "LOCALAPPDATA"):
                if env.get(var):
                    base = Path(env[var])
                    roots += [(base / "nvm", "node"), (base / "fnm" / "node-versions", "node"),
                              (base / "Volta" / "tools" / "image" / "node", "node")]
            if env.get("NVM_HOME"):
                roots.append((Path(env["NVM_HOME"]), "node"))
            drive = Path(env.get("SystemDrive", "C:") + "\\")
            roots += [(drive / "laragon" / "bin" / "php", "php"), (drive / "MAMP" / "bin" / "php", "php")]
        return roots

    def _cellar_roots(self, cellar: Path) -> list[tuple[Path, str]]:
        out = []
        for formula in self._children(cellar):
            name = formula.name
            if name == "node" or name.startswith("node@"):
                out.append((formula, "node"))
            elif name == "php" or name.startswith("php@"):
                out.append((formula, "php"))
        return out

    @staticmethod
    def _children(folder: Path) -> list[Path]:
        try:
            return sorted(p for p in folder.iterdir() if p.is_dir())
        except OSError:
            return []

    def _programs_in(self, folder: Path) -> list[tuple[Path, str]]:
        found = []
        try:
            entries = sorted(folder.iterdir())
        except OSError:
            return found
        for entry in entries:
            for runtime, spec in RUNTIMES.items():
                if spec["programs"].match(entry.name) and entry.is_file():
                    found.append((entry, runtime))
        return found

    def _find_copies(self, platform: Platform) -> list[dict[str, Any]]:
        candidates: list[tuple[Path, str]] = []
        for folder in self._search_dirs(platform):
            candidates += self._programs_in(folder)
        for root, runtime in self._version_roots(platform):
            for version_dir in self._children(root):
                # <version>/bin/node, <version>/installation/bin/node (fnm),
                # <version>/node.exe (nvm-windows), <version>/php.exe (Laragon).
                for sub in (version_dir / "bin", version_dir / "sbin",
                            version_dir / "installation" / "bin", version_dir / "installation",
                            version_dir / "root" / "usr" / "bin", version_dir):
                    candidates += [(p, r) for p, r in self._programs_in(sub) if r == runtime]
        copies: list[dict[str, Any]] = []
        seen: set[str] = set()
        for program, runtime in candidates:
            try:
                real = str(program.resolve())
            except OSError:
                continue
            if real in seen:
                continue
            seen.add(real)
            if not os.access(real, os.X_OK) and platform != Platform.WIN32:
                continue
            copies.append({"runtime": runtime, "path": str(program), "real_path": real,
                           "version": None, "version_source": None})
            if len(copies) >= MAX_COPIES:
                break
        return copies

    # --- reading the version ----------------------------------------------------

    def _prefix(self, real_path: str) -> Path:
        binary = Path(real_path)
        parent = binary.parent
        return parent.parent if parent.name.lower() in ("bin", "sbin") else parent

    def _header_version(self, copy: dict[str, Any]) -> tuple[int, int, int] | None:
        prefix = self._prefix(copy["real_path"])
        if prefix.as_posix() in _SHARED_PREFIXES:
            return None
        header = prefix.joinpath(*RUNTIMES[copy["runtime"]]["header"])
        try:
            text = header.read_text(encoding="utf-8", errors="replace")[:20000]
        except OSError:
            return None
        if copy["runtime"] == "node":
            parts = dict(_NODE_HEADER_RE.findall(text))
            if {"MAJOR", "MINOR", "PATCH"} <= parts.keys():
                return int(parts["MAJOR"]), int(parts["MINOR"]), int(parts["PATCH"])
            return None
        m = _PHP_HEADER_RE.search(text)
        return parse_version(m.group(1)) if m else None

    def _folder_version(self, copy: dict[str, Any]) -> tuple[int, int, int] | None:
        """The version in a version manager's folder name (v22.1.0, 8.3.12_1, php8.2.0)."""
        for part in reversed(Path(copy["real_path"]).parts[:-1]):
            if re.fullmatch(r"(?:v|php-?|node-?v?)?\d+\.\d+\.\d+(?:[_-].*)?", part, re.IGNORECASE):
                return parse_version(part)
        return None

    def _read_version(self, copy: dict[str, Any], platform: Platform) -> None:
        version = self._header_version(copy)
        if version:
            copy.update(version=version, version_source="version header")
            return
        if not self._is_elevated(platform):
            args = RUNTIMES[copy["runtime"]]["version_args"]
            result = run([copy["real_path"], *args[1:]], timeout=VERSION_TIMEOUT)
            version = parse_version(result.stdout) if result.ok else None
            if version:
                copy.update(version=version, version_source="asked the program")
                return
        version = self._folder_version(copy)
        if version:
            copy.update(version=version, version_source="folder name")

    # --- how it was installed, and how to update it -------------------------------

    def _install_kind(self, copy: dict[str, Any], platform: Platform) -> dict[str, Any]:
        real = copy["real_path"].replace("\\", "/")
        low = real.lower()
        home = self._home().as_posix().lower()
        m = re.search(r"/Cellar/([^/]+)/([^/]+)/", real)
        if m:
            formula, keg = m.group(1), m.group(2)
            prefix = real[:m.start()]
            current = None
            try:
                current = Path(prefix, "opt", formula).resolve().name
            except OSError:
                pass
            return {"kind": "homebrew", "label": f"Homebrew ({formula})", "formula": formula,
                    "in_use": current == keg}
        if "/.nvm/versions/node/" in low:
            return {"kind": "nvm", "label": "nvm"}
        if "/fnm/node-versions/" in low or "/.fnm/node-versions/" in low:
            return {"kind": "fnm", "label": "fnm"}
        if "/volta/tools/image/node/" in low:
            return {"kind": "volta", "label": "Volta"}
        if "/.asdf/installs/" in low:
            return {"kind": "asdf", "label": "asdf"}
        if "/mise/installs/" in low:
            return {"kind": "mise", "label": "mise"}
        if "/mamp/bin/php/" in low:
            return {"kind": "mamp", "label": "MAMP"}
        if "/xampp" in low or "/opt/lampp/" in low:
            return {"kind": "xampp", "label": "XAMPP"}
        if "/herd/bin/" in low:
            return {"kind": "herd", "label": "Laravel Herd"}
        if "/laragon/" in low:
            return {"kind": "laragon", "label": "Laragon"}
        if platform == Platform.WIN32 and re.search(r"/(appdata/(roaming|local)/)?nvm/v?\d", low):
            return {"kind": "nvm_windows", "label": "nvm for Windows"}
        if low.startswith("/snap/"):
            return {"kind": "snap", "label": "Snap"}
        if platform == Platform.WIN32 and "/program files" in low and copy["runtime"] == "node":
            return {"kind": "node_installer", "label": "the Node.js installer"}
        if platform == Platform.DARWIN and low == "/usr/local/bin/node":
            return {"kind": "node_installer", "label": "the Node.js installer from nodejs.org",
                    "how": "probably installed with the Node.js installer from nodejs.org"}
        if platform == Platform.LINUX and (low.startswith("/usr/bin/") or low.startswith("/usr/sbin/")
                                           or low.startswith("/opt/remi/")):
            return {"kind": "distro", "label": "your Linux system's packages"}
        where = str(Path(copy["real_path"]).parent)
        if home and low.startswith(home + "/."):
            # ~/.something/node: a copy another program keeps for itself.
            return {"kind": "other_program", "label": "another program",
                    "how": f"kept by another program in {self._tilde(where)}"}
        return {"kind": "unknown", "label": "unknown", "how": "we couldn't tell how it was installed"}

    def _tilde(self, path: str) -> str:
        home = str(self._home())
        if path == home or path.startswith(home + os.sep) or path.startswith(home + "/"):
            return "~" + path[len(home):]
        return path

    def _upgrade_step(self, copy: dict, how: dict, target: str | None, own_line_fixed: bool) -> str:
        runtime = copy["runtime"]
        label = RUNTIMES[runtime]["label"]
        download = RUNTIMES[runtime]["download"]
        old = ".".join(str(n) for n in copy["version"])
        kind = how["kind"]
        tool = "node" if runtime == "node" else "php"
        if target is None:
            return (f"Install a supported version of {label} from {download}, then remove this one.")
        if kind == "homebrew":
            formula = how["formula"]
            if not how.get("in_use"):
                return f"In Terminal: `brew cleanup {formula}` removes this old copy Homebrew left behind."
            if own_line_fixed:
                return f"In Terminal: `brew update && brew upgrade {formula}`"
            newer = "node" if runtime == "node" else "php"
            return (f"In Terminal: `brew update && brew install {newer}`, move your projects to it, "
                    f"then `brew uninstall {formula}`.")
        if kind == "nvm":
            return f"In Terminal: `nvm install {target}`, then `nvm uninstall {old}` once your projects use it."
        if kind == "nvm_windows":
            return f"In a command prompt: `nvm install {target}`, `nvm use {target}`, then `nvm uninstall {old}`."
        if kind == "fnm":
            return f"In a terminal: `fnm install {target}`, then `fnm uninstall {old}` once your projects use it."
        if kind == "volta":
            return f"In a terminal: `volta install {tool}@{target}`"
        if kind == "asdf":
            plugin = "nodejs" if runtime == "node" else "php"
            return f"In a terminal: `asdf install {plugin} {target}`, then `asdf uninstall {plugin} {old}`."
        if kind == "mise":
            return f"In a terminal: `mise use -g {tool}@{target}`, then `mise uninstall {tool}@{old}`."
        if kind == "snap":
            return "In a terminal: `sudo snap refresh node`"
        if kind == "distro":
            return ("Install your system's updates (`sudo apt update && sudo apt upgrade`, or "
                    "`sudo dnf upgrade`). Your distribution may have fixed this without changing "
                    "the version number; its security notices say.")
        if kind in ("mamp", "xampp", "herd", "laragon"):
            return (f"Update {how['label']} to a release that comes with {label} {target} or "
                    f"later, and stop its web server until then. {label} {target} is the "
                    f"version that fixes this.")
        if kind == "node_installer":
            return f"Download and run the {label} {target} installer (or newer) from {download}."
        if kind == "other_program":
            return (f"Update the program that keeps this copy. If you don't know which program "
                    f"that is, the folder name usually says. {label} {target} is the fixed version.")
        return f"Update it to {label} {target} or later ({download}), or remove it if you don't use it."

    # --- findings ---------------------------------------------------------------

    def _affected_finding(self, copy: dict, hits: list[dict], platform: Platform) -> Finding:
        runtime = copy["runtime"]
        label = RUNTIMES[runtime]["label"]
        how = self._install_kind(copy, platform)
        version = ".".join(str(n) for n in copy["version"])
        own_fix = fixed_version(runtime, copy["version"], hits)
        target = own_fix or upgrade_target(runtime, hits)
        step = self._upgrade_step(copy, how, target, own_fix is not None)
        cves = sorted({cve for adv in hits for cve in adv["cves"]})
        names = sorted({adv["name"] for adv in hits})
        path = self._tilde(copy["path"])
        old_copy = how["kind"] == "homebrew" and not how.get("in_use")
        what_bug = "; ".join(f"{adv['summary']} ({', '.join(adv['cves'])})" for adv in hits)
        no_fix = ("" if own_fix else
                  f"\n\n{label} {release_line(runtime, copy['version'])} no longer gets fixes, so "
                  f"there is no update for this version line; it has to move to a newer one.")
        distro = how["kind"] == "distro"
        code = "security.vulnerable_runtimes.exploited_rce"
        if old_copy:
            code = "security.vulnerable_runtimes.old_copy_affected"
            title = f"An old copy of {label} {version} with a bug attackers are using"
            lead = (f"Homebrew kept an older copy of {label} ({version}) at {path} after an update. "
                    "Nothing uses it unless a project points at it directly, but it has "
                    f"{', '.join(names)}: {what_bug}.")
        else:
            title = f"{label} {version} has a bug attackers are using now ({', '.join(names)})"
            installed = how.get("how") or f"installed with {how['label']}"
            lead = (f"The copy of {label} at {path} ({installed}) is version "
                    f"{version}. That version has {', '.join(names)}: {what_bug}. It is on the "
                    "US government's list of bugs attackers are using right now. A website or "
                    f"tool you run with this {label} can be taken over from outside.")
            if distro:
                lead += (" Linux distributions sometimes fix a bug without changing the version "
                         "number, so this one may already be fixed.")
        return Finding(
            title=title,
            description=f"{lead}{no_fix}\n\nWhat to do: {step}",
            severity=Severity.WARNING if (old_copy or distro) else Severity.CRITICAL,
            category=self.category,
            code=code,
            confidence=0.7 if distro else 0.95,
            data={
                "runtime": runtime, "version": version, "path": copy["path"],
                "real_path": copy["real_path"], "version_source": copy["version_source"],
                "installed_with": how["kind"], "installed_with_label": how["label"],
                "in_use": not old_copy, "cves": cves, "advisories": [adv["id"] for adv in hits],
                "advisory_urls": [adv["advisory"] for adv in hits],
                "kev_added": sorted({adv["kev_added"] for adv in hits}),
                "fixed_version": own_fix, "upgrade_to": target, "upgrade_step": step,
                "distro_may_backport": distro,
            },
        )

    def _unknown_finding(self, copy: dict) -> Finding:
        label = RUNTIMES[copy["runtime"]]["label"]
        return Finding(
            title=f"Couldn't tell which version of {label} this is",
            description=(
                f"There's a copy of {label} at {self._tilde(copy['path'])}, but we couldn't read "
                "its version, so we don't know whether it has the bug attackers are using now. "
                "That doesn't mean it's fine or that something is wrong."
            ),
            severity=Severity.INFO,
            category=self.category,
            code="security.vulnerable_runtimes.version_unknown",
            data={"runtime": copy["runtime"], "path": copy["path"], "real_path": copy["real_path"]},
        )

    def _inventory_finding(self, copies: list[dict]) -> Finding:
        rows = []
        for c in copies:
            version = ".".join(str(n) for n in c["version"]) if c["version"] else None
            rows.append({"runtime": c["runtime"], "version": version, "path": self._tilde(c["path"]),
                         "version_source": c["version_source"],
                         "affected_by": c.get("affected_by", [])})
        lines = [f"- {RUNTIMES[r['runtime']]['label']} {r['version'] or '(version unknown)'}: "
                 f"{r['path']}{' (affected)' if r['affected_by'] else ''}" for r in rows]
        return Finding(
            title=f"Node.js and PHP on this computer: {len(rows)} found",
            description=(
                "Every copy of Node.js and PHP we found in the usual places, with its version:\n"
                + "\n".join(lines)
                + "\n\nCopies of Node.js built into desktop apps (Slack, VS Code, Discord and "
                "others built on Electron) aren't checked here; those apps' own updates fix them."
            ),
            severity=Severity.INFO,
            category=self.category,
            code="security.vulnerable_runtimes.runtime_inventory",
            data={"copies": rows, "advisories_checked": [a["id"] for a in ADVISORIES],
                  "not_covered": ["Node.js inside Electron apps"]},
        )
