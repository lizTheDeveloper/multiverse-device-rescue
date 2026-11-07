"""endor_dependency_scan: known-bad packages in the person's code projects, using Endor Labs.

Off unless asked for. Without ``scan_projects: true`` (the dependency_scan
profile) check() only looks for code projects in the usual folders and, if
there are some, says the scan is available, what it sends to Endor Labs, and
how to run it. Nothing is run and nothing leaves the computer.

With it on, and only when Endor Labs' own command-line tool ``endorctl`` is
installed and already signed in (the person does that at Endor, with
``endorctl init``; we never see, ask for or pass a key or token), each project
is scanned in turn:

    endorctl scan --path <project> --dependencies --quick-scan --output-type json

with a time limit per project and for the whole check. Sign-in is checked first
with ``endorctl api list -r Project --page-size=1`` (exit code only), which
Endor's docs give as the way to tell. ``~/.endorctl/config.yaml`` holds the
person's credentials: its existence is checked, it is never read.

What a scan sends to Endor Labs (docs.endorlabs.com/trust-compliance/sca-scan-data):
each package's name, version, ecosystem and path in the project, the
dependencies it declares and resolves, the git ref, commit SHA and last commit
date, the repository name and clone URLs (first time), commit authors' email
addresses on the scanned branch, the computer's operating system, hardware and
build tools, and the scan's logs. Not sent: source files, manifests and lock
files. Results are kept in the person's Endor Labs account.

Look, don't touch: endorctl builds a project it can't read a lock file for
(``npm install``, a Python virtual environment, Gradle, Maven), which runs the
project's own install and build code, the very code a malicious package hides
in, and writes into the project. So only projects it can read without building
are scanned: JavaScript projects with a lock file (endorctl "uses the existing
file ... and skips the build step"). Every other project is listed as not
scanned, with Endor's command for the person to run themselves if they choose.
"""

from __future__ import annotations

import json
import os
import shutil
import time
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

# Where people keep code, under the home folder.
PROJECT_ROOTS = ["src", "code", "Code", "Projects", "projects", "Developer", "dev", "repos",
                 "workspace", "git", "GitHub"]
MAX_DEPTH = 3
# Folders looked into while finding projects, at most; and projects listed.
MAX_DIRS_VISITED = 4000
MAX_PROJECTS_FOUND = 200
# Folders that are never a project of the person's own, or are huge.
SKIP_DIRS = frozenset({"node_modules", "vendor", "venv", ".venv", "env", "dist", "build", "target",
                       "__pycache__", "Pods", "DerivedData", ".git", "site-packages", "bower_components"})

# The files that make a folder a code project, and its ecosystem.
MANIFESTS = {
    "package.json": "javascript", "requirements.txt": "python", "pyproject.toml": "python",
    "setup.py": "python", "Pipfile": "python", "go.mod": "go", "Cargo.toml": "rust",
    "pom.xml": "java", "build.gradle": "java", "build.gradle.kts": "java", "Gemfile": "ruby",
    "composer.json": "php", "packages.config": "dotnet",
}
# Lock files endorctl reads instead of building a JavaScript project.
JS_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")

AUTH_TIMEOUT = 30
PROJECT_TIMEOUT = 300
TOTAL_BUDGET = 1800
DEFAULT_MAX_SCANS = 20

INSTALL_URL = "https://docs.endorlabs.com/endorctl/install-and-configure/"
SIGNUP_URL = "https://www.endorlabs.com/get-started"
DATA_URL = "https://docs.endorlabs.com/trust-compliance/sca-scan-data"
# Stand-in filled in at run time (shown as "…" in docs/commands.md).
_PROJECT = object()
# The two commands this module runs. argv[0] is replaced by the full path of
# the endorctl found, _PROJECT by the project's folder.
AUTH_ARGS = ["endorctl", "api", "list", "-r", "Project", "--page-size=1"]
SCAN_ARGS = ["endorctl", "scan", "--path", _PROJECT, "--dependencies", "--quick-scan",
             "--output-type", "json"]

SPONSOR_NOTE = "Disclosure: Endor Labs is one of Reclaim City's sponsors."

WHAT_IS_SENT = (
    "What the scan sends to Endor Labs: the names and versions of the packages each "
    "project uses and where they're listed in it, the project's git details (branch, "
    "latest commit, repository name and web address, and the email addresses of people "
    "who made commits), and basic facts about this computer (operating system, hardware, "
    "build tools). Your code itself, and the files that list your packages, stay here. "
    f"Endor's own page on this: {DATA_URL}"
)

_LEVELS = {"FINDING_LEVEL_CRITICAL": "critical", "FINDING_LEVEL_HIGH": "high",
           "FINDING_LEVEL_MEDIUM": "medium", "FINDING_LEVEL_LOW": "low"}


class _CouldNotCheck(Exception):
    def __init__(self, reason: str, **data: Any):
        super().__init__(reason)
        self.reason = reason
        self.data = data


_COULD_NOT_CHECK = {
    "not_installed": (
        "Endor Labs' scanning tool (endorctl) isn't installed, so your projects' packages "
        f"weren't checked. Endor's install instructions: {INSTALL_URL} . Then sign in "
        "with `endorctl init` in a terminal, which opens Endor's sign-in page in your "
        "browser. Scanning from the command line needs an Endor Labs account with its own "
        f"workspace (their paid plan); you can ask them about one at {SIGNUP_URL} . "
        "Their free 'AURI for Developers' checks packages from inside AI coding tools instead."
    ),
    "not_signed_in": (
        "Endor Labs' scanning tool (endorctl) is installed but isn't signed in to an "
        "Endor Labs account here. To sign in, run `endorctl init` in a terminal; it "
        "opens Endor's sign-in page in your browser. You sign in there yourself: "
        "Reclaim City never asks for or keeps your Endor key. Scanning from the command "
        "line needs an account with its own workspace (their paid plan; "
        f"{SIGNUP_URL} )."
    ),
    "elevated": (
        "Reclaim City is running with administrator rights, and it doesn't run another "
        "company's tool that way. Run the checkup again as your normal account."
    ),
}


def _count(projects: list) -> str:
    """'12', or '200+' when the search stopped at its limit."""
    return f"{len(projects)}{'+' if len(projects) >= MAX_PROJECTS_FOUND else ''}"


def _tilde(path: str, home: Path) -> str:
    h = str(home)
    if path == h or path.startswith(h + os.sep):
        return "~" + path[len(h):]
    return path


class Module(ModuleBase):
    name = "endor_dependency_scan"
    category = "security"
    platforms = [Platform.DARWIN, Platform.LINUX, Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "about a second; when turned on, up to 5 minutes per project"

    emits_codes = [
        "security.endor_dependency_scan.scan_available",
        "security.endor_dependency_scan.could_not_check",
        "security.endor_dependency_scan.malicious_dependency",
        "security.endor_dependency_scan.vulnerable_dependencies",
        "security.endor_dependency_scan.not_scanned",
        "security.endor_dependency_scan.scan_summary",
    ]

    # Off everywhere except the dependency_scan profile: a scan sends package
    # details to Endor Labs, which the person agrees to first.
    scan_projects: bool = False
    max_scans: int = DEFAULT_MAX_SCANS
    project_timeout: int = PROJECT_TIMEOUT
    total_budget: int = TOTAL_BUDGET
    # Seams for tests: the home folder, the endorctl found (None = look on
    # PATH; "" = none), and administrator rights (None = ask the system).
    home: Path | None = None
    endorctl: str | None = None
    elevated: bool | None = None

    def configure(self, config: dict[str, Any]) -> None:
        config = config or {}
        if "scan_projects" in config:
            self.scan_projects = config["scan_projects"] is True
        for key in ("max_scans", "project_timeout", "total_budget"):
            if key in config:
                setattr(self, key, int(config[key]))
        if self.scan_projects:
            # The orchestrator's default would abandon a real scan.
            self.check_timeout = AUTH_TIMEOUT + min(
                self.total_budget, self.max_scans * self.project_timeout) + 60

    def check(self, profile: SystemProfile) -> CheckResult:
        projects = self._find_projects()
        if not projects:
            return CheckResult(module_name=self.name, findings=[])
        if not self.scan_projects:
            return CheckResult(module_name=self.name, findings=[self._available_finding(projects)])
        try:
            tool = self._signed_in_tool(profile.platform)
        except _CouldNotCheck as exc:
            return CheckResult(module_name=self.name, findings=[self._could_not_check(exc, projects)])
        return CheckResult(module_name=self.name, findings=self._scan_all(tool, projects))

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        # Changing a project's packages is the developer's call.
        return FixResult(module_name=self.name, actions=[])

    # --- finding projects ---------------------------------------------------------

    def _home(self) -> Path:
        return Path(self.home) if self.home is not None else Path.home()

    def _find_projects(self) -> list[dict[str, Any]]:
        """Folders holding a package list, at most MAX_DEPTH below the usual roots.

        A project's own sub-folders aren't searched: endorctl scans a project
        from its top folder. Hidden folders and package caches are skipped."""
        home = self._home()
        found: list[dict[str, Any]] = []
        # By device and inode: on a Mac ~/Code and ~/code are one folder.
        seen: set[tuple[int, int]] = set()
        visited = 0
        stack: list[tuple[Path, int]] = [(home / r, 0) for r in reversed(PROJECT_ROOTS)]
        while stack and len(found) < MAX_PROJECTS_FOUND and visited < MAX_DIRS_VISITED:
            folder, depth = stack.pop()
            try:
                st = folder.stat()
                if (st.st_dev, st.st_ino) in seen or not folder.is_dir():
                    continue
                seen.add((st.st_dev, st.st_ino))
                names = sorted(os.listdir(folder))
            except OSError:
                continue
            visited += 1
            ecosystems = sorted({MANIFESTS[n] for n in names if n in MANIFESTS})
            if ecosystems and depth > 0:
                found.append({"path": str(folder), "ecosystems": ecosystems,
                              "js_lockfile": next((n for n in JS_LOCKFILES if n in names), None)})
                continue
            if depth >= MAX_DEPTH:
                continue
            for name in reversed(names):
                if name.startswith(".") or name in SKIP_DIRS:
                    continue
                child = folder / name
                if child.is_dir() and not child.is_symlink():
                    stack.append((child, depth + 1))
        return found

    @staticmethod
    def _scannable(project: dict[str, Any]) -> bool:
        """Only a JavaScript project with a lock file, and nothing else to build in it."""
        return project["ecosystems"] == ["javascript"] and bool(project["js_lockfile"])

    # --- endorctl ---------------------------------------------------------------------

    def _is_elevated(self, platform: Platform) -> bool:
        if self.elevated is not None:
            return bool(self.elevated)
        if platform == Platform.WIN32:
            try:
                import ctypes

                return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
            except Exception:
                return False
        geteuid = getattr(os, "geteuid", None)
        return bool(geteuid is not None and geteuid() == 0)

    def _signed_in_tool(self, platform: Platform) -> str:
        tool = self.endorctl if self.endorctl is not None else shutil.which("endorctl")
        if not tool:
            raise _CouldNotCheck("not_installed")
        if self._is_elevated(platform):
            raise _CouldNotCheck("elevated")
        # Signed in = a saved sign-in, or the person's own Endor variables, and
        # Endor answering. The file holds credentials: it is never opened.
        config = os.environ.get("ENDOR_CONFIG_PATH") or str(self._home() / ".endorctl" / "config.yaml")
        has_env = bool(os.environ.get("ENDOR_TOKEN") or os.environ.get("ENDOR_API_CREDENTIALS_KEY"))
        if not os.path.exists(config) and not has_env:
            raise _CouldNotCheck("not_signed_in")
        result = run([tool, *AUTH_ARGS[1:]], timeout=AUTH_TIMEOUT, max_output=256 * 1024)
        if not result.ok:
            raise _CouldNotCheck("not_signed_in", exit_code=result.returncode,
                                 timed_out=result.timed_out)
        return tool

    @staticmethod
    def _snapshot(folder: Path) -> dict[str, float]:
        """The project's top-level entries and their change times, to tell if a scan wrote into it."""
        out = {}
        try:
            for entry in os.scandir(folder):
                try:
                    out[entry.name] = entry.stat(follow_symlinks=False).st_mtime
                except OSError:
                    pass
        except OSError:
            pass
        return out

    def _scan_all(self, tool: str, projects: list[dict[str, Any]]) -> list[Finding]:
        findings: list[Finding] = []
        scanned, not_scanned = [], []
        deadline = time.monotonic() + self.total_budget
        for project in projects:
            if not self._scannable(project):
                not_scanned.append({**project, "reason": "would_build"})
                continue
            if len(scanned) >= self.max_scans:
                not_scanned.append({**project, "reason": "limit"})
                continue
            left = deadline - time.monotonic()
            if left < 10:
                not_scanned.append({**project, "reason": "out_of_time"})
                continue
            folder = Path(project["path"])
            before = self._snapshot(folder)
            args = [tool, *(project["path"] if a is _PROJECT else a for a in SCAN_ARGS[1:])]
            result = run(args, timeout=min(self.project_timeout, left), cwd=project["path"])
            changed = self._snapshot(folder) != before
            if result.timed_out:
                not_scanned.append({**project, "reason": "timed_out"})
                continue
            doc = self._parse(result.stdout)
            if doc is None:
                not_scanned.append({**project, "reason": "tool_failed", "exit_code": result.returncode})
                continue
            entry = self._project_result(project, doc, changed)
            scanned.append(entry)
            findings += entry.pop("_findings")
        if scanned:
            findings.append(self._summary_finding(scanned))
        if not_scanned:
            findings.append(self._not_scanned_finding(not_scanned))
        return findings

    @staticmethod
    def _parse(stdout: str) -> dict | None:
        """endorctl's JSON: the object holding ``all_findings`` (a list), or None."""
        text = (stdout or "").strip()
        start = text.find("{")
        if start < 0:
            return None
        try:
            doc = json.loads(text[start:])
        except ValueError:
            return None
        if not isinstance(doc, dict) or not isinstance(doc.get("all_findings", []), list):
            return None
        return doc

    # --- turning endorctl's findings into ours ------------------------------------------

    @staticmethod
    def _package(f: dict) -> dict[str, Any]:
        spec = f.get("spec") if isinstance(f.get("spec"), dict) else {}
        meta = spec.get("finding_metadata") if isinstance(spec.get("finding_metadata"), dict) else {}
        aliases: list[str] = []
        for kind in ("vulnerability", "malware"):
            block = meta.get(kind) if isinstance(meta.get(kind), dict) else {}
            inner = block.get("spec") if isinstance(block.get("spec"), dict) else {}
            aliases += [a for a in inner.get("aliases") or [] if isinstance(a, str)]
        cats = [c for c in spec.get("finding_categories") or [] if isinstance(c, str)]
        name = spec.get("target_dependency_name") or spec.get("target_dependency_package_name") or ""
        return {
            "package": str(name)[:200],
            "version": str(spec.get("target_dependency_version") or "")[:60],
            "ecosystem": str(spec.get("ecosystem") or "")[:40],
            "level": _LEVELS.get(spec.get("level"), "unknown"),
            "malware": "FINDING_CATEGORY_MALWARE" in cats,
            "vulnerability": "FINDING_CATEGORY_VULNERABILITY" in cats,
            "ids": sorted(set(aliases))[:10],
            "summary": str(spec.get("summary") or (f.get("meta") or {}).get("description") or "")[:300],
            "fix_version": str(spec.get("proposed_version") or "")[:60] or None,
            "files": [str(p)[:200] for p in (spec.get("dependency_file_paths") or [])[:5]],
        }

    def _project_result(self, project: dict, doc: dict, changed: bool) -> dict[str, Any]:
        home = self._home()
        where = _tilde(project["path"], home)
        packages = [self._package(f) for f in doc.get("all_findings") or [] if isinstance(f, dict)]
        findings: list[Finding] = []
        for p in packages:
            if p["malware"]:
                findings.append(self._malicious_finding(p, project, where))
        vulns = [p for p in packages if p["vulnerability"] and not p["malware"]]
        serious = [p for p in vulns if p["level"] in ("critical", "high")]
        if serious:
            findings.append(self._vulnerable_finding(serious, project, where))
        return {"path": where, "malicious": sum(p["malware"] for p in packages),
                "serious": len(serious), "other": len(vulns) - len(serious),
                "changed_during_scan": changed, "_findings": findings}

    def _malicious_finding(self, p: dict, project: dict, where: str) -> Finding:
        named = f"{p['package']} {p['version']}".strip()
        return Finding(
            title=f"A known malicious package in {Path(project['path']).name}: {p['package']}",
            description=(
                f"Endor Labs lists {named}, which the project in {where} uses, as malicious: "
                "code made to steal from or take over the computers that install it. If "
                "you or a tool you use installed or ran this project's packages, that code "
                "may already have run here.\n\n"
                "What to do: Don't install or run this project's packages until it's "
                "removed. Remove the package from the project (and from its lock file), "
                "and delete the project's node_modules folder. If its packages were "
                "installed on this computer, treat the computer as possibly broken into: "
                "run the AI Worm & Spyware Response checkup, and from another device "
                "change the passwords and keys this computer had (code hosting, package "
                "registry, cloud accounts)."
            ),
            severity=Severity.CRITICAL,
            category=self.category,
            code="security.endor_dependency_scan.malicious_dependency",
            confidence=0.9,
            data={"project": where, "package": p["package"], "version": p["version"],
                  "ecosystem": p["ecosystem"], "ids": p["ids"], "files": p["files"],
                  "source": "Endor Labs (endorctl)"},
        )

    def _vulnerable_finding(self, serious: list[dict], project: dict, where: str) -> Finding:
        critical = any(p["level"] == "critical" for p in serious)
        names = sorted({p["package"] for p in serious})
        shown = ", ".join(names[:8]) + (f" and {len(names) - 8} more" if len(names) > 8 else "")
        return Finding(
            title=(f"{len(names)} package(s) in {Path(project['path']).name} have known "
                   "security holes"),
            description=(
                f"Endor Labs found packages with known, serious security holes in the "
                f"project in {where}: {shown}. A program built from this project can be "
                "attacked through them.\n\n"
                "What to do: Update each package to the version the finding lists as "
                "fixed (in the project's folder, for example `npm install <package>@<version>`), "
                "run the project's tests, and scan again. Endor Labs' own account page "
                "shows each problem in detail."
            ),
            severity=Severity.CRITICAL if critical else Severity.WARNING,
            category=self.category,
            code="security.endor_dependency_scan.vulnerable_dependencies",
            confidence=0.85,
            data={"project": where, "packages": [
                {k: p[k] for k in ("package", "version", "ecosystem", "level", "ids", "fix_version")}
                for p in serious[:50]], "count": len(serious), "source": "Endor Labs (endorctl)"},
        )

    def _summary_finding(self, scanned: list[dict]) -> Finding:
        lines = [f"- {s['path']}: {s['malicious']} malicious, {s['serious']} serious, "
                 f"{s['other']} minor" for s in scanned]
        changed = [s["path"] for s in scanned if s["changed_during_scan"]]
        text = ("Endor Labs scanned these projects' packages:\n" + "\n".join(lines)
                + "\n\nA scan only knows about problems that have been found and published; a "
                "clean result lowers the odds of a bad package without ruling one out.")
        if changed:
            text += ("\n\nThe scan changed files in: " + ", ".join(changed)
                     + ". Check those projects with `git status`.")
        return Finding(
            title=f"Endor Labs checked {len(scanned)} project(s)",
            description=text + f"\n\n{SPONSOR_NOTE}",
            severity=Severity.INFO,
            category=self.category,
            code="security.endor_dependency_scan.scan_summary",
            data={"projects": scanned, "changed_during_scan": changed},
        )

    def _not_scanned_finding(self, skipped: list[dict]) -> Finding:
        home = self._home()
        why = {
            "would_build": "scanning it would run the project's own install or build code",
            "limit": f"over the limit of {self.max_scans} projects per checkup",
            "out_of_time": "the checkup's time for this ran out",
            "timed_out": f"the scan took longer than {self.project_timeout // 60} minutes",
            "tool_failed": "endorctl didn't give a result",
        }
        rows = [{"path": _tilde(s["path"], home), "ecosystems": s["ecosystems"], "reason": s["reason"]}
                for s in skipped]
        lines = [f"- {r['path']}: {why[r['reason']]}" for r in rows[:30]]
        return Finding(
            title=f"{len(rows)} project(s) weren't checked",
            description=(
                "These projects' packages weren't checked, so we don't know whether they "
                "have a problem:\n" + "\n".join(lines)
                + ("\n…" if len(rows) > 30 else "")
                + "\n\nWe only scan projects Endor's tool can read without building them. "
                "For the others, endorctl runs the project's package manager or build tool, "
                "which runs the project's own code (and any bad package's). If you trust a "
                "project, you can scan it yourself in its folder with "
                "`endorctl scan --path . --dependencies`."
            ),
            severity=Severity.INFO,
            category=self.category,
            code="security.endor_dependency_scan.not_scanned",
            data={"projects": rows},
        )

    def _available_finding(self, projects: list[dict]) -> Finding:
        installed = bool(self.endorctl if self.endorctl is not None else shutil.which("endorctl"))
        scannable = sum(self._scannable(p) for p in projects)
        count = _count(projects)
        return Finding(
            title=f"{count} code project(s) here can be checked for bad packages",
            description=(
                f"We found {count} code project(s) in your usual code folders. Their "
                "packages (the code other people wrote that they use) can be checked for "
                "known malicious packages and known security holes with Endor Labs' "
                f"scanning tool, endorctl ({'installed' if installed else 'not installed'} "
                f"here). {scannable} of them can be checked without building them.\n\n"
                f"{WHAT_IS_SENT}\n\n"
                "This isn't run unless you ask: in Reclaim City's terminal tool, "
                "`rescue scan --profile dependency_scan`. It needs endorctl, signed in to "
                f"an Endor Labs account ({INSTALL_URL}).\n\n{SPONSOR_NOTE}"
            ),
            severity=Severity.INFO,
            category=self.category,
            code="security.endor_dependency_scan.scan_available",
            data={"projects_found": len(projects), "scannable": scannable,
                  "endorctl_installed": installed},
        )

    def _could_not_check(self, exc: _CouldNotCheck, projects: list[dict]) -> Finding:
        return Finding(
            title="Couldn't check your code projects' packages",
            description=(
                f"{_COULD_NOT_CHECK[exc.reason]}\n\nThis means we didn't check the "
                f"{_count(projects)} project(s) we found; it doesn't mean they're fine or that "
                f"something is wrong.\n\n{SPONSOR_NOTE}"
            ),
            severity=Severity.INFO,
            category=self.category,
            code="security.endor_dependency_scan.could_not_check",
            data={"reason": exc.reason, "projects_found": len(projects), **exc.data},
        )
