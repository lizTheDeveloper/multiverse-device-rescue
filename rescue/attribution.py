"""Who made it?  A plain-language maker line for programs named in findings.

Normal people cannot tell which processes, launch agents or apps are suspicious.
This module answers one question per program: who made it, and is that
verifiable?  It is a read-only *enrichment layer*: it never changes a finding,
it only produces ``made_by`` entries that the JSON output and the desktop app
show next to it.

Performance contract (an earlier version froze a Mac by doing heavy work during
a scan): every external command goes through :mod:`rescue.command` with a short
timeout, results are cached per path, the number of lookups per scan is capped,
and a wall-clock budget stops further lookups.  Anything over budget simply gets
no maker line.

What "verified" means: on macOS, ``codesign --verify --strict`` succeeded AND
the signature satisfies a requirement pinning Apple's anchor and the Team ID the
certificate names.  Reading the claimed signature (``codesign -dv``) alone never
yields "verified": an attacker controls that text.  Friendly names from
attribution_names.json are applied only after verification.  If verification
fails or runs out of budget, the claimed name is shown as *unverified*.
Homebrew paths and launchd label prefixes only say where something came from;
they are never "verified".

What it is: a verified maker line can also carry a short plain-language ``what``
("Loom: records your screen and camera to make video messages.") from
program_descriptions.json.  It is never matched by name or path: only the
signing Identifier (sealed in the signature and pinned in the ``--verify``
requirement) together with the verified Team ID, or Apple's own anchor for
programs that are part of macOS, selects an entry.  See :func:`describe`.
"""

from __future__ import annotations

import dataclasses
import json
import os
import plistlib
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from rescue import command

LOOKUP_TIMEOUT = 5.0
DEFAULT_MAX_LOOKUPS = 150
DEFAULT_BUDGET_SECONDS = 60.0
MAX_SUBJECTS_PER_FINDING = 6

# Finding.data keys that name a program, plist, app or bundle id.
PROGRAM_KEYS = (
    "program", "plist", "plist_path", "path", "binary", "executable", "exe",
    "app", "apps", "bundle_id", "items",
)
# Inside dict items of those lists, the keys that hold the actual path.
# "plist" comes first: a job's settings file says how the program is launched,
# so an interpreter running a script is credited to the script, not the interpreter.
_ITEM_PATH_KEYS = ("plist", "path", "program", "exe", "executable", "binary", "command")

_UNKNOWN = "Unknown maker"
_INTERPRETERS = {
    "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "python", "pythonw",
    "node", "nodejs", "deno", "bun", "ruby", "perl", "osascript", "env", "php",
    "open", "lua", "luajit", "tclsh", "wish", "awk", "gawk", "nawk", "pwsh",
    "powershell", "java", "uv", "uvx", "npx", "npm", "pnpm", "yarn", "pipx",
    "xargs", "nohup", "caffeinate", "arch", "sudo", "launchctl",
}
# "python3.12", "node22", "perl5.30", "Python3", "bash-5.2", "ruby.exe": the same
# runner under another spelling. Mac disks ignore case by default.
_VERSION_SUFFIX = re.compile(r"(?:[-_.]?\d+)*(?:\.exe)?$", re.I)


_IDENT_HASH = re.compile(r"-[0-9a-f]{16,}$", re.I)


def ident_is_interpreter(ident: str) -> bool:
    """True when a code-signing Identifier names an interpreter.

    The identifier is sealed into the signature, so renaming or copying the
    file (``cp /bin/zsh ~/updater``) doesn't change it.
    """
    if not ident:
        return False
    last = _IDENT_HASH.sub("", ident.rsplit(".", 1)[-1])
    return is_interpreter(last)


def is_interpreter(program) -> bool:
    """True when ``program`` is something that runs *other* code it is given."""
    name = os.path.basename(str(program).rstrip("/\\")).lower()
    return name in _INTERPRETERS or _VERSION_SUFFIX.sub("", name) in _INTERPRETERS
# Where the OS's own interpreters live: signed by Apple, but that says nothing
# about the script they were told to run.
_SYSTEM_BIN = ("/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/")
_BUNDLE_ID_RE = re.compile(r"^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+){2,}\Z")
# Strict reverse-DNS check applied right before a bundle id goes into any query.
_SAFE_BUNDLE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,254}\Z")
_TEAM_ID_RE = re.compile(r"^[A-Z0-9]{10}\Z")
# A signing Identifier safe to quote inside a code requirement.
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z")
_SMALL_BUNDLE_MAX_ENTRIES = 400
_SMALL_BUNDLE_MAX_BYTES = 100 * 1024 * 1024
_DEVID_RE = re.compile(r"^Authority=Developer ID Application: (.+) \(([A-Z0-9]{10})\)\s*$", re.M)
_DEVCERT_RE = re.compile(r"^Authority=Apple (?:Development|Distribution): (.+?)(?: \(([A-Z0-9]{10})\))?\s*$", re.M)

_SCRIPT_NOTE = "A script, not signed; check who created it."


_ENV_NOTE = ("Its settings change how or where the program runs, so a signed "
             "program could be running something else; check who created it.")
# The only environment settings a verified job may carry: they change language
# and time display, never which code runs. Anything else fails closed.
_SAFE_ENV = re.compile(r"^(?:LANG|LANGUAGE|LC_[A-Z]+|TZ)$")
# launchd keys that only say *when* or *how often* the program runs, or where
# its log goes. Any other key (StandardInPath, WorkingDirectory, RootDirectory,
# BundleProgram, inetdCompatibility, ...) could change what actually runs, so a
# job using one is never verified. An allowlist: unknown keys fail closed.
_SAFE_KEYS = frozenset({
    "Label", "Program", "ProgramArguments", "RunAtLoad", "KeepAlive",
    "StartInterval", "StartCalendarInterval", "WatchPaths", "QueueDirectories",
    "StartOnMount", "EnvironmentVariables", "LimitLoadToSessionType",
    "LimitLoadToHardware", "LimitLoadFromHardware", "ProcessType",
    "ThrottleInterval", "ExitTimeOut", "StandardOutPath", "StandardErrorPath",
    "Disabled", "Nice", "LowPriorityIO", "LowPriorityBackgroundIO",
    "AssociatedBundleIdentifiers", "AbandonProcessGroup", "EnableTransactions",
    "EnablePressuredExit", "POSIXSpawnType", "MachServices", "Sockets",
    "LaunchEvents", "LegacyTimers", "SoftResourceLimits", "HardResourceLimits",
})


def _injects_code(env) -> bool:
    if env is None:
        return False
    if not isinstance(env, dict):
        return True  # unreadable: assume the worst
    return any(not isinstance(k, str) or not _SAFE_ENV.match(k) for k in env)


_INLINE = object()
_INLINE_NOTE = ("Runs through an interpreter with extra options or a command "
                "written into its settings, not a signed program on its own; "
                "check who created it.")


def _interpreter_target(argv):
    """What an interpreter launch actually runs, or ``_INLINE`` when unsure.

    Deliberately conservative: a script is credited only when it immediately
    follows the interpreter (``/bin/sh /path/job.sh arg ...``). Any option
    before it (``-c``, ``-r preload.js``, ``-o``, ``-W``, ``env -S``...) can
    make something else run, so the launch is reported as unverified rather
    than borrowing the maker of a file named in its arguments. ``open`` is
    credited only as ``open [-a] /path/App.app [--args]`` with nothing after it, and
    ``env`` only as ``env [VAR=value ...] <program> ...``.
    """
    name = _VERSION_SUFFIX.sub("", os.path.basename(argv[0]).lower())
    rest = argv[1:]
    if name == "env":
        while rest and "=" in rest[0] and not rest[0].startswith("-"):
            rest = rest[1:]
        if not rest or rest[0].startswith("-"):
            return _INLINE
        if is_interpreter(rest[0]):
            return _interpreter_target(rest)
        return rest[0]
    if name == "open":
        if rest[:1] == ["-a"]:
            rest = rest[1:]
        if rest[-1:] == ["--args"]:
            rest = rest[:-1]  # a bare --args passes nothing
        if len(rest) == 1 and not rest[0].startswith("-"):
            return rest[0]
        return _INLINE
    if not rest:
        return None
    if rest[0].startswith("-"):
        return _INLINE
    return rest[0]


@dataclass(frozen=True)
class MadeBy:
    """A maker line.  Out of ``parse_codesign`` ``verified`` only means "claims a
    signature type we can check"; :meth:`Attributor._mac` makes it true only after
    ``codesign --verify`` succeeds."""

    name: str
    verified: bool
    how: str
    location_note: str = ""
    # Team ID named by the (still unverified) certificate; never serialised.
    team: str = ""
    # The signature says this program is an interpreter (com.apple.zsh,
    # org.python.python, node-<hash>...), whatever the file is called. Never serialised.
    runner: bool = False
    # Signing Identifier (bundle id) the signature claims; only set when it is
    # plain enough to pin in a code requirement. Never serialised.
    identifier: str = ""

    def to_dict(self, subject: str) -> dict:
        out = {
            "subject": subject,
            "name": self.name,
            "verified": self.verified,
            "how": self.how,
            "location_note": self.location_note,
        }
        what = describe(self)
        if what:
            out["what"] = what
        return out


def _names() -> dict:
    try:
        return json.loads((Path(__file__).parent / "attribution_names.json").read_text("utf-8"))
    except (OSError, ValueError):
        return {}


_NAMES_CACHE: dict | None = None


def _name_table() -> dict:
    global _NAMES_CACHE
    if _NAMES_CACHE is None:
        _NAMES_CACHE = _names()
    return _NAMES_CACHE


def _team_name(team: str | None, fallback: str) -> str:
    return _name_table().get("team_ids", {}).get(team or "", fallback)


# --- what it is -------------------------------------------------------------------

# program_descriptions.json team_id for Apple's own programs (parts of macOS and
# Apple's App Store apps): they have no Team ID that --verify can pin, and
# Apple's anchor plus the pinned identifier is what was verified.  Third-party
# App Store apps get no description: their certificate is Apple's, so the Team
# ID cannot be pinned the way a Developer ID one is.
_APPLE_ANCHOR = "apple"
_DESCRIPTIONS_CACHE: tuple[dict, list] | None = None


def _load_descriptions() -> tuple[dict, list]:
    """(exact {(identifier, team): text}, prefix [(identifier, team, text)])."""
    try:
        raw = json.loads((Path(__file__).parent / "program_descriptions.json").read_text("utf-8"))
        programs = raw.get("programs", [])
    except (OSError, ValueError, AttributeError):
        return {}, []
    exact: dict = {}
    prefix: list = []
    for p in programs if isinstance(programs, list) else []:
        if not isinstance(p, dict):
            continue
        ident, team, name, what = (p.get(k) for k in ("identifier", "team_id", "name", "what"))
        if not all(isinstance(v, str) and v for v in (ident, team, name, what)):
            continue
        if team != _APPLE_ANCHOR and not _TEAM_ID_RE.match(team):
            continue
        text = f"{name}: {what}"
        if p.get("match") == "prefix":
            prefix.append((ident, team, text))
        else:
            exact[(ident, team)] = text
    prefix.sort(key=lambda e: len(e[0]), reverse=True)  # most specific first
    return exact, prefix


def _description_table() -> tuple[dict, list]:
    global _DESCRIPTIONS_CACHE
    if _DESCRIPTIONS_CACHE is None:
        _DESCRIPTIONS_CACHE = _load_descriptions()
    return _DESCRIPTIONS_CACHE


def describe(made: MadeBy) -> str:
    """Plain-language "what it is" for a *verified* program, or "".

    Never by name or path: an entry matches only on the signing Identifier
    together with the Team ID that ``codesign --verify`` pinned (or Apple's
    anchor, for parts of macOS).  Anything unverified gets nothing.  A
    ``"match": "prefix"`` entry also covers helpers whose Identifier continues
    it after a dot (``com.google.Keystone`` -> ``com.google.Keystone.Agent``),
    still only for the same team.  A table lookup; no commands run.
    """
    if not made.verified or not made.identifier:
        return ""
    if made.how == "Apple system file":
        team = _APPLE_ANCHOR
    elif made.how == "Mac App Store signature" and not made.team and made.identifier.startswith("com.apple."):
        # Apple's own App Store apps (Pages, iMovie...). An App Store
        # certificate is Apple's, so no Team ID is pinned; the Apple anchor plus
        # the pinned identifier in Apple's namespace is what was verified.
        team = _APPLE_ANCHOR
    elif made.how == "Developer ID signature" and made.team:
        team = made.team
    else:
        return ""
    exact, prefix = _description_table()
    hit = exact.get((made.identifier, team))
    if hit:
        return hit
    for ident, t, text in prefix:
        if t == team and (made.identifier == ident or made.identifier.startswith(ident + ".")):
            return text
    return ""


# --- codesign parsing -------------------------------------------------------------

def parse_codesign(text: str) -> MadeBy | None:
    """Turn ``codesign -dv --verbose=2`` output into a *claimed* MadeBy (no location).

    Names are the raw certificate names; the friendly-name table is applied only
    after ``codesign --verify`` passes.
    """
    if not text:
        return None
    if "not signed at all" in text:
        return MadeBy(_UNKNOWN, False, "unsigned")
    if "Signature=adhoc" in text or "(adhoc" in text or ",adhoc" in text:
        return MadeBy(_UNKNOWN, False, "ad-hoc signed")
    team_m = re.search(r"^TeamIdentifier=([A-Z0-9]{10})\s*$", text, re.M)
    team = team_m.group(1) if team_m else None
    ident_m = re.search(r"^Identifier=(\S+)", text, re.M)
    ident = ident_m.group(1) if ident_m else ""
    # Kept only if it can be pinned verbatim in the --verify requirement.
    pinned = ident if _IDENTIFIER_RE.match(ident) else ""

    m = _DEVID_RE.search(text)
    if m:
        if team is not None and team != m.group(2):
            return MadeBy(m.group(1).strip(), False, "team ID does not match the certificate")
        return MadeBy(m.group(1).strip(), True, "Developer ID signature", team=m.group(2),
                      identifier=pinned)
    if "Authority=Software Signing" in text:
        return MadeBy("Apple", True, "Apple system file", identifier=pinned)
    if "Authority=Apple Mac OS Application Signing" in text:
        if ident.startswith("com.apple.") or team == "74J34U3R6X":
            return MadeBy("Apple", True, "Mac App Store signature", identifier=pinned)
        fallback = f"an App Store developer (team {team})" if team else "an App Store developer"
        return MadeBy(fallback, True, "Mac App Store signature", team=team or "",
                      identifier=pinned)
    m = _DEVCERT_RE.search(text)
    if m:
        return MadeBy(m.group(1).strip(), False, "development certificate")
    if "Authority=" in text:
        return MadeBy(_UNKNOWN, False, "unrecognised signature")
    return None


# --- location ---------------------------------------------------------------------

_POSIX_RISKY = (
    ("/private/var/tmp/", "/var/tmp"), ("/private/tmp/", "/tmp"),
    ("/var/tmp/", "/var/tmp"), ("/tmp/", "/tmp"), ("/dev/shm/", "/dev/shm"),
    ("/private/var/folders/", "a temporary folder"), ("/var/folders/", "a temporary folder"),
)


def location_note(path: str, platform: str) -> str:
    """Plain-language warning when ``path`` is somewhere any program can write."""
    p = path.replace("\\", "/") if platform == "win32" else path
    low = p.lower()
    if platform == "win32":
        if "/appdata/local/temp/" in low or "/windows/temp/" in low or "/temp/" in low:
            return "Runs from a temporary folder (Temp), which any program can write to."
        if "/users/public/" in low:
            return "Runs from C:\\Users\\Public, a folder every account can write to."
        if "/downloads/" in low:
            return "Runs from your Downloads folder, where files from the internet land."
        return ""
    for prefix, shown in _POSIX_RISKY:
        if p.startswith(prefix) or p == prefix.rstrip("/"):
            if shown.startswith("a "):
                return "Runs from a temporary folder, which any program can write to."
            return f"Runs from {shown}, a temporary folder any program can write to."
    if p.startswith("/Users/Shared/"):
        return "Runs from /Users/Shared, a folder every account on this computer can write to."
    if "/Downloads/" in p:
        return "Runs from your Downloads folder, where files from the internet land."
    return ""


def _world_writable(path: str) -> bool:
    try:
        return bool(os.stat(path).st_mode & stat.S_IWOTH)
    except OSError:
        return False


# --- the attributor ---------------------------------------------------------------

class Attributor:
    """Identifies makers with a per-path cache, a lookup cap and a time budget."""

    def __init__(
        self,
        platform: str,
        *,
        run=None,
        max_lookups: int = DEFAULT_MAX_LOOKUPS,
        budget_seconds: float = DEFAULT_BUDGET_SECONDS,
        applications_dirs: list[str] | None = None,
        distro: str | None = None,
    ):
        self.platform = platform
        self._run = run or command.run
        self.max_lookups = max_lookups
        self.lookups = 0
        self.skipped = 0
        self._deadline = time.monotonic() + budget_seconds
        self._cache: dict[str, MadeBy | None] = {}
        self._app_dirs = applications_dirs
        self._bundle_index: dict[str, str] | None = None
        self._distro = distro

    # budget ----------------------------------------------------------------
    def _can_lookup(self) -> bool:
        return self.lookups < self.max_lookups and time.monotonic() < self._deadline

    def _exec(self, args: list[str]):
        """Run one bounded command; None if out of budget or it failed."""
        if not self._can_lookup():
            return None
        self.lookups += 1
        try:
            res = self._run(args, timeout=LOOKUP_TIMEOUT)
        except Exception:
            return None
        if getattr(res, "timed_out", False):
            return None
        return res

    # public ----------------------------------------------------------------
    def identify(self, path_or_label: str, exists=os.path.exists) -> MadeBy | None:
        """Return who made ``path_or_label`` (a path, plist, bundle id or label)."""
        subject = (path_or_label or "").strip()
        if not subject:
            return None
        if subject in self._cache:
            return self._cache[subject]
        if not self._can_lookup():
            self.skipped += 1
            return None
        try:
            result = self._identify(subject, exists)
        except Exception:
            result = None
        self._cache[subject] = result
        return result

    # internals -------------------------------------------------------------
    def _identify(self, subject: str, exists) -> MadeBy | None:
        for prefix, what in _name_table().get("label_prefixes", {}).items():
            if subject.startswith(prefix):
                # A label is just text any program can pick; say so, never "verified".
                return MadeBy(f"{what} {subject[len(prefix):]}", False,
                              "named like a Homebrew service; the program itself was not checked")
        path = subject
        if self.platform == "darwin" and "/" not in subject and "\\" not in subject and not subject.endswith(".plist"):
            path = self._resolve_app(subject, exists)
            if path is None:
                return None
        path = os.path.expanduser(path)
        if not exists(path):
            return None
        if path.endswith(".plist") and self.platform == "darwin":
            return self._identify_plist(path, exists)
        return self._identify_program(path)

    def _identify_plist(self, plist_path: str, exists) -> MadeBy | None:
        try:
            with open(plist_path, "rb") as fh:
                data = plistlib.load(fh)
        except Exception:
            return None
        if not isinstance(data, dict):
            return None
        program = data.get("Program")
        args = data.get("ProgramArguments")
        if args is None:
            args = []
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            return MadeBy(_UNKNOWN, False, "unreadable settings", _INLINE_NOTE)
        if program is None and args:
            program = args[0]
        if not isinstance(program, str) or not program:
            return None
        # launchd neither expands "~" nor searches our working folder: a program
        # that isn't a full path could be anything, so nothing is credited.
        if not program.startswith("/"):
            return MadeBy(_UNKNOWN, False, "program not named by full path", _INLINE_NOTE)
        if _injects_code(data.get("EnvironmentVariables")) or any(
            not isinstance(k, str) or k not in _SAFE_KEYS for k in data
        ):
            return MadeBy(_UNKNOWN, False, "settings change how the program loads code", _ENV_NOTE)
        # With both keys set, launchd runs Program and passes ProgramArguments
        # as argv, so argv[1:] is what the program is told to do.
        extra = args[1:]
        # By name, by the file a link points to, or (below) by signature.
        if is_interpreter(program) or (exists(program) and is_interpreter(os.path.realpath(program))):
            return self._through_interpreter(program, extra, exists)
        if not exists(program):
            return None
        made = self._identify_program(program)
        if made is not None and made.runner:
            # A renamed copy of an interpreter: its signature still says so.
            # Even with no arguments it can read code from rc files, so never verified.
            if extra:
                return self._through_interpreter(program, extra, exists)
            return dataclasses.replace(made, verified=False, how="inline command",
                                       location_note=_INLINE_NOTE)
        if made is not None and extra and made.verified:
            # A signature vouches for the file, not for what the job tells it to
            # do: arguments can steer even an ordinary program, so fail closed.
            made = dataclasses.replace(made, verified=False, how="started with extra instructions")
        return made

    def _through_interpreter(self, program: str, extra: list[str], exists) -> MadeBy | None:
        """Credit what an interpreter is told to run, never the interpreter itself."""
        # Treat the program as its real interpreter name so env/open rules apply.
        real = os.path.basename(os.path.realpath(program)) if exists(program) else os.path.basename(program)
        target = _interpreter_target([real] + extra)
        if target is _INLINE:
            return MadeBy(_UNKNOWN, False, "inline command", _INLINE_NOTE)
        target = os.path.expanduser(target) if target else None
        if target and os.path.isabs(target) and exists(target):
            made = self._identify_program(target)
            if made is not None and made.runner:
                # "zsh /bin/bash -c ..." style chains: don't follow, don't credit.
                return MadeBy(_UNKNOWN, False, "inline command", _INLINE_NOTE)
            return made
        # Never credit the interpreter's maker (Apple, Python, Node...) for a
        # script or command we could not find.
        return None

    def _identify_program(self, path: str) -> MadeBy | None:
        note = location_note(path, self.platform)
        if not note and self.platform != "win32" and os.path.isfile(path) and _world_writable(path):
            note = "This file can be changed by any program on the computer."
        made = self._signature_for(path)
        if made is None:
            return None
        if note:
            joined = f"{made.location_note} {note}".strip()
            made = dataclasses.replace(made, location_note=joined)
        return made

    def _signature_for(self, path: str) -> MadeBy | None:
        if self.platform == "darwin":
            return self._mac(path)
        if self.platform == "win32":
            return self._windows(path)
        return self._linux(path)

    # macOS -----------------------------------------------------------------
    def _mac(self, path: str) -> MadeBy | None:
        # Resolve "..", symlinks and the like first: a name such as
        # "X.app/Contents/../../evil" points outside the bundle, and checking
        # the bundle's signature would credit its maker for that file.
        path = os.path.realpath(path)
        brew_re = r"^(?:/opt/homebrew|/usr/local)/(?:Cellar|opt)/([^/]+)"
        brew = re.match(brew_re, path) and re.match(brew_re, os.path.realpath(path))
        if brew:
            # Homebrew binaries are usually unsigned and the folder is writable by
            # the user, so this says where it lives, not who made it.
            return MadeBy(f"Homebrew package {brew.group(1)}", False,
                          "installed in Homebrew's folder; not signature-checked")
        if _is_script(path):
            return MadeBy(_UNKNOWN, False, "script", _SCRIPT_NOTE)
        target = path
        bundle = re.search(r"\.app[\\/]", path)
        if bundle:
            target = path[: bundle.start() + 4]
        res = self._exec(["codesign", "-dv", "--verbose=2", "--", target])
        if res is None:
            return None
        text = (res.stderr or "") + "\n" + (res.stdout or "")
        claimed = parse_codesign(text)
        if claimed is not None and claimed.verified:
            claimed = self._verify_signature(claimed, target)
        ident_m = re.search(r"^Identifier=(\S+)", text, re.M)
        if claimed is not None and ident_m and ident_is_interpreter(ident_m.group(1)):
            claimed = dataclasses.replace(claimed, runner=True)
        return claimed

    def _verify_signature(self, claimed: MadeBy, target: str) -> MadeBy:
        """Upgrade a claimed signature to verified only if codesign validates it."""
        requirement = _requirement_for(claimed)
        if requirement is not None:
            args = ["codesign", "--verify", "--strict"]
            if _small_bundle(target):
                args.append("--deep")
            args += [f"-R={requirement}", "--", target]
            res = self._exec(args)
            if res is not None and res.ok:
                return MadeBy(_team_name(claimed.team, claimed.name), True, claimed.how,
                              team=claimed.team, identifier=claimed.identifier)
        return MadeBy(
            claimed.name, False,
            f"claims to be made by {claimed.name}; couldn't verify",
        )

    def _resolve_app(self, ident: str, exists) -> str | None:
        """Bundle id (or app name) -> .app path, read-only."""
        if _BUNDLE_ID_RE.match(ident):
            # Cheapest first: read the Info.plists in /Applications (no process).
            found = self._index().get(ident)
            if found:
                return found
            if not _SAFE_BUNDLE_ID_RE.match(ident):
                return None
            res = self._exec(["mdfind", f"kMDItemCFBundleIdentifier == '{ident}'"])
            if res is not None and getattr(res, "stdout", ""):
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if line.endswith(".app") and exists(line):
                        return line
            return None
        name = ident if ident.endswith(".app") else f"{ident}.app"
        for d in self._applications_dirs():
            cand = os.path.join(d, name)
            if exists(cand):
                return cand
        return None

    def _applications_dirs(self) -> list[str]:
        if self._app_dirs is not None:
            return self._app_dirs
        return ["/Applications", os.path.expanduser("~/Applications")]

    def _index(self) -> dict[str, str]:
        if self._bundle_index is None:
            index: dict[str, str] = {}
            for d in self._applications_dirs():
                try:
                    names = sorted(os.listdir(d))[:600]
                except OSError:
                    continue
                for n in names:
                    if not n.endswith(".app"):
                        continue
                    try:
                        with open(os.path.join(d, n, "Contents", "Info.plist"), "rb") as fh:
                            bid = plistlib.load(fh).get("CFBundleIdentifier")
                    except Exception:
                        continue
                    if bid:
                        index.setdefault(bid, os.path.join(d, n))
            self._bundle_index = index
        return self._bundle_index

    # Windows ---------------------------------------------------------------
    def _windows(self, path: str) -> MadeBy | None:
        # PowerShell treats the typographic single quotes as quotes too.
        quoted = re.sub("['\u2018\u2019\u201a\u201b]", lambda m: m.group(0) * 2, path)
        script = (
            f"$s = Get-AuthenticodeSignature -LiteralPath '{quoted}'; "
            "@{Status=[string]$s.Status; Subject=$s.SignerCertificate.Subject} | ConvertTo-Json -Compress"
        )
        res = self._exec(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])
        if res is None:
            return None
        try:
            info = json.loads(res.stdout)
        except (ValueError, TypeError):
            return None
        status = str(info.get("Status", ""))
        subject = info.get("Subject") or ""
        cn = re.search(r'CN=("[^"]+"|[^,]+)', subject)
        org = re.search(r'O=("[^"]+"|[^,]+)', subject)
        name = ((cn or org).group(1).strip('"').strip()) if (cn or org) else _UNKNOWN
        if status == "Valid":
            return MadeBy(name, True, "Authenticode signature")
        if status == "NotSigned":
            return MadeBy(_UNKNOWN, False, "unsigned")
        if status == "HashMismatch":
            return MadeBy(name, False, "signature does not match the file (changed after signing)")
        if status in ("NotTrusted", "UnknownError", "Incompatible"):
            return MadeBy(name if subject else _UNKNOWN, False, "untrusted signature")
        return None

    # Linux -----------------------------------------------------------------
    def _distro_name(self) -> str:
        if self._distro is None:
            self._distro = "System"
            try:
                for line in Path("/etc/os-release").read_text("utf-8").splitlines():
                    if line.startswith("NAME="):
                        self._distro = line.split("=", 1)[1].strip().strip('"').split()[0]
                        break
            except OSError:
                pass
        return self._distro

    def _linux(self, path: str) -> MadeBy | None:
        if _is_script(path):
            return MadeBy(_UNKNOWN, False, "script", _SCRIPT_NOTE)
        res = self._exec(["dpkg", "-S", "--", path])
        pkg = None
        if res is not None and res.ok and ":" in (res.stdout or ""):
            pkg = res.stdout.splitlines()[0].split(":", 1)[0].split(",")[0].strip()
        else:
            res = self._exec(["rpm", "-qf", "--", path])
            if res is not None and res.ok and (res.stdout or "").strip():
                pkg = res.stdout.splitlines()[0].strip()
        if pkg:
            return MadeBy(f"{self._distro_name()} package {pkg}", True, "system package")
        return MadeBy(_UNKNOWN, False, "not part of any installed package")


def _requirement_for(claimed: MadeBy) -> str | None:
    """Code requirement that pins Apple's anchor (and the Team ID) for ``claimed``.

    The signing Identifier is pinned too, so the identifier a description is
    keyed on is the one this same check verified.
    """
    ident_clause = ""
    if claimed.identifier:
        if not _IDENTIFIER_RE.match(claimed.identifier):
            return None
        ident_clause = f'identifier "{claimed.identifier}" and '
    req = _anchor_requirement(claimed)
    return ident_clause + req if req else None


def _anchor_requirement(claimed: MadeBy) -> str | None:
    if claimed.how == "Apple system file":
        return "anchor apple"
    team_clause = ""
    if claimed.team:
        if not _TEAM_ID_RE.match(claimed.team):
            return None
        team_clause = f' and certificate leaf[subject.OU] = "{claimed.team}"'
    if claimed.how == "Developer ID signature":
        if not team_clause:
            return None
        return (
            "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists"
            " and certificate leaf[field.1.2.840.113635.100.6.1.13] exists" + team_clause
        )
    if claimed.how == "Mac App Store signature":
        return (
            "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists"
            + team_clause
        )
    return None


def _small_bundle(path: str) -> bool:
    """True if ``path`` is small enough for ``codesign --deep`` within the timeout."""
    if not os.path.isdir(path):
        return False
    entries = 0
    total = 0
    stack = [path]
    try:
        while stack:
            with os.scandir(stack.pop()) as it:
                for e in it:
                    entries += 1
                    if entries > _SMALL_BUNDLE_MAX_ENTRIES:
                        return False
                    if e.is_dir(follow_symlinks=False):
                        stack.append(e.path)
                    else:
                        total += e.stat(follow_symlinks=False).st_size
                        if total > _SMALL_BUNDLE_MAX_BYTES:
                            return False
    except OSError:
        return False
    return True


def _is_script(path: str) -> bool:
    try:
        if not os.path.isfile(path):
            return False
        with open(path, "rb") as fh:
            return fh.read(2) == b"#!"
    except OSError:
        return False


# --- module-level convenience -----------------------------------------------------

_DEFAULT: dict[str, Attributor] = {}


def identify(path_or_label: str, platform: str) -> MadeBy | None:
    """Identify one subject with a shared per-platform cache and budget."""
    att = _DEFAULT.get(platform)
    if att is None:
        att = _DEFAULT[platform] = Attributor(platform)
    return att.identify(path_or_label)


# --- finding enrichment -----------------------------------------------------------

def _looks_like_subject(s: str) -> bool:
    if not s or len(s) > 1024 or "\n" in s:
        return False
    if s.startswith(("/", "~")) or re.match(r"^[A-Za-z]:[\\/]", s):
        return True
    return bool(_BUNDLE_ID_RE.match(s)) or s.endswith(".app")


def _candidates(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        for k in _ITEM_PATH_KEYS:
            v = value.get(k)
            if isinstance(v, str) and v:
                if k == "command" and not os.path.exists(v):
                    v = v.split(" ", 1)[0]  # a command line: keep the program
                return [v]
        return []
    if isinstance(value, (list, tuple)):
        out: list[str] = []
        for item in value:
            out.extend(_candidates(item))
        return out
    return []


def subjects_for_finding(finding) -> list[str]:
    """Programs a finding names, in order, deduplicated and capped."""
    data = getattr(finding, "data", None) or {}
    seen: list[str] = []
    for key in PROGRAM_KEYS:
        if key not in data:
            continue
        for cand in _candidates(data[key]):
            if _looks_like_subject(cand) and cand not in seen:
                seen.append(cand)
                if len(seen) >= MAX_SUBJECTS_PER_FINDING:
                    return seen
    return seen


def compute_made_by(
    results,
    platform: str,
    *,
    max_lookups: int = DEFAULT_MAX_LOOKUPS,
    attributor: Attributor | None = None,
) -> dict[int, list[dict]]:
    """Map ``id(finding)`` -> list of made_by dicts for every attributable finding."""
    att = attributor or Attributor(platform, max_lookups=max_lookups)
    out: dict[int, list[dict]] = {}
    for _mod, check in results:
        for finding in getattr(check, "findings", []) or []:
            entries = []
            for subject in subjects_for_finding(finding):
                try:
                    made = att.identify(subject)
                except Exception:
                    made = None
                if made is not None:
                    entries.append(made.to_dict(subject))
            if entries:
                out[id(finding)] = entries
    return out
