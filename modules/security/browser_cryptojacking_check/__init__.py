"""Detect in-browser cryptojacking (drive-by mining).

Not all mining runs as a native process. A browser extension — or a page the
browser is forced to open at startup — can mine continuously for as long as
the browser is open, which on most people's machines is all day. Process-level
miner detection never sees it, because the process doing the work is Chrome.

This module reads browser extension manifests and startup settings looking for
mining libraries and mining service endpoints, and checks whether the hosts
file has been made to resolve a mining domain somewhere unexpected.
"""

import json
from pathlib import Path

from rescue.models import (
    Action,
    ActionKind,
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
from rescue.runtime import content_directory, load_content_module

_IOC_DIR = content_directory("modules/security/cryptojacking_iocs")
_IOC_LOADER_KEY = "rescue_cryptojacking_iocs_loader"

# Bounds on read-only filesystem work.
_MAX_EXTENSIONS_PER_BROWSER = 300
_MAX_FILES_PER_EXTENSION = 40
_MAX_READ_BYTES = 512 * 1024
# JSON config files are parsed whole rather than sampled, so they get their own
# (larger) ceiling — a Chrome Preferences file is often several megabytes.
_MAX_JSON_BYTES = 16 * 1024 * 1024

# Addresses that mean "block this domain" rather than "send me here". A hosts
# entry pointing a mining domain at one of these is a protection, not a threat.
_BLACKHOLE_ADDRESSES = {"0.0.0.0", "127.0.0.1", "::", "::1"}

_CHROMIUM_PROFILE_ROOTS = {
    Platform.DARWIN: [
        "~/Library/Application Support/Google/Chrome",
        "~/Library/Application Support/Microsoft Edge",
        "~/Library/Application Support/BraveSoftware/Brave-Browser",
        "~/Library/Application Support/Chromium",
        "~/Library/Application Support/Vivaldi",
    ],
    Platform.WIN32: [
        "~/AppData/Local/Google/Chrome/User Data",
        "~/AppData/Local/Microsoft/Edge/User Data",
        "~/AppData/Local/BraveSoftware/Brave-Browser/User Data",
        "~/AppData/Local/Chromium/User Data",
    ],
    Platform.LINUX: [
        "~/.config/google-chrome",
        "~/.config/chromium",
        "~/.config/microsoft-edge",
        "~/.config/BraveSoftware/Brave-Browser",
    ],
}

_FIREFOX_PROFILE_ROOTS = {
    Platform.DARWIN: ["~/Library/Application Support/Firefox/Profiles"],
    Platform.WIN32: ["~/AppData/Roaming/Mozilla/Firefox/Profiles"],
    Platform.LINUX: ["~/.mozilla/firefox"],
}

_HOSTS_FILES = {
    Platform.DARWIN: "/etc/hosts",
    Platform.LINUX: "/etc/hosts",
    Platform.WIN32: r"C:\Windows\System32\drivers\etc\hosts",
}

# Files inside an extension worth reading. Mining code lives in the background
# worker or a content script, never in the icons.
_SCANNABLE_SUFFIXES = {".js", ".json", ".html"}


def _load_iocs():
    """Load the shared cryptojacking IOC database, or None if unavailable."""
    loader = load_content_module(
        "modules/security/cryptojacking_iocs/loader.py", _IOC_LOADER_KEY
    )
    if loader is None:
        return None
    try:
        return loader.load_cryptojacking_iocs(_IOC_DIR)
    except Exception:
        return None


_IOCS = _load_iocs()


class Module(ModuleBase):
    name = "browser_cryptojacking_check"
    category = "security"
    platforms = [Platform.DARWIN, Platform.WIN32, Platform.LINUX]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "20s"

    def check(self, profile: SystemProfile) -> CheckResult:
        if _IOCS is None:
            return CheckResult(
                module_name=self.name,
                error="Cryptojacking indicator data could not be loaded.",
            )

        findings: list[Finding] = []
        findings.extend(self._check_chromium_extensions(profile.platform))
        findings.extend(self._check_firefox_extensions(profile.platform))
        findings.extend(self._check_startup_pages(profile.platform))
        findings.extend(self._check_hosts_file(profile.platform))
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Guidance only — this module never edits browser or system files."""
        actions: list[Action] = []

        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "mining_extension":
                name = finding.data.get("extension_name", "the extension")
                browser = finding.data.get("browser", "your browser")
                actions.append(
                    Action(
                        title=f"Remove the mining extension '{name}' from {browser}",
                        description=(
                            f"{finding.description}\n\n"
                            f"1. Open {browser}'s extensions page and remove '{name}'.\n"
                            "2. Check every browser profile — extensions are per-profile, "
                            "and a second profile you rarely use keeps mining.\n"
                            "3. Check whether the extension was installed by policy "
                            "(it will say 'Installed by your administrator' and cannot "
                            "simply be removed). If it was, something with admin rights "
                            "put it there and the machine needs a deeper clean.\n"
                            "4. Sign out of browser sync while cleaning up, or the "
                            "extension can be re-synced back onto the machine."
                        ),
                        risk_level=RiskLevel.MODERATE,
                        kind=ActionKind.GUIDANCE,
                        success=True,
                        data={"extension_name": name, "browser": browser},
                    )
                )
            elif check == "mining_startup_page":
                actions.append(
                    Action(
                        title="Reset the browser's startup and homepage settings",
                        description=(
                            f"{finding.description}\n\n"
                            "Open the browser's settings and reset 'On startup', "
                            "homepage, and search engine to what you actually want. "
                            "If the setting will not stick, an extension or a device "
                            "management policy is re-applying it."
                        ),
                        risk_level=RiskLevel.MODERATE,
                        kind=ActionKind.GUIDANCE,
                        success=True,
                    )
                )
            elif check == "mining_hosts_entry":
                actions.append(
                    Action(
                        title="Remove the mining entry from the hosts file",
                        description=(
                            f"{finding.description}\n\n"
                            "Editing the hosts file requires administrator rights, so "
                            "whoever added this had them. Remove the line, then work "
                            "out how they got that access before considering this "
                            "closed."
                        ),
                        risk_level=RiskLevel.MODERATE,
                        kind=ActionKind.GUIDANCE,
                        success=True,
                    )
                )

        if findings.findings:
            actions.append(
                Action(
                    title="Install a content blocker to stop drive-by mining",
                    description=(
                        "Browser mining is usually delivered by a compromised or "
                        "ad-supported page. A reputable content blocker (uBlock Origin "
                        "or the browser's own tracking protection set to strict) blocks "
                        "the mining endpoints outright, which is a durable fix rather "
                        "than a one-time cleanup."
                    ),
                    risk_level=RiskLevel.SAFE,
                    kind=ActionKind.GUIDANCE,
                    success=True,
                )
            )

        return FixResult(module_name=self.name, actions=actions)

    # ---------------- Chromium-family ----------------

    def _check_chromium_extensions(self, platform: Platform) -> list[Finding]:
        findings: list[Finding] = []
        for root in _CHROMIUM_PROFILE_ROOTS.get(platform, []):
            base = Path(root).expanduser()
            browser = base.name
            scanned = 0
            for version_dir in _extension_version_dirs(base):
                if scanned >= _MAX_EXTENSIONS_PER_BROWSER:
                    break
                scanned += 1
                finding = self._inspect_extension_dir(version_dir, browser)
                if finding is not None:
                    findings.append(finding)
        return findings

    def _inspect_extension_dir(self, version_dir: Path, browser: str) -> Finding | None:
        manifest = _read_json(version_dir / "manifest.json")
        name = _extension_name(manifest, version_dir)

        hit = self._match_known_extension(name)
        if hit is None:
            hit = self._scan_extension_files(version_dir)
        if hit is None:
            return None

        return Finding(
            title=f"Browser extension appears to mine cryptocurrency: {name}",
            description=(
                f"The {browser} extension '{name}' {hit['detail']}. An extension with "
                "mining code runs for as long as the browser is open, which is why the "
                "machine stays hot and slow even when it looks idle."
            ),
            severity=hit["severity"],
            category=self.category,
            data={
                "check": "mining_extension",
                "browser": browser,
                "extension_name": name,
                "extension_id": version_dir.parent.name,
                "path": str(version_dir),
                "indicator": hit["indicator"],
                "evidence": hit["evidence"],
                "confidence": hit["confidence"],
            },
        )

    def _scan_extension_files(self, version_dir: Path) -> dict | None:
        """Read a bounded sample of an extension's code looking for miners."""
        scanned = 0
        for path in _bounded_walk(version_dir, _MAX_FILES_PER_EXTENSION):
            if path.suffix.lower() not in _SCANNABLE_SUFFIXES:
                continue
            scanned += 1
            content = _read_text(path)
            if not content:
                continue
            hit = self._match_content(content)
            if hit is not None:
                hit["detail"] += f" (found in {path.name})"
                return hit
        return None

    # ---------------- Firefox ----------------

    def _check_firefox_extensions(self, platform: Platform) -> list[Finding]:
        findings: list[Finding] = []
        for root in _FIREFOX_PROFILE_ROOTS.get(platform, []):
            base = Path(root).expanduser()
            if not _is_dir(base):
                continue
            for profile_dir in _bounded_dirs(base, 20):
                data = _read_json(profile_dir / "extensions.json")
                for addon in (data.get("addons") or [])[:_MAX_EXTENSIONS_PER_BROWSER]:
                    name = _firefox_addon_name(addon)
                    hit = self._match_known_extension(name)
                    if hit is None:
                        continue
                    findings.append(
                        Finding(
                            title=f"Browser extension appears to mine cryptocurrency: {name}",
                            description=(
                                f"The Firefox add-on '{name}' {hit['detail']}. Remove it "
                                "from about:addons."
                            ),
                            severity=hit["severity"],
                            category=self.category,
                            data={
                                "check": "mining_extension",
                                "browser": "Firefox",
                                "extension_name": name,
                                "extension_id": addon.get("id", ""),
                                "path": str(profile_dir),
                                "indicator": hit["indicator"],
                                "evidence": hit["evidence"],
                                "confidence": hit["confidence"],
                            },
                        )
                    )
        return findings

    # ---------------- startup pages ----------------

    def _check_startup_pages(self, platform: Platform) -> list[Finding]:
        findings: list[Finding] = []
        for root in _CHROMIUM_PROFILE_ROOTS.get(platform, []):
            base = Path(root).expanduser()
            if not _is_dir(base):
                continue
            for profile_dir in _bounded_dirs(base, 20):
                prefs = _read_json(profile_dir / "Preferences")
                if not prefs:
                    continue
                urls = list(
                    (prefs.get("session", {}) or {}).get("startup_urls", []) or []
                )
                homepage = prefs.get("homepage")
                if isinstance(homepage, str):
                    urls.append(homepage)
                for url in urls:
                    hit = self._match_content(str(url))
                    if hit is None:
                        continue
                    findings.append(
                        Finding(
                            title="Browser is set to open a cryptomining page at startup",
                            description=(
                                f"{base.name} profile '{profile_dir.name}' opens {url} "
                                "automatically. That page hosts mining code, so the "
                                "browser starts mining as soon as it is launched."
                            ),
                            severity=Severity.CRITICAL,
                            category=self.category,
                            data={
                                "check": "mining_startup_page",
                                "browser": base.name,
                                "profile": profile_dir.name,
                                "url": str(url),
                                "indicator": hit["indicator"],
                                "evidence": hit["evidence"],
                                "confidence": "high",
                            },
                        )
                    )
        return findings

    # ---------------- hosts file ----------------

    def _check_hosts_file(self, platform: Platform) -> list[Finding]:
        hosts_path = _HOSTS_FILES.get(platform)
        if hosts_path is None:
            return []
        content = _read_text(Path(hosts_path))
        if not content:
            return []

        findings: list[Finding] = []
        for line in content.splitlines():
            stripped = line.split("#", 1)[0].strip()
            if not stripped:
                continue
            parts = stripped.split()
            if len(parts) < 2:
                continue
            address, hostnames = parts[0], parts[1:]
            if address in _BLACKHOLE_ADDRESSES:
                # A blocklist entry — this is someone protecting the machine.
                continue
            for hostname in hostnames:
                domain = self._match_mining_domain(hostname)
                if domain is None:
                    continue
                findings.append(
                    Finding(
                        title=f"Hosts file points {hostname} at {address}",
                        description=(
                            f"The hosts file redirects {hostname}, a cryptomining "
                            f"service, to {address} instead of blocking it. Someone "
                            "with administrator rights edited this file to keep mining "
                            "traffic flowing even if the public service is blocked."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        data={
                            "check": "mining_hosts_entry",
                            "hostname": hostname,
                            "address": address,
                            "path": str(hosts_path),
                            "confidence": "high",
                        },
                    )
                )
        return findings

    # ---------------- matching ----------------

    def _match_known_extension(self, name: str) -> dict | None:
        lowered = (name or "").lower()
        if not lowered:
            return None
        for extension in _IOCS.browser_extensions:
            if extension.name.lower() in lowered:
                return {
                    "indicator": "known_mining_extension",
                    "severity": _severity(extension.severity),
                    "confidence": "medium",
                    "detail": f"matches a known mining extension — {extension.description}",
                    "evidence": extension.name,
                }
        return None

    def _match_content(self, content: str) -> dict | None:
        lowered = content.lower()
        for domain in _IOCS.browser_script_domains:
            if domain.value.lower() in lowered:
                return {
                    "indicator": "mining_service_endpoint",
                    "severity": _severity(domain.severity),
                    "confidence": "high",
                    "detail": f"contains a reference to {domain.value} — {domain.description}",
                    "evidence": domain.value,
                }
        for marker in _IOCS.browser_script_markers:
            if marker.value.lower() in lowered:
                return {
                    "indicator": "mining_library_call",
                    "severity": _severity(marker.severity),
                    "confidence": "medium",
                    "detail": f"contains the mining library call {marker.value} — {marker.description}",
                    "evidence": marker.value,
                }
        return None

    def _match_mining_domain(self, hostname: str) -> str | None:
        lowered = hostname.lower()
        for domain in _IOCS.browser_script_domains:
            if domain.value.lower() in lowered:
                return domain.value
        for pool in _IOCS.pools:
            if pool.domain.lower() in lowered:
                return pool.domain
        return None


# ---------------- helpers ----------------


def _severity(value: str) -> Severity:
    return Severity.CRITICAL if value == "critical" else Severity.WARNING


def _is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _bounded_dirs(base: Path, limit: int) -> list[Path]:
    try:
        if not base.is_dir():
            return []
        return [p for p in sorted(base.iterdir()) if _is_dir(p)][:limit]
    except OSError:
        return []


def _extension_version_dirs(base: Path) -> list[Path]:
    """Return <profile>/Extensions/<id>/<version> directories under a browser root."""
    version_dirs: list[Path] = []
    for profile_dir in _bounded_dirs(base, 20):
        extensions_dir = profile_dir / "Extensions"
        for extension_dir in _bounded_dirs(extensions_dir, _MAX_EXTENSIONS_PER_BROWSER):
            version_dirs.extend(_bounded_dirs(extension_dir, 5))
    return version_dirs


def _bounded_walk(base: Path, limit: int) -> list[Path]:
    """Return up to ``limit`` files from ``base``, one level of subdirectories."""
    files: list[Path] = []
    try:
        if not base.is_dir():
            return files
        for path in sorted(base.iterdir()):
            if len(files) >= limit:
                return files
            if path.is_file():
                files.append(path)
            elif path.is_dir():
                for child in sorted(path.iterdir()):
                    if len(files) >= limit:
                        return files
                    if child.is_file():
                        files.append(child)
    except OSError:
        return files
    return files


def _read_text(path: Path) -> str:
    try:
        if not path.is_file():
            return ""
        if path.stat().st_size > _MAX_READ_BYTES * 8:
            return ""
        with open(path, "r", errors="replace") as f:
            return f.read(_MAX_READ_BYTES)
    except (OSError, ValueError):
        return ""


def _read_json(path: Path) -> dict:
    """Read a JSON config file whole, within a size limit.

    Unlike the code scan, this cannot use the truncating reader: a browser's
    Preferences file routinely exceeds the code-scan read limit, and half a
    JSON document parses as nothing at all.
    """
    try:
        if not path.is_file() or path.stat().st_size > _MAX_JSON_BYTES:
            return {}
        with open(path, "r", errors="replace") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _extension_name(manifest: dict, version_dir: Path) -> str:
    name = manifest.get("name", "")
    # Chrome stores localised names as "__MSG_appName__"; fall back to the
    # extension ID, which is still enough for the user to find it.
    if not isinstance(name, str) or not name or name.startswith("__MSG_"):
        return version_dir.parent.name
    return name


def _firefox_addon_name(addon: dict) -> str:
    default_locale = addon.get("defaultLocale") or {}
    name = default_locale.get("name") if isinstance(default_locale, dict) else None
    if isinstance(name, str) and name:
        return name
    return str(addon.get("id", "unknown add-on"))
