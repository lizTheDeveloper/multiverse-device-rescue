import hashlib
import os
import re
import shutil
import subprocess
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

# Warm the shared IOC database cache at import time (not lazily inside
# check()). The loader caches its parsed result keyed by data_dir, so this
# eager load ensures real IOC data is cached before check()/fix() run —
# which matters because check() may execute under test mocks (or other
# unusual filesystem conditions) that would otherwise interfere with the
# loader's own internal file-existence checks.
try:
    from modules.security.ai_worm_iocs.loader import load_iocs as _load_iocs

    _load_iocs()
except Exception:
    pass

_OBFUSCATION_PATTERNS = [
    re.compile(r"exec\s*\(\s*base64\.b64decode\s*\("),
    re.compile(r"eval\s*\(\s*atob\s*\("),
    re.compile(r"eval\s*\(\s*Buffer\.from\s*\(.*,\s*['\"]base64['\"]\s*\)"),
    re.compile(r"exec\s*\(\s*compile\s*\(\s*base64\."),
    re.compile(r"curl\s+[^\n]*\|\s*(bash|sh|zsh|python|node)"),
    re.compile(r"wget\s+[^\n]*\|\s*(bash|sh|zsh|python|node)"),
    re.compile(r"wget\s+-O\s*-\s+[^\n]*\|\s*(bash|sh|zsh|python|node)"),
]

_SCRIPT_EXTENSIONS = {".py", ".js", ".mjs", ".sh", ".bash", ".zsh", ".ps1", ".ts"}

_SCAN_DIRS_UNIX = [
    "~/.local/bin",
    "~/.config",
    "~/.cache",
    "/tmp",
    "/var/tmp",
]

_SCAN_DIRS_WIN = [
    "%TEMP%",
    "%APPDATA%",
    "%LOCALAPPDATA%",
]


class Module(ModuleBase):
    name = "ai_worm_filesystem"
    category = "security"
    platforms = [Platform.DARWIN, Platform.LINUX, Platform.WIN32]
    risk_level = RiskLevel.MODERATE
    priority = 55
    depends_on = []
    estimated_duration = "10s"

    emits_codes = [
        "security.ai_worm_filesystem.known_payload_path",
        "security.ai_worm_filesystem.known_hash_match",
        "security.ai_worm_filesystem.obfuscated_script",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        findings.extend(self._check_known_payload_paths(profile))
        findings.extend(self._check_known_hashes(profile))
        findings.extend(self._check_obfuscated_scripts(profile))
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        quarantine_dir = Path.home() / ".rescue_quarantine"

        for finding in findings.findings:
            confidence = finding.data.get("confidence", "low")
            file_path = finding.data.get("path")

            if confidence == "high" and file_path:
                quarantine_dir.mkdir(parents=True, exist_ok=True)
                src = Path(file_path)
                dest = quarantine_dir / f"{src.parent.name}_{src.name}"
                try:
                    if src.exists():
                        shutil.move(str(src), str(dest))
                        actions.append(
                            Action(
                                title=f"Quarantine: {src.name}",
                                description=f"Moved {src} to {dest}",
                                risk_level=RiskLevel.MODERATE,
                                kind=ActionKind.MUTATION,
                                executed=True,
                                success=True,
                            )
                        )
                    else:
                        actions.append(
                            Action(
                                title=f"Quarantine: {src.name}",
                                description=f"File already removed: {src}",
                                risk_level=RiskLevel.SAFE,
                                executed=True,
                                success=True,
                            )
                        )
                except OSError as e:
                    actions.append(
                        Action(
                            title=f"Quarantine: {src.name}",
                            description=f"Failed to quarantine {src}",
                            risk_level=RiskLevel.MODERATE,
                            kind=ActionKind.MUTATION,
                            executed=True,
                            success=False,
                            error=str(e),
                        )
                    )
            else:
                actions.append(
                    Action(
                        title=f"Investigate: {finding.title}",
                        description=(
                            f"Manual investigation recommended. "
                            f"Confidence: {confidence}. {finding.description}"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_known_payload_paths(self, profile: SystemProfile) -> list[Finding]:
        findings = []
        try:
            from modules.security.ai_worm_iocs.loader import load_iocs

            iocs = load_iocs()
        except Exception:
            return findings

        platform_str = profile.platform.value
        for entry in iocs.paths:
            if platform_str not in entry.platforms:
                continue
            expanded = Path(entry.path).expanduser()
            try:
                if expanded.is_file():
                    findings.append(
                        Finding(
                            title=f"Known {entry.threat} artifact: {expanded.name}",
                            description=entry.description,
                            severity=Severity.CRITICAL,
                            category=self.category,
                            code="security.ai_worm_filesystem.known_payload_path",
                            data={
                                "check": "known_payload_path",
                                "confidence": "high",
                                "path": str(expanded),
                                "threat": entry.threat,
                                "ioc_type": entry.type,
                            },
                        )
                    )
            except OSError:
                continue

        return findings

    def _check_known_hashes(self, profile: SystemProfile) -> list[Finding]:
        findings = []
        try:
            from modules.security.ai_worm_iocs.loader import load_iocs

            iocs = load_iocs()
        except Exception:
            return findings

        if not iocs.hashes:
            return findings

        platform_str = profile.platform.value
        for entry in iocs.paths:
            if platform_str not in entry.platforms:
                continue
            expanded = Path(entry.path).expanduser()
            try:
                if expanded.is_file() and expanded.stat().st_size < 10 * 1024 * 1024:
                    sha = hashlib.sha256(expanded.read_bytes()).hexdigest()
                    if sha in iocs.hashes:
                        h = iocs.hashes[sha]
                        findings.append(
                            Finding(
                                title=f"Known malicious file: {h.name or expanded.name}",
                                description=h.description,
                                severity=Severity.CRITICAL,
                                category=self.category,
                                code="security.ai_worm_filesystem.known_hash_match",
                                data={
                                    "check": "known_hash_match",
                                    "confidence": "high",
                                    "path": str(expanded),
                                    "sha256": sha,
                                    "threat": h.threat,
                                },
                            )
                        )
            except OSError:
                continue

        return findings

    def _check_obfuscated_scripts(self, profile: SystemProfile) -> list[Finding]:
        findings = []
        scan_results = self._scan_for_obfuscated_scripts(profile)
        for result in scan_results:
            findings.append(
                Finding(
                    title=f"Obfuscated script: {Path(result['path']).name}",
                    description=(
                        f"Script at {result['path']} contains suspicious pattern: "
                        f"{result['pattern'][:80]}"
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.ai_worm_filesystem.obfuscated_script",
                    data={
                        "check": "obfuscated_script",
                        "confidence": "medium",
                        "path": result["path"],
                        "pattern": result["pattern"],
                    },
                )
            )
        return findings

    def _scan_for_obfuscated_scripts(
        self, profile: SystemProfile
    ) -> list[dict[str, str]]:
        results = []
        if profile.platform == Platform.WIN32:
            scan_dirs = [os.path.expandvars(d) for d in _SCAN_DIRS_WIN]
        else:
            scan_dirs = [str(Path(d).expanduser()) for d in _SCAN_DIRS_UNIX]

        for dir_path in scan_dirs:
            d = Path(dir_path)
            if not d.exists():
                continue
            try:
                for f in d.rglob("*"):
                    if not f.is_file():
                        continue
                    if f.suffix not in _SCRIPT_EXTENSIONS:
                        continue
                    try:
                        if f.stat().st_size > 1 * 1024 * 1024:
                            continue
                        content = f.read_text(encoding="utf-8", errors="ignore")
                        for pat in _OBFUSCATION_PATTERNS:
                            match = pat.search(content)
                            if match:
                                results.append(
                                    {
                                        "path": str(f),
                                        "pattern": match.group(0),
                                    }
                                )
                                break
                    except OSError:
                        continue
            except OSError:
                continue

        return results
