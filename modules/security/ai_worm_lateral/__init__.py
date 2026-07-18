import os
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
# which matters because check() may execute under test mocks (e.g. patched
# Path.exists / subprocess.run) that would otherwise interfere with the
# loader's own internal file-existence checks.
def _load_iocs():
    try:
        from modules.security.ai_worm_iocs.loader import load_iocs

        return load_iocs()
    except Exception:
        return None


_iocs_cache = _load_iocs()

# Well known CLI processes that legitimately talk to the cloud instance
# metadata service (169.254.169.254). Any other process doing so is
# suspicious and may indicate an AI worm harvesting cloud IAM credentials
# via IMDS.
_CLOUD_CLI_PROCESSES = {
    "aws",
    "aws-vault",
    "gcloud",
    "az",
    "azure-cli",
    "terraform",
    "packer",
    "amazon-ssm-agent",
    "cloud-init",
    "kubelet",
    "ecs-agent",
    "instance-metadata",
}

_IMDS_HOST = "169.254.169.254"

# Filenames/relative paths that indicate a supply-chain compromise dropped
# into a repository or package directory. These are checked by name across
# scanned project directories rather than via the generic IOC path list,
# since they can appear inside *any* project, not just a single fixed
# location.
_SUPPLY_CHAIN_ARTIFACTS = {
    ".github/workflows/shai-hulud-workflow.yml": ("shai_hulud", "workflow"),
    "setup_bun.js": ("miasma", "dropper"),
    "bun_environment.js": ("miasma", "dropper"),
}

_PROJECT_SCAN_DIRS = ["~/src", "~/projects", "~/code"]


class Module(ModuleBase):
    name = "ai_worm_lateral"
    category = "security"
    platforms = [Platform.DARWIN, Platform.LINUX, Platform.WIN32]
    risk_level = RiskLevel.MODERATE
    priority = 58
    depends_on = []
    estimated_duration = "10s"

    emits_codes = [
        "security.ai_worm_lateral.credential_harvesting",
        "security.ai_worm_lateral.supply_chain_artifact",
        "security.ai_worm_lateral.imds_access",
        "security.ai_worm_lateral.npm_publish_credentials",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings: list[Finding] = []

        for hit in self._check_credential_harvesting():
            path = hit.get("path", "")
            findings.append(
                Finding(
                    title=(
                        f"Stolen credential storage detected: "
                        f"{Path(path).name if path else 'unknown'}"
                    ),
                    description=(
                        f"Found file at {path} matching a known "
                        f"{hit.get('threat', 'unknown')} credential-harvesting "
                        f"storage location. Rotate and revoke any GitHub PATs, "
                        f"SSH keys, npm tokens, or other credentials that may "
                        f"have been stored or exfiltrated via this file."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.ai_worm_lateral.credential_harvesting",
                    data={
                        "check": "credential_harvesting",
                        "confidence": "high" if hit.get("ioc_match") else "medium",
                        "path": path,
                        "threat": hit.get("threat"),
                    },
                )
            )

        for hit in self._check_supply_chain_artifacts():
            path = hit.get("path", "")
            findings.append(
                Finding(
                    title=(
                        f"Supply chain artifact detected: "
                        f"{Path(path).name if path else 'unknown'}"
                    ),
                    description=(
                        f"Found {hit.get('type', 'artifact')} at {path} matching "
                        f"a known {hit.get('threat', 'unknown')} supply-chain "
                        f"compromise indicator. This may have run with your "
                        f"credentials — rotate and revoke any tokens (GitHub "
                        f"PAT, npm, cloud IAM) accessible from this project."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.ai_worm_lateral.supply_chain_artifact",
                    data={
                        "check": "supply_chain_artifact",
                        "confidence": "high",
                        "path": path,
                        "threat": hit.get("threat"),
                        "type": hit.get("type"),
                    },
                )
            )

        for hit in self._check_imds_access():
            findings.append(
                Finding(
                    title=(
                        f"Possible IMDS access from non-cloud-CLI process: "
                        f"{hit.get('process')}"
                    ),
                    description=(
                        f"Process {hit.get('process')} (pid {hit.get('pid')}) has "
                        f"a connection to the cloud instance metadata service "
                        f"({_IMDS_HOST}) but is not a recognized cloud CLI tool. "
                        f"This may indicate credential harvesting via IMDS. "
                        f"Rotate any cloud IAM credentials/roles reachable from "
                        f"this host."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.ai_worm_lateral.imds_access",
                    data={
                        "check": "imds_access",
                        "confidence": "medium",
                        "pid": hit.get("pid"),
                        "process": hit.get("process"),
                        "dest": hit.get("dest"),
                    },
                )
            )

        for hit in self._check_npm_publish_history():
            findings.append(
                Finding(
                    title="Active npm publish credentials detected",
                    description=(
                        f"npm CLI is currently authenticated as "
                        f"'{hit.get('user')}'. This is informational — if this "
                        f"session was not initiated by you, rotate/revoke the "
                        f"npm token immediately to prevent supply-chain package "
                        f"publishing abuse."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.ai_worm_lateral.npm_publish_credentials",
                    data={
                        "check": "npm_publish_credentials",
                        "confidence": "low",
                        "user": hit.get("user"),
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions: list[Action] = []

        for finding in findings.findings:
            confidence = finding.data.get("confidence", "low")
            check = finding.data.get("check")

            if confidence == "high" and check in (
                "credential_harvesting",
                "supply_chain_artifact",
            ):
                actions.append(self._fix_remove_artifact(finding))
            else:
                actions.append(self._fix_investigate(finding, confidence))

        return FixResult(module_name=self.name, actions=actions)

    # -- fix actions ---------------------------------------------------

    def _fix_remove_artifact(self, finding: Finding) -> Action:
        path = finding.data.get("path")
        name = Path(path).name if path else "artifact"
        rotation_guidance = (
            "Rotate and revoke any credentials (GitHub PATs, SSH keys, npm "
            "tokens, cloud IAM keys) that may have been exposed or "
            "exfiltrated via this artifact."
        )
        try:
            if not path:
                raise ValueError("no path available for finding")
            p = Path(path)
            if p.exists():
                os.remove(str(p))
                description = f"Removed {path}. {rotation_guidance}"
            else:
                description = f"Already removed: {path}. {rotation_guidance}"
            return Action(
                title=f"Remove malicious artifact: {name}",
                description=description,
                risk_level=RiskLevel.MODERATE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=True,
            )
        except (OSError, ValueError) as e:
            return Action(
                title=f"Remove malicious artifact: {name}",
                description=(
                    f"Failed to remove {path}. {rotation_guidance}"
                ),
                risk_level=RiskLevel.MODERATE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=False,
                error=str(e),
            )

    def _fix_investigate(self, finding: Finding, confidence: str) -> Action:
        return Action(
            title=f"Investigate: {finding.title}",
            description=(
                f"Manual investigation recommended. Confidence: {confidence}. "
                f"{finding.description} If this indicates credential exposure, "
                f"rotate/revoke the affected credentials (GitHub PAT, npm "
                f"token, cloud IAM keys, SSH keys) immediately."
            ),
            risk_level=RiskLevel.SAFE,
            success=True,
        )

    # -- shared helpers --------------------------------------------------

    def _get_iocs(self):
        global _iocs_cache
        if _iocs_cache is not None:
            return _iocs_cache
        _iocs_cache = _load_iocs()
        return _iocs_cache

    # -- detection: credential harvesting storage -------------------------

    def _check_credential_harvesting(self) -> list[dict]:
        """Check for known credential storage locations from the IOC
        database (type == "stolen_credential"). We intentionally do NOT
        scan/flag standard credential files (~/.aws/credentials,
        ~/.ssh/id_rsa) simply for existing — that is normal and expected.
        Only IOC-matched, worm-specific storage locations are flagged.
        """
        hits: list[dict] = []
        iocs = self._get_iocs()
        if iocs is None:
            return hits

        for entry in iocs.paths:
            if entry.type != "stolen_credential":
                continue
            expanded = Path(entry.path).expanduser()
            try:
                if expanded.is_file():
                    hits.append(
                        {
                            "path": str(expanded),
                            "threat": entry.threat,
                            "ioc_match": True,
                        }
                    )
            except OSError:
                continue

        return hits

    # -- detection: supply chain artifacts --------------------------------

    def _check_supply_chain_artifacts(self) -> list[dict]:
        """Scan the current directory and common project directories
        (~/src, ~/projects, ~/code) for known supply-chain compromise
        artifacts (malicious workflows, dropper scripts)."""
        hits: list[dict] = []
        seen: set[str] = set()

        project_dirs: list[Path] = [Path.cwd()]
        for base in _PROJECT_SCAN_DIRS:
            base_path = Path(base).expanduser()
            try:
                if not base_path.is_dir():
                    continue
            except OSError:
                continue
            project_dirs.append(base_path)
            try:
                for child in base_path.iterdir():
                    try:
                        if child.is_dir():
                            project_dirs.append(child)
                    except OSError:
                        continue
            except OSError:
                continue

        for proj in project_dirs:
            for rel_path, (threat, artifact_type) in _SUPPLY_CHAIN_ARTIFACTS.items():
                candidate = proj / rel_path
                try:
                    if not candidate.is_file():
                        continue
                except OSError:
                    continue
                key = str(candidate)
                if key in seen:
                    continue
                seen.add(key)
                hits.append(
                    {"path": key, "threat": threat, "type": artifact_type}
                )

        return hits

    # -- detection: IMDS access from non-cloud-CLI processes --------------

    def _check_imds_access(self) -> list[dict]:
        hits: list[dict] = []
        try:
            result = subprocess.run(
                ["lsof", "-i", "-n", "-P"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (subprocess.TimeoutExpired, OSError):
            return hits

        output = result.stdout or ""
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("COMMAND"):
                continue
            if _IMDS_HOST not in line:
                continue

            parts = line.split()
            if len(parts) < 2:
                continue
            process = parts[0]
            try:
                pid = int(parts[1])
            except ValueError:
                continue

            if process.lower() in _CLOUD_CLI_PROCESSES:
                continue

            hits.append({"process": process, "pid": pid, "dest": _IMDS_HOST})

        return hits

    # -- detection: npm publish credential status (informational) ---------

    def _check_npm_publish_history(self) -> list[dict]:
        hits: list[dict] = []
        try:
            result = subprocess.run(
                ["npm", "whoami"], capture_output=True, text=True, timeout=10
            )
        except (subprocess.TimeoutExpired, OSError):
            return hits

        output = (result.stdout or "").strip()
        if result.returncode == 0 and output:
            hits.append({"user": output})

        return hits
