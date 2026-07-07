import os
import subprocess
import re
from pathlib import Path

from rescue.models import (
    Action,
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


# Known AI API endpoints to monitor
AI_API_ENDPOINTS = {
    "api.openai.com",
    "api.anthropic.com",
    "api.together.ai",
    "generativelanguage.googleapis.com",
    "api.cohere.com",
    "api.aleph-alpha.com",
    "api.nlpcloud.io",
    "api.deepinfra.com",
    "api.perplexity.ai",
}

# Environment variables that might indicate rogue AI agents
AI_ENV_KEYS = {
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "TOGETHER_API_KEY",
    "GOOGLE_API_KEY",
    "COHERE_API_KEY",
    "HUGGINGFACE_API_KEY",
}

# Known AI tool names to detect in config
AI_TOOL_INDICATORS = {
    "claude",
    "chatgpt",
    "gpt",
    "openai",
    "anthropic",
    "together",
    "cohere",
    "huggingface",
    "ai-agent",
    "langchain",
    "llamaindex",
    "llama-index",
}


class Module(ModuleBase):
    name = "ai_threat_indicators"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 56
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check for processes connecting to AI API endpoints
        findings.extend(self._check_ai_api_connections())

        # Check for AI API keys in environment
        findings.extend(self._check_ai_env_keys())

        # Check for suspicious cron jobs calling AI APIs
        findings.extend(self._check_cron_jobs())

        # Check for LaunchAgents/LaunchDaemons with AI references
        findings.extend(self._check_launch_agents())

        # Check for unexpected Python/Node processes with AI packages
        findings.extend(self._check_python_node_processes())

        # Check config files for AI agent configurations
        findings.extend(self._check_config_files())

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Report AI threat indicators with investigation guidance (informational only)."""
        actions = []

        for finding in findings.findings:
            check_type = finding.data.get("check")

            if check_type == "ai_api_connection":
                process = finding.data.get("process")
                endpoint = finding.data.get("endpoint")
                title = f"Investigate AI API connection from {process}"
                description = (
                    f"Process {process} is connecting to AI endpoint {endpoint}. "
                    f"Verify this is expected. Check if the process is authorized to use AI services. "
                    f"Use 'lsof -i -n -P | grep {endpoint}' to monitor this connection."
                )
            elif check_type == "ai_api_key_found":
                key_name = finding.data.get("key_name")
                title = f"Unexpected AI API key: {key_name}"
                description = (
                    f"Found {key_name} in environment variables. "
                    f"Verify you intentionally set this. If not, this may indicate a rogue AI agent. "
                    f"Consider running 'unset {key_name}' to remove it."
                )
            elif check_type == "cron_ai_call":
                cron_entry = finding.data.get("cron_entry", "unknown")
                title = "Suspicious cron job calling AI API"
                description = (
                    f"Cron job found calling AI endpoint: {cron_entry}. "
                    f"Review 'crontab -l' to verify this is expected. "
                    f"Remove from crontab if unauthorized."
                )
            elif check_type == "launchagent_ai":
                plist_path = finding.data.get("plist_path")
                title = f"LaunchAgent/Daemon with AI reference: {Path(plist_path).name}"
                description = (
                    f"Found AI-related reference in {plist_path}. "
                    f"Review this plist file to verify it's authorized. "
                    f"Remove from ~/Library/LaunchAgents or /Library/LaunchDaemons if unauthorized."
                )
            elif check_type == "python_node_ai_process":
                process = finding.data.get("process")
                ai_indicator = finding.data.get("ai_indicator")
                title = f"Unexpected Python/Node process with AI indicator: {process}"
                description = (
                    f"Process {process} references AI-related package/name: {ai_indicator}. "
                    f"Verify this is an authorized process. Check 'ps aux | grep {process}' for full details."
                )
            elif check_type == "ai_config_file":
                config_path = finding.data.get("config_path")
                title = f"AI configuration file found: {config_path}"
                description = (
                    f"Found potential AI agent configuration at {config_path}. "
                    f"Review this file to verify it's authorized. "
                    f"Delete if it's from an unauthorized AI agent."
                )
            else:
                continue

            actions.append(
                Action(
                    title=title,
                    description=description,
                    risk_level=RiskLevel.SAFE,
                    success=True,
                    error=None,
                )
            )

        return FixResult(module_name=self.name, actions=actions)

    def _check_ai_api_connections(self) -> list[Finding]:
        """Check for processes connecting to AI API endpoints."""
        findings = []

        try:
            result = subprocess.run(
                ["lsof", "-i", "-n", "-P"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            lsof_output = result.stdout
        except (subprocess.TimeoutExpired, OSError):
            return findings

        for line in lsof_output.split("\n"):
            if not line.strip():
                continue

            # Check if line contains any AI API endpoint
            for endpoint in AI_API_ENDPOINTS:
                if endpoint in line:
                    # Parse the line to extract process name
                    parts = line.split()
                    if len(parts) >= 1:
                        process = parts[0]
                        findings.append(
                            Finding(
                                title=f"Outbound connection to AI API endpoint from {process}",
                                description=(
                                    f"Process {process} is connecting to {endpoint}. "
                                    f"This may indicate a rogue AI agent or unauthorized AI usage."
                                ),
                                severity=Severity.CRITICAL,
                                category=self.category,
                                data={
                                    "check": "ai_api_connection",
                                    "process": process,
                                    "endpoint": endpoint,
                                },
                            )
                        )
                        break

        return findings

    def _check_ai_env_keys(self) -> list[Finding]:
        """Check for AI API keys in environment variables."""
        findings = []

        for key_name in AI_ENV_KEYS:
            if key_name in os.environ:
                findings.append(
                    Finding(
                        title=f"AI API key found in environment: {key_name}",
                        description=(
                            f"Found {key_name} in environment variables. "
                            f"Verify you intentionally set this, as it could indicate a rogue AI agent."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "ai_api_key_found",
                            "key_name": key_name,
                        },
                    )
                )

        return findings

    def _check_cron_jobs(self) -> list[Finding]:
        """Check for suspicious cron jobs calling AI APIs."""
        findings = []

        try:
            result = subprocess.run(
                ["crontab", "-l"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            crontab_output = result.stdout
        except (subprocess.TimeoutExpired, OSError):
            # crontab command may not be available or user has no cron jobs
            return findings

        for line in crontab_output.split("\n"):
            if not line.strip() or line.startswith("#"):
                continue

            # Check if cron entry calls curl/wget to AI endpoints
            line_lower = line.lower()
            if any(endpoint in line_lower for endpoint in AI_API_ENDPOINTS):
                findings.append(
                    Finding(
                        title="Suspicious cron job calling AI endpoint",
                        description=(
                            f"Cron job found that calls an AI API endpoint: {line[:100]}"
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "cron_ai_call",
                            "cron_entry": line[:200],
                        },
                    )
                )
            elif any(tool in line_lower for tool in AI_TOOL_INDICATORS):
                # Check for AI tool references in curl/wget commands
                if any(cmd in line_lower for cmd in ["curl", "wget", "python", "node"]):
                    findings.append(
                        Finding(
                            title="Suspicious cron job with AI tool reference",
                            description=(
                                f"Cron job found that references AI tools: {line[:100]}"
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "cron_ai_call",
                                "cron_entry": line[:200],
                            },
                        )
                    )

        return findings

    def _check_launch_agents(self) -> list[Finding]:
        """Check LaunchAgents and LaunchDaemons for AI references."""
        findings = []

        launch_paths = [
            Path.home() / "Library" / "LaunchAgents",
            Path("/Library/LaunchDaemons"),
            Path("/System/Library/LaunchDaemons"),
        ]

        for launch_path in launch_paths:
            if not launch_path.exists():
                continue

            try:
                for plist_file in launch_path.glob("*.plist"):
                    try:
                        with open(plist_file, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read().lower()

                            # Check for AI endpoint references
                            if any(
                                endpoint.lower() in content
                                for endpoint in AI_API_ENDPOINTS
                            ):
                                findings.append(
                                    Finding(
                                        title=f"LaunchAgent/Daemon with AI endpoint reference: {plist_file.name}",
                                        description=(
                                            f"Found AI API endpoint reference in {plist_file}. "
                                            f"This may indicate a rogue AI agent."
                                        ),
                                        severity=Severity.WARNING,
                                        category=self.category,
                                        data={
                                            "check": "launchagent_ai",
                                            "plist_path": str(plist_file),
                                        },
                                    )
                                )
                            # Check for AI tool references
                            elif any(
                                tool in content for tool in AI_TOOL_INDICATORS
                            ):
                                findings.append(
                                    Finding(
                                        title=f"LaunchAgent/Daemon with AI tool reference: {plist_file.name}",
                                        description=(
                                            f"Found AI tool reference in {plist_file}. "
                                            f"Verify this is an authorized AI service."
                                        ),
                                        severity=Severity.WARNING,
                                        category=self.category,
                                        data={
                                            "check": "launchagent_ai",
                                            "plist_path": str(plist_file),
                                        },
                                    )
                                )
                    except (IOError, OSError):
                        # Skip files we can't read
                        continue
            except (IOError, OSError):
                # Skip directories we can't read
                continue

        return findings

    def _check_python_node_processes(self) -> list[Finding]:
        """Check for unexpected Python/Node processes with AI-related packages."""
        findings = []

        try:
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            ps_output = result.stdout
        except (subprocess.TimeoutExpired, OSError):
            return findings

        for line in ps_output.split("\n"):
            if not line.strip():
                continue

            line_lower = line.lower()

            # Check for Python processes with AI packages
            if "python" in line_lower or "node" in line_lower:
                for ai_indicator in AI_TOOL_INDICATORS:
                    if ai_indicator in line_lower:
                        # Extract process name/path
                        parts = line.split()
                        if len(parts) >= 11:
                            process_cmd = " ".join(parts[10:])[:100]
                            findings.append(
                                Finding(
                                    title=f"Unexpected Python/Node process with AI indicator",
                                    description=(
                                        f"Found process with AI reference: {process_cmd}"
                                    ),
                                    severity=Severity.INFO,
                                    category=self.category,
                                    data={
                                        "check": "python_node_ai_process",
                                        "process": process_cmd,
                                        "ai_indicator": ai_indicator,
                                    },
                                )
                            )
                        break

        return findings

    def _check_config_files(self) -> list[Finding]:
        """Check ~/.config and ~/.local for AI agent configuration files."""
        findings = []

        config_paths = [
            Path.home() / ".config",
            Path.home() / ".local",
            Path.home() / ".cache",
        ]

        suspicious_patterns = [
            r"ai.?agent",
            r"ai.?config",
            r"claude",
            r"chatgpt",
            r"openai",
            r"anthropic",
        ]

        for config_path in config_paths:
            if not config_path.exists():
                continue

            try:
                # Look for suspicious config files
                for item in config_path.rglob("*"):
                    if not item.is_file():
                        continue

                    # Check filename matches suspicious patterns
                    filename = item.name.lower()
                    for pattern in suspicious_patterns:
                        if re.search(pattern, filename):
                            # Skip common false positives
                            if item.suffix in [".log", ".txt", ".md"]:
                                try:
                                    # Check file size to avoid huge files
                                    if item.stat().st_size > 10 * 1024 * 1024:  # 10MB
                                        continue

                                    with open(item, "r", encoding="utf-8", errors="ignore") as f:
                                        content = f.read(1000)  # Read first 1KB
                                        # Check if content has AI references
                                        if any(
                                            endpoint.lower() in content.lower()
                                            for endpoint in AI_API_ENDPOINTS
                                        ):
                                            findings.append(
                                                Finding(
                                                    title=f"AI configuration file detected: {item.name}",
                                                    description=(
                                                        f"Found potential AI agent configuration at {item}. "
                                                        f"Review and remove if unauthorized."
                                                    ),
                                                    severity=Severity.WARNING,
                                                    category=self.category,
                                                    data={
                                                        "check": "ai_config_file",
                                                        "config_path": str(item),
                                                    },
                                                )
                                            )
                                except (IOError, OSError):
                                    continue
                            else:
                                findings.append(
                                    Finding(
                                        title=f"AI agent configuration file detected: {item.name}",
                                        description=(
                                            f"Found suspicious configuration file at {item}. "
                                            f"Review and remove if not authorized."
                                        ),
                                        severity=Severity.INFO,
                                        category=self.category,
                                        data={
                                            "check": "ai_config_file",
                                            "config_path": str(item),
                                        },
                                    )
                                )
                            break
            except (IOError, OSError):
                # Skip directories we can't read
                continue

        return findings
