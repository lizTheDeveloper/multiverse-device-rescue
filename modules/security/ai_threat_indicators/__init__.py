import os
import subprocess
import re
import time
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

MAX_CONFIG_SCAN_SECONDS = 1.0
MAX_CONFIG_SCAN_FILES = 200
MAX_CONFIG_SCAN_DEPTH = 2


class Module(ModuleBase):
    name = "ai_threat_indicators"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 56
    depends_on = []
    estimated_duration = "5s"

    emits_codes = [
        "security.ai_threat_indicators.ai_api_connection",
        "security.ai_threat_indicators.ai_api_key_found",
        "security.ai_threat_indicators.cron_ai_call",
        "security.ai_threat_indicators.launchagent_ai",
        "security.ai_threat_indicators.python_node_ai_process",
        "security.ai_threat_indicators.ai_config_file",
    ]

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
                                title=f"App {process} is connecting to an AI service",
                                description=(
                                    f"The program {process} is currently sending data "
                                    f"to an AI service at {endpoint}. Most apps do not "
                                    "connect to AI services unless you are actively using "
                                    "an AI feature. If you are not using an AI app right "
                                    "now, this connection might be from a hidden program "
                                    "or a bug.\n\n"
                                    "What to do: Check if you have an AI-related app "
                                    f"open. If not, quit the program {process} from your "
                                    "Dock or Activity Monitor to stop the connection. "
                                    "If it keeps happening, ask a trusted technical friend "
                                    "to investigate."
                                ),
                                severity=Severity.CRITICAL,
                                category=self.category,
                                code="security.ai_threat_indicators.ai_api_connection",
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
                        title=f"AI key stored in your system settings: {key_name}",
                        description=(
                            f"We found a key named {key_name} saved in your computer's "
                            "environment. Keys like this are usually set by developers "
                            "or specific apps to connect to AI services. If you do not "
                            "recognize this key or did not set it up, it could be a sign "
                            "that a program is using your computer to access AI services "
                            "without your permission.\n\n"
                            f"Here is the key we found: {key_name}\n\n"
                            "What to do: If you do not recognize this key, check your "
                            "shell configuration files (like .zshrc or .bash_profile) "
                            "to see if you added it. If you did not, remove it from those "
                            "files. If you are unsure, ask a trusted technical friend "
                            "for help."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.ai_threat_indicators.ai_api_key_found",
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
                        title="A scheduled task is calling an AI service",
                        description=(
                            "Your computer is set to automatically run a command that "
                            "connects to an AI service. This is unusual for standard "
                            "system tasks and could be a sign of a hidden program trying "
                            "to use AI features.\n\n"
                            f"The task details are: {line[:100]}\n\n"
                            "What to do: If you don't recognize it, follow the steps below "
                            "to remove it, or ask a trusted technical friend to help."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.ai_threat_indicators.cron_ai_call",
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
                            title="A scheduled task mentions an AI tool",
                            description=(
                                "Your computer has a scheduled task that refers to an "
                                "AI tool. This is not normal for standard system maintenance "
                                "and could indicate a hidden program.\n\n"
                                f"The task details are: {line[:100]}\n\n"
                                "What to do: If you don't recognize it, follow the steps below "
                                "to remove it, or ask a trusted technical friend to help."
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
                                        title=(
                                            f"Background item {plist_file.name} references "
                                            "an AI service"
                                        ),
                                        description=(
                                            f"A background file on your Mac, named {plist_file.name}, "
                                            "contains a reference to an AI service. Background "
                                            "items usually handle system tasks, so this "
                                            "is unusual and could be a sign of a hidden "
                                            "program.\n\n"
                                            f"The file is located at: {plist_file}\n\n"
                                            "What to do: Do not delete the file yet. "
                                            "Instead, move it to a folder on your Desktop "
                                            "so it stops running but stays as evidence. "
                                            "Then, ask a trusted technical friend to "
                                            "inspect the file to see what it is trying "
                                            "to do."
                                        ),
                                        severity=Severity.WARNING,
                                        category=self.category,
                                        code="security.ai_threat_indicators.launchagent_ai",
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
                                tool = next(
                                    t for t in sorted(AI_TOOL_INDICATORS) if t in content
                                )
                                findings.append(
                                    Finding(
                                        title=f"Background item mentions an AI tool: {plist_file.name}",
                                        description=(
                                            f"{plist_file} mentions an AI tool or vendor "
                                            f"(\"{tool}\"). Updaters and helpers for AI "
                                            "tools you installed, such as Claude Code, "
                                            "are normal. This is for your information; "
                                            "it only needs a closer look if you do not "
                                            "recognize the tool."
                                        ),
                                        severity=Severity.INFO,
                                        category=self.category,
                                        code="security.ai_threat_indicators.launchagent_ai",
                                        data={
                                            "check": "launchagent_ai",
                                            "plist_path": str(plist_file),
                                            "matched": tool,
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
                                    code="security.ai_threat_indicators.python_node_ai_process",
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

        config_paths = [Path.home() / ".config", Path.home() / ".local"]

        suspicious_patterns = [
            r"ai.?agent",
            r"ai.?config",
            r"claude",
            r"chatgpt",
            r"openai",
            r"anthropic",
        ]

        deadline = time.monotonic() + MAX_CONFIG_SCAN_SECONDS
        for item in _bounded_files(config_paths, deadline):
            filename = item.name.lower()
            if not any(re.search(pattern, filename) for pattern in suspicious_patterns):
                continue
            if item.suffix in [".log", ".txt", ".md"]:
                try:
                    if item.stat().st_size > 10 * 1024 * 1024:
                        continue
                    with open(item, "r", encoding="utf-8", errors="ignore") as file:
                        content = file.read(1000).lower()
                except (IOError, OSError):
                    continue
                if not any(endpoint.lower() in content for endpoint in AI_API_ENDPOINTS):
                    continue
            findings.append(
                Finding(
                    title=f"AI-related configuration file detected: {item.name}",
                    description=(
                        f"Found an AI-related configuration at {item}. Review it to confirm "
                        "that it belongs to software you intentionally installed."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.ai_threat_indicators.ai_config_file",
                    data={"check": "ai_config_file", "config_path": str(item)},
                )
            )

        return findings


def _bounded_files(roots: list[Path], deadline: float):
    seen = 0
    stack = [(root, 0) for root in roots if root.exists()]
    while stack and seen < MAX_CONFIG_SCAN_FILES and time.monotonic() < deadline:
        directory, depth = stack.pop()
        try:
            children = list(directory.iterdir())
        except OSError:
            continue
        for child in children:
            if seen >= MAX_CONFIG_SCAN_FILES or time.monotonic() >= deadline:
                return
            try:
                if child.is_symlink():
                    continue
                if child.is_dir():
                    if depth < MAX_CONFIG_SCAN_DEPTH and child.name not in {".git", "node_modules", "venv"}:
                        stack.append((child, depth + 1))
                elif child.is_file():
                    seen += 1
                    yield child
            except OSError:
                continue
