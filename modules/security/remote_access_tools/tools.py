"""The list of remote-access tools ``remote_access_tools`` looks for.

Loaded by path (``rescue.runtime.load_content_module``), like the other helpers
shipped next to the modules. ``load_tools()`` validates every entry strictly:
a bad entry raises ``ValueError`` naming it, so a broken data file makes the
check fail loudly instead of quietly looking for fewer tools.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from rescue.runtime import content_file

TOOLS_FILE = content_file("modules/security/remote_access_tools/data/tools.json")

LOG_FORMATS = frozenset({"teamviewer_incoming", "anydesk_trace"})
LOG_PLATFORMS = frozenset({"darwin", "win32"})

_LIST_FIELDS = (
    "mac_bundle_ids", "mac_app_names", "mac_launchd", "mac_processes",
    "win_display_names", "win_services", "win_processes",
)
_ID = re.compile(r"^[a-z0-9_]+$")


@dataclass(frozen=True)
class LogSpec:
    platform: str
    path: str
    format: str


@dataclass(frozen=True)
class Tool:
    id: str
    name: str
    maker: str
    mac_bundle_ids: tuple[str, ...] = ()
    mac_app_names: tuple[str, ...] = ()
    mac_launchd: tuple[str, ...] = ()
    mac_processes: tuple[str, ...] = ()
    win_display_names: tuple[str, ...] = ()
    win_services: tuple[str, ...] = ()
    win_processes: tuple[str, ...] = ()
    logs: tuple[LogSpec, ...] = ()
    presence_only: bool = False


def _text(entry: dict, key: str, label: str) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"remote access tool {label}: '{key}' must be a non-empty string")
    return value.strip()


def _strings(entry: dict, key: str, label: str) -> tuple[str, ...]:
    value = entry.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise ValueError(f"remote access tool {label}: '{key}' must be a list of non-empty strings")
    return tuple(v.strip() for v in value)


def _tool(entry, index: int) -> Tool:
    if not isinstance(entry, dict):
        raise ValueError(f"remote access tool #{index}: not an object")
    label = entry.get("id") if isinstance(entry.get("id"), str) and entry.get("id") else f"#{index}"
    tool_id = _text(entry, "id", label)
    if not _ID.match(tool_id):
        raise ValueError(f"remote access tool {label}: id must be lowercase letters, digits and _")
    fields = {key: _strings(entry, key, label) for key in _LIST_FIELDS}
    for pattern in fields["win_display_names"]:
        try:
            re.compile(pattern, re.I)
        except re.error as exc:
            raise ValueError(f"remote access tool {label}: bad win_display_names pattern {pattern!r}: {exc}") from None
    logs = entry.get("logs", [])
    if not isinstance(logs, list):
        raise ValueError(f"remote access tool {label}: 'logs' must be a list")
    specs = []
    for log in logs:
        if not isinstance(log, dict):
            raise ValueError(f"remote access tool {label}: a log entry is not an object")
        platform = _text(log, "platform", label)
        fmt = _text(log, "format", label)
        path = _text(log, "path", label)
        if platform not in LOG_PLATFORMS:
            raise ValueError(f"remote access tool {label}: unknown log platform {platform!r}")
        if fmt not in LOG_FORMATS:
            raise ValueError(f"remote access tool {label}: unknown log format {fmt!r}")
        specs.append(LogSpec(platform=platform, path=path, format=fmt))
    presence_only = entry.get("presence_only", False)
    if not isinstance(presence_only, bool):
        raise ValueError(f"remote access tool {label}: 'presence_only' must be true or false")
    if not any(fields.values()):
        raise ValueError(f"remote access tool {label}: nothing to look for")
    return Tool(
        id=tool_id,
        name=_text(entry, "name", label),
        maker=_text(entry, "maker", label),
        logs=tuple(specs),
        presence_only=presence_only,
        **fields,
    )


def load_tools(path: Path | str | None = None) -> list[Tool]:
    """Every tool in the data file. Raises ValueError (naming the entry) when one is malformed."""
    source = Path(path) if path is not None else TOOLS_FILE
    try:
        doc = json.loads(Path(source).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"the remote access tool list could not be read: {exc}") from None
    entries = doc.get("tools") if isinstance(doc, dict) else None
    if not isinstance(entries, list) or not entries:
        raise ValueError("the remote access tool list has no 'tools'")
    tools = [_tool(entry, i) for i, entry in enumerate(entries)]
    seen: set[str] = set()
    for tool in tools:
        if tool.id in seen:
            raise ValueError(f"remote access tool {tool.id}: listed twice")
        seen.add(tool.id)
    return tools
