from __future__ import annotations
import json
from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any


def _plain(value: Any) -> Any:
    """Recursively convert values to JSON-serializable plain Python types.

    Module ``Finding.data`` dicts are free-form and occasionally hold values
    that ``json.dumps`` cannot encode (e.g. ``bytes`` from a subprocess). A
    single such value must never crash the whole scan's JSON output, so
    anything that is not a JSON-native scalar is coerced to a string.
    """
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if is_dataclass(value):
        return {k: _plain(v) for k, v in asdict(value).items()}
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return str(value)


def checks_to_json(results, platform: str) -> str:
    """Convert check results to a JSON string suitable for external consumption.

    Args:
        results: List of (ModuleBase, CheckResult) tuples from Orchestrator.run_checks()
        platform: Platform string (e.g. "darwin", "win32", "linux")

    Returns:
        JSON string with schema_version, platform, and modules array
    """
    modules = []
    for mod, check in results:
        modules.append({
            "name": mod.name,
            "status": "error" if check.error else "ok",
            "error": check.error,
            "findings": [_plain(f) for f in check.findings],
        })
    return json.dumps(
        {"schema_version": 1, "platform": platform, "modules": modules},
        indent=2,
    )
