"""Read macOS configuration profiles from ``/usr/bin/profiles`` output.

Used by the ``mdm_enrollment`` and ``mdm_enrollment_check`` modules. These are
pure functions; the modules run the commands themselves (without ``sudo``, with
a timeout) so the command catalog and ``--trace`` show them.

What a profile says about itself (its name, its organization) is written by
whoever made it, so it is never enough to call a profile "known". A profile is
known only when all of these hold:

- this Mac says it is enrolled in device management
  (``profiles status -type enrollment`` prints ``MDM enrollment: Yes``,
  optionally ``(User Approved)``);
- if the listing says where profiles came from, this one says MDM;
- its organization names a known device-management service.

Anything missing, unreadable or contradictory is "not known". Parsers return
``None`` for output they can't read ("couldn't check"), never "nothing there".

Output formats (synthetic in the tests; check against a managed Mac):

- ``profiles status -type enrollment``: ``Enrolled via DEP: No`` /
  ``MDM enrollment: Yes (User Approved)`` / ``MDM server: https://…``.
- ``profiles status``: ``There are no configuration profiles installed on this
  system`` (seen), or ``There are N configuration profiles installed …``.
- ``profiles list -verbose``: ``<level>[<N>] attribute: <key>: <value>``, where
  level is ``_computerlevel`` or a user name; one profile per (level, N).
- ``profiles show -output stdout-xml``: a plist dict of level -> list of
  profile dicts (``ProfileDisplayName``, ``ProfileIdentifier``,
  ``ProfileOrganization``…); ``<dict/>`` when none are visible (seen).
"""

from __future__ import annotations

import json
import plistlib
import re

PROFILES = "/usr/bin/profiles"
# A listing bigger than this isn't a list of profiles this check should parse.
MAX_LISTING_BYTES = 2 * 1024 * 1024

_MDM_LINE = re.compile(r"^\s*MDM enrollment\s*:\s*(.*?)\s*$", re.IGNORECASE | re.MULTILINE)
_DEP_LINE = re.compile(r"^\s*Enrolled via DEP\s*:\s*(.*?)\s*$", re.IGNORECASE | re.MULTILINE)
_SERVER_LINE = re.compile(r"^\s*MDM (?:enrollment )?server\s*:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_YES = re.compile(r"^yes\b", re.IGNORECASE)
_NO = re.compile(r"^no\b", re.IGNORECASE)
_COUNT = re.compile(r"There (?:are|is) (\d+) configuration profiles? installed", re.IGNORECASE)
_NONE_INSTALLED = re.compile(r"There are no configuration profiles installed", re.IGNORECASE)
_ATTR = re.compile(
    r"^\s*(?P<level>[^\s\[\]]+)\[(?P<idx>\d+)\]\s+attribute:\s*(?P<key>[^:]+?)\s*:\s*(?P<val>.*?)\s*$",
    re.IGNORECASE,
)

# Keys that say how a profile was installed. None of them is confirmed in real
# output; when no profile carries one, the rule falls back to enrollment plus
# organization.
_SOURCE_KEYS = {"source", "installsource", "installationsource", "profileinstallsource"}
_MDM_FLAG_KEYS = {"installedbymdm", "profileinstalledbymdm", "ismanaged", "managed", "ismdmprofile"}
_NAME_KEYS = {"name", "profiledisplayname", "displayname"}
_ID_KEYS = {"profileidentifier", "identifier"}
_ORG_KEYS = {"organization", "profileorganization"}


def _yes_no(value: str | None) -> bool | None:
    if not value:
        return None
    if _YES.match(value):
        return True
    if _NO.match(value):
        return False
    return None


def _one(pattern: re.Pattern, text: str) -> bool | None:
    """The yes/no a line says, or None when it's absent, unclear, or said two ways."""
    answers = {_yes_no(m) for m in pattern.findall(text)}
    if len(answers) != 1:
        return None
    return answers.pop()


def parse_enrollment(stdout: str | None) -> dict:
    """``profiles status -type enrollment`` -> {"mdm", "dep": True/False/None, "server"}."""
    text = stdout or ""
    server = _SERVER_LINE.search(text)
    return {
        "mdm": _one(_MDM_LINE, text),
        "dep": _one(_DEP_LINE, text),
        "server": server.group(1) if server else None,
    }


def parse_system_profile_count(stdout: str | None) -> int | None:
    """How many profiles ``profiles status`` says the whole system has, or None."""
    if not stdout:
        return None
    if _NONE_INSTALLED.search(stdout):
        return 0
    m = _COUNT.search(stdout)
    return int(m.group(1)) if m else None


def _truthy(value) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "yes", "1"):
            return True
        if v in ("false", "no", "0"):
            return False
    return None


def _new_profile(level: str) -> dict:
    return {
        "name": None,
        "identifier": None,
        "organization": None,
        "source": None,
        "installed_by_mdm": None,
        "level": level,
        "ambiguous": False,
    }


def _set(profile: dict, field: str, value) -> None:
    if profile[field] is not None and profile[field] != value:
        profile["ambiguous"] = True
        return
    profile[field] = value


def _apply(profile: dict, key: str, value) -> None:
    k = re.sub(r"[\s_-]", "", str(key)).lower()
    if k in _NAME_KEYS and isinstance(value, str) and value.strip():
        _set(profile, "name", value.strip())
    elif k in _ID_KEYS and isinstance(value, str) and value.strip():
        _set(profile, "identifier", value.strip())
    elif k in _ORG_KEYS and isinstance(value, str) and value.strip():
        _set(profile, "organization", value.strip())
    elif k in _SOURCE_KEYS:
        raw = str(value).strip()
        _set(profile, "source", raw)
        # Present but not plainly MDM: not MDM.
        _set(profile, "installed_by_mdm", bool(re.search(r"\bmdm\b", raw, re.IGNORECASE)))
    elif k in _MDM_FLAG_KEYS:
        _set(profile, "installed_by_mdm", _truthy(value) is True)


def _finish(profile: dict, level: str, idx) -> dict:
    if not profile["name"]:
        profile["name"] = profile["identifier"] or f"Unnamed profile ({level} {idx})"
    return profile


def parse_profiles_text(stdout: str | None) -> list[dict] | None:
    """``profiles list -verbose``: one dict per (level, index) block, in order.

    A new block starts whenever the level or index changes; nothing carries
    from one block to the next. Lines without the ``level[N] attribute:``
    prefix are ignored. Returns None for output with no such lines that also
    doesn't say no profiles are installed.
    """
    if not stdout:
        return None
    profiles: list[dict] = []
    current = None
    current_key = None
    for line in stdout.splitlines():
        m = _ATTR.match(line)
        if not m:
            continue
        block = (m.group("level"), m.group("idx"))
        if block != current_key:
            if current is not None:
                profiles.append(_finish(current, *current_key))
            current, current_key = _new_profile(block[0]), block
        _apply(current, m.group("key"), m.group("val"))
    if current is not None:
        profiles.append(_finish(current, *current_key))
    if not profiles and not _NONE_INSTALLED.search(stdout):
        return None
    return profiles


def parse_profiles_xml(stdout: str | bytes | None) -> list[dict] | None:
    """``profiles show -output stdout-xml``: level -> [profile dict]. None if unreadable."""
    if not stdout:
        return None
    data = stdout.encode("utf-8") if isinstance(stdout, str) else stdout
    if len(data) > MAX_LISTING_BYTES:
        return None
    try:
        root = plistlib.loads(data)
    except Exception:  # plistlib raises several types for bad input
        return None
    if not isinstance(root, dict):
        return None
    profiles: list[dict] = []
    for level, items in root.items():
        if not isinstance(items, list):
            return None
        for idx, item in enumerate(items, 1):
            if not isinstance(item, dict):
                return None
            p = _new_profile(str(level))
            for k, v in item.items():
                _apply(p, k, v)
            profiles.append(_finish(p, str(level), idx))
    return profiles


def load_known(path) -> list[str]:
    with open(path) as f:
        return [n for n in json.load(f) if isinstance(n, str) and n.strip()]


def is_known_mdm(organization, known: list[str]) -> bool:
    """Whether an organization names a known device-management service (whole words)."""
    if not isinstance(organization, str) or not organization.strip():
        return False
    return any(re.search(rf"\b{re.escape(n)}\b", organization, re.IGNORECASE) for n in known)


def untrusted_profiles(profiles: list[dict], enrolled: bool | None, known: list[str]) -> list[dict]:
    """The profiles that are not known to come from a device-management service."""
    sources_given = any(p.get("installed_by_mdm") is not None for p in profiles)

    def trusted(p: dict) -> bool:
        if enrolled is not True or p.get("ambiguous"):
            return False
        if sources_given and p.get("installed_by_mdm") is not True:
            return False
        return is_known_mdm(p.get("organization"), known)

    return [p for p in profiles if not trusted(p)]
