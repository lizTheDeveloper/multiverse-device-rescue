"""Read a macOS code requirement and say which signer it pins, or nothing.

A TCC.db row stores, next to the app's bundle id, a ``csreq``: the code
requirement macOS itself checks before letting a program use that permission.
A bundle id is a name an app picks for itself; the requirement is what macOS
enforces. So when the requirement says "this identifier, signed through
Apple's chain by Team ID X", only code from team X can use the grant.

This reads the *text* form (``/usr/bin/csreq -r - -t``) and is deliberately
narrow. It credits a signer only for these shapes, as clauses joined by
``and`` and nothing else:

- ``identifier "<client>"``, ``anchor apple generic`` and
  ``certificate leaf[subject.OU] = <TEAMID>`` (each exactly once), plus any
  number of ``certificate <n|leaf|root>[field.<oid>]`` presence clauses
  (written ``/* exists */`` by csreq), as in a Developer ID requirement;
- ``identifier "<client>"`` and ``anchor apple`` for a ``com.apple.`` client:
  Apple's own code;
- one exact "Mac App Store, or Developer ID from Team X" requirement (see
  ``_STORE_OR_DEVID``), optionally after ``identifier "<client>" and``, for a
  non-Apple client. TCC applies a bundle-id row only to an app with that id,
  and the App Store signs an id only for the team that registered it, so
  either branch is team X's code.

Anything else fails closed (``None``): ``or``, ``!``, parentheses, any other
comment, a clause it does not know (even one that would only be stricter),
a repeated clause, an identifier other than the client's, escapes or quotes
inside an identifier, an unterminated string. A table lookup on the result
names the maker; this module runs nothing.
"""

from __future__ import annotations

import re

# The signer value for Apple's own anchor (no Team ID to pin).
APPLE = "apple"

_MAX_LEN = 2048
_IDENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z")
_TEAM_RE = re.compile(r"^[A-Z0-9]{10}\Z")
_WORD_RE = re.compile(r"^[A-Za-z0-9._\-\[\]=]+\Z")
_FIELD_RE = re.compile(r"^(?:leaf|root|[0-9]+)\[field\.[0-9]+(?:\.[0-9]+)*\]\Z")
_EXISTS_COMMENT = "/* exists */"
_X = r"(?: /\* exists \*/)?"
_STORE_OR_DEVID = re.compile(
    r'(?:identifier "(?P<ident>[A-Za-z0-9][A-Za-z0-9._-]{0,254})" and )?'
    r"anchor apple generic and \(certificate leaf\[field\.1\.2\.840\.113635\.100\.6\.1\.9\]" + _X
    + r" or certificate 1\[field\.1\.2\.840\.113635\.100\.6\.2\.6\]" + _X
    + r" and certificate leaf\[field\.1\.2\.840\.113635\.100\.6\.1\.13\]" + _X
    + r' and certificate leaf\[subject\.OU\] = (?:"(?P<qteam>[A-Z0-9]{10})"|(?P<team>[A-Z0-9]{10}))\)\Z'
)


def _tokens(text: str) -> list[tuple[str, str]] | None:
    """[(kind, value)] with kind "w" (word) or "q" (quoted); None if unsafe."""
    out: list[tuple[str, str]] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == " ":
            i += 1
            continue
        if text.startswith("/*", i):
            if not text.startswith(_EXISTS_COMMENT, i):
                return None
            i += len(_EXISTS_COMMENT)
            if i < n and text[i] != " ":
                return None
            continue
        if c == '"':
            end = text.find('"', i + 1)
            if end < 0:
                return None
            value = text[i + 1:end]
            if "\\" in value:
                return None
            i = end + 1
            if i < n and text[i] != " ":
                return None  # "a"b: a quote glued to more text
            out.append(("q", value))
            continue
        end = text.find(" ", i)
        end = n if end < 0 else end
        word = text[i:end]
        if not _WORD_RE.match(word):
            return None  # (, ), !, quotes, comments glued to words, anything odd
        out.append(("w", word))
        i = end
    return out


def _clauses(tokens: list[tuple[str, str]]) -> list[list[tuple[str, str]]] | None:
    clauses: list[list[tuple[str, str]]] = [[]]
    for tok in tokens:
        if tok == ("w", "or"):
            return None
        if tok == ("w", "and"):
            clauses.append([])
        else:
            clauses[-1].append(tok)
    if any(not c for c in clauses):
        return None
    return clauses


def signer_for(text, client) -> str | None:
    """The Team ID (or ``APPLE``) the requirement pins for ``client``, else None."""
    if not isinstance(text, str) or not isinstance(client, str) or not _IDENT_RE.match(client):
        return None
    text = text.strip()
    if not text or len(text) > _MAX_LEN or any(c in text for c in "\r\n\t\0"):
        return None
    store = _STORE_OR_DEVID.match(text)
    if store:
        if client.startswith("com.apple.") or store.group("ident") not in (None, client):
            return None
        return store.group("team") or store.group("qteam")
    tokens = _tokens(text)
    if not tokens:
        return None
    clauses = _clauses(tokens)
    if clauses is None:
        return None
    idents, teams = [], []
    generic = apple = 0
    for clause in clauses:
        kinds = [k for k, _ in clause]
        words = [v for _, v in clause]
        if len(clause) == 2 and clause[0] == ("w", "identifier"):
            idents.append(words[1])
        elif clause == [("w", "anchor"), ("w", "apple"), ("w", "generic")]:
            generic += 1
        elif clause == [("w", "anchor"), ("w", "apple")]:
            apple += 1
        elif (len(clause) == 4 and clause[:3] == [("w", "certificate"), ("w", "leaf[subject.OU]"), ("w", "=")]):
            teams.append(words[3])
        elif (len(clause) in (2, 3) and clause[0] == ("w", "certificate") and kinds[1] == "w"
              and _FIELD_RE.match(words[1]) and (len(clause) == 2 or clause[2] == ("w", "exists"))):
            pass  # a presence check on a certificate field: only ever stricter
        else:
            return None
    if len(idents) != 1 or idents[0] != client or not _IDENT_RE.match(idents[0]):
        return None
    if generic == 1 and apple == 0 and len(teams) == 1 and _TEAM_RE.match(teams[0]):
        return teams[0]
    if apple == 1 and generic == 0 and not teams and client.startswith("com.apple."):
        return APPLE
    return None
