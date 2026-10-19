"""Tidy the words a finding carries before a person reads them.

Modules build titles with f-strings, which gives "1 app(s) have", "crashed 1
times" and raw ISO time stamps. ``tidy`` fixes those in the scan's JSON (the
``title`` and ``description`` of each finding), in one place, so every module
reads the same way:

- "N word(s)" agrees with N: "1 app", "2 apps"; a verb right after it
  (have/are/were) agrees too. With no number before it, "(s)" is plural.
- "1 times" is "once".
- An ISO date-time ("2026-10-10T18:44:55+00:00") is a plain day ("10 Oct 2026").
- A count of a thousand or more things gets thousands separators: "4837
  errors" is "4,837 errors" (only before a counted noun, so ports, ids, phone
  and text numbers are left alone; four digits that read as a year stay).

``data`` is never touched: it keeps the exact values for anyone who wants them.
"""

from __future__ import annotations

import re

_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

# A number, up to three words, then the counted word with "(s)", then maybe a verb.
_COUNTED = re.compile(
    r"\b(?P<n>\d[\d,]*)(?P<mid>\s+(?:[\w.'-]+\s+){0,3}?)(?P<word>[A-Za-z][\w-]*)\(s\)"
    r"(?P<verb>\s+(?:have|are|were)\b)?"
)
_BARE = re.compile(r"\b(?P<word>[A-Za-z][\w-]*)\(s\)")
_ONE_TIMES = re.compile(r"\b1 times\b")
_ISO = re.compile(
    r"\b(?P<y>\d{4})-(?P<m>\d{2})-(?P<d>\d{2})T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?"
)
_SINGULAR_VERB = {"have": "has", "are": "is", "were": "was"}
_NOUNS = (
    "errors|warnings|files|items|apps|entries|times|crashes|connections|lines|events|"
    "messages|processes|requests|records|attempts|packets|fonts|folders|programs"
)
_BIG_COUNT = re.compile(rf"(?<![\w.,:/#-])(?P<n>\d{{4,}})(?=\s+(?:{_NOUNS})\b)")


def _plural(word: str) -> str:
    if re.search(r"(?:s|x|z|ch|sh)$", word):
        return word + "es"
    if re.search(r"[^aeiou]y$", word):
        return word[:-1] + "ies"
    return word + "s"


def _counted(m: re.Match) -> str:
    n = int(m.group("n").replace(",", ""))
    word = m.group("word")
    verb = m.group("verb") or ""
    if n == 1:
        if verb:
            v = verb.strip()
            verb = verb.replace(v, _SINGULAR_VERB[v])
        return f"{m.group('n')}{m.group('mid')}{word}{verb}"
    return f"{m.group('n')}{m.group('mid')}{_plural(word)}{verb}"


def plain_day(match_or_text) -> str:
    """"2026-10-10T18:44:55+00:00" -> "10 Oct 2026" (the day as written)."""
    m = match_or_text if isinstance(match_or_text, re.Match) else _ISO.search(str(match_or_text))
    if not m:
        return str(match_or_text)
    month = int(m.group("m"))
    if not 1 <= month <= 12:
        return m.group(0)
    return f"{int(m.group('d'))} {_MONTHS[month - 1]} {m.group('y')}"


def _big(m: re.Match) -> str:
    n = m.group("n")
    # Four digits that read as a year ("2026 errors" after a date) stay as written.
    if len(n) == 4 and 1900 <= int(n) <= 2099:
        return n
    return f"{int(n):,}"


def tidy(text):
    """The same text with the fixes above. Anything not a string is returned as is."""
    if not isinstance(text, str) or not text:
        return text
    out = _COUNTED.sub(_counted, text)
    out = _BARE.sub(lambda m: _plural(m.group("word")), out)
    out = _ONE_TIMES.sub("once", out)
    out = _ISO.sub(plain_day, out)
    out = _BIG_COUNT.sub(_big, out)
    return out
