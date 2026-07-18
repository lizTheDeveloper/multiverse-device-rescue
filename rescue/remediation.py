"""Remediation walkthrough loading and the code->walkthrough reverse index.

Walkthroughs live in guides/remediation/*.md and declare which finding codes
they remediate via a front-matter `remediates: [codes]` list. This module
builds a reverse index {code: Guide} at startup, first-wins on conflict.
"""

import logging
from pathlib import Path

from rescue.guides import Guide, load_guide

logger = logging.getLogger(__name__)


def load_remediation_walkthroughs(remediation_dir: Path) -> dict[str, Guide]:
    """Scan a directory of walkthrough markdown files, return {code: Guide}.

    First-wins on a code claimed by two files (sorted by filename); a warning
    is logged. Files with no `remediates` entries are skipped with a warning.
    A missing directory yields an empty index (no error).
    """
    index: dict[str, Guide] = {}
    if not remediation_dir.is_dir():
        return index
    for path in sorted(remediation_dir.glob("*.md")):
        try:
            guide = load_guide(path)
        except Exception as e:  # malformed front-matter etc.
            logger.warning("Skipping unparseable walkthrough %s: %s", path.name, e)
            continue
        if not guide.remediates:
            logger.warning("Walkthrough %s declares no `remediates` codes", path.name)
            continue
        for code in guide.remediates:
            if code in index:
                logger.warning(
                    "Code %s already remediated by an earlier walkthrough; "
                    "ignoring duplicate in %s", code, path.name)
                continue
            index[code] = guide
    return index


def walkthrough_for(index: dict[str, Guide], code: str | None) -> Guide | None:
    """Resolve a finding code to its walkthrough, or None."""
    if not code:
        return None
    return index.get(code)
