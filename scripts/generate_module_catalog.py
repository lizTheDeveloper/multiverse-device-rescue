#!/usr/bin/env python3
"""Generate ``docs/modules.md`` from the live module registry.

The catalog page is the one place in the documentation that claims *what the
tool actually ships*. Hand-maintaining it guarantees it drifts: a module gets
added, renamed, or gains Linux support, and the page keeps describing the tree
as it was months ago. So it is generated from
:func:`rescue.registry.discover_modules` — the same discovery the CLI uses — and
CI runs this script with ``--check`` to fail the build if the committed page no
longer matches the registry.

Usage::

    python scripts/generate_module_catalog.py            # write docs/modules.md
    python scripts/generate_module_catalog.py --check     # exit 1 if stale

Note that discovery imports every module's ``__init__.py`` in-process (roadmap
P0#10), so this script executes the same code a scan would import. It never
calls ``check()`` or ``fix()`` — only class-level metadata is read.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rescue.models import Platform  # noqa: E402
from rescue.module_base import ModuleBase  # noqa: E402
from rescue.registry import discover_modules  # noqa: E402

MODULES_DIR = REPO_ROOT / "modules"
OUTPUT_PATH = REPO_ROOT / "docs" / "modules.md"

PLATFORM_LABELS = {
    Platform.DARWIN: "macOS",
    Platform.WIN32: "Windows",
    Platform.LINUX: "Linux",
}
PLATFORM_ORDER = [Platform.DARWIN, Platform.WIN32, Platform.LINUX]

CATEGORY_BLURBS = {
    "security": (
        "Malware and spyware indicators, persistence, remote access, "
        "credential exposure, and system hardening posture."
    ),
    "integrity": (
        "Whether the machine's own subsystems are healthy and intact: disks, "
        "updates, backups, drivers, logs, keychains, networking stacks."
    ),
    "performance": (
        "Why the machine is slow: CPU and memory pressure, thermals, disk "
        "space, startup load, and background work."
    ),
    "network": (
        "The local network and how this machine sits on it: interfaces, "
        "neighbours, ports, DNS, and interception."
    ),
    "bloatware": (
        "Preinstalled and vendor software that consumes resources without "
        "being asked for."
    ),
}

HEADER = """# Module catalog

!!! info "This page is generated"
    Written by `python scripts/generate_module_catalog.py` from the live
    registry (`rescue.registry.discover_modules`). CI runs the same script with
    `--check`, so this page cannot drift from the modules the tool actually
    ships. Do not edit it by hand.

A **module** is one self-contained check. It declares which platforms it can
run on, how risky its `fix()` is, and roughly how long its `check()` takes, then
returns findings. Modules never run in isolation from the rest of the
system — see [Architecture](architecture.md) for how a scan is assembled, and
[Writing a module](writing-a-module.md) for the authoring contract.

Reading the columns:

- **Platforms** — the module only runs where it declares support. Everywhere
  else it is filtered out before the scan starts, or returns
  `supported=False` with a reason. It never silently reports "no issues".
- **Risk** — the risk level of the module's `fix()`, not of its `check()`.
  Every `check()` is read-only. `safe` fixes are low-impact and reversible;
  `moderate` and `destructive` fixes always require explicit confirmation.
- **Duration** — the author's estimate for `check()`. The orchestrator
  enforces a hard 60-second per-module timeout regardless.

Run any single module directly:

```console
$ rescue run <module_name>
```
"""

FOOTER = """
## Reading a module before you run it

Every module is a single `__init__.py` under
`modules/<category>/<module_name>/`. There is no compiled code, no plugin
download, and no dynamic fetch — what is in the tree is what runs. To read one:

```console
$ less modules/security/linux_firewall_check/__init__.py
```

The top of the file is a docstring stating what the check looks at and why, the
class body declares the metadata shown in the tables above, `check()` is the
read-only half, and `fix()` is the half that produces guidance or mutations.
See [Trust and safety](trust-and-safety.md).
"""


def _module_dir(module: ModuleBase) -> str:
    """Repo-relative directory a module was loaded from, for the reader."""
    return f"modules/{module.category}/{module.name}/"


def _summary(module: ModuleBase) -> str:
    """First line of the module's documentation, if it has any.

    The convention in this tree is a file-level docstring at the top of
    ``__init__.py`` (that is also what ``rescue validate`` accepts as
    documentation), so both the class docstring and the containing module's
    docstring are considered, class first.
    """
    candidates = [type(module).__doc__]
    containing = sys.modules.get(type(module).__module__)
    candidates.append(getattr(containing, "__doc__", None))

    for doc in candidates:
        if not doc:
            continue
        for raw_line in doc.strip().splitlines():
            line = raw_line.strip()
            if line:
                return line
    return ""


def _cell(text: str) -> str:
    """Make free text safe inside a Markdown table cell."""
    return text.replace("|", r"\|").replace("\n", " ").strip()


def _platforms(module: ModuleBase) -> str:
    labels = [
        PLATFORM_LABELS[p]
        for p in PLATFORM_ORDER
        if p in module.platforms
    ]
    unknown = sorted(
        str(p) for p in module.platforms if p not in PLATFORM_LABELS
    )
    return ", ".join(labels + unknown) or "none declared"


def render(modules: list[ModuleBase]) -> str:
    by_category: dict[str, list[ModuleBase]] = {}
    for module in modules:
        by_category.setdefault(module.category or "uncategorised", []).append(module)

    platform_counts = {
        p: sum(1 for m in modules if p in m.platforms) for p in PLATFORM_ORDER
    }

    lines: list[str] = [HEADER, "", "## Coverage at a glance", ""]
    lines.append(f"**{len(modules)} modules** ship in the tree.")
    lines.append("")
    lines.append("| Platform | Modules that run there |")
    lines.append("| --- | ---: |")
    for platform in PLATFORM_ORDER:
        lines.append(f"| {PLATFORM_LABELS[platform]} | {platform_counts[platform]} |")
    lines.append("")
    lines.append(
        "A module can support more than one platform, so these numbers add up "
        "to more than the total."
    )
    lines.append("")
    lines.append("| Category | Modules |")
    lines.append("| --- | ---: |")
    for category in sorted(by_category):
        lines.append(f"| [{category}](#{category}) | {len(by_category[category])} |")
    lines.append("")

    for category in sorted(by_category):
        entries = sorted(by_category[category], key=lambda m: m.name)
        lines.append(f"## {category}")
        lines.append("")
        blurb = CATEGORY_BLURBS.get(category)
        if blurb:
            lines.append(blurb)
            lines.append("")
        per_platform = ", ".join(
            f"{PLATFORM_LABELS[p]} {sum(1 for m in entries if p in m.platforms)}"
            for p in PLATFORM_ORDER
        )
        lines.append(f"{len(entries)} modules — {per_platform}.")
        lines.append("")
        lines.append("| Module | Platforms | Risk | Duration | What it checks |")
        lines.append("| --- | --- | --- | --- | --- |")
        for module in entries:
            risk = getattr(module.risk_level, "value", str(module.risk_level))
            duration = module.estimated_duration or "unknown"
            lines.append(
                "| `{name}` | {platforms} | {risk} | {duration} | {summary} |".format(
                    name=_cell(module.name),
                    platforms=_platforms(module),
                    risk=_cell(str(risk)),
                    duration=_cell(str(duration)),
                    summary=_cell(_summary(module)) or "—",
                )
            )
        lines.append("")

    lines.append(FOOTER.strip())
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="Do not write; exit 1 if the committed page is out of date.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT_PATH,
        help=f"Where to write the catalog (default: {OUTPUT_PATH.relative_to(REPO_ROOT)}).",
    )
    args = parser.parse_args(argv)

    modules = discover_modules(MODULES_DIR)
    if not modules:
        # Discovery finding nothing is the signature of a packaging or path bug.
        # Writing an empty catalog would quietly document the tool as having no
        # modules at all, so refuse instead.
        print(
            f"error: no modules discovered under {MODULES_DIR}; refusing to "
            "generate an empty catalog",
            file=sys.stderr,
        )
        return 1

    rendered = render(modules)

    if args.check:
        if not args.output.exists():
            print(f"error: {args.output} does not exist; run this script without --check", file=sys.stderr)
            return 1
        current = args.output.read_text(encoding="utf-8")
        if current != rendered:
            print(
                f"error: {args.output} is out of date "
                f"({len(modules)} modules discovered). Run "
                "'python scripts/generate_module_catalog.py' and commit the result.",
                file=sys.stderr,
            )
            return 1
        print(f"{args.output} is up to date ({len(modules)} modules).")
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(f"Wrote {args.output} ({len(modules)} modules).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
