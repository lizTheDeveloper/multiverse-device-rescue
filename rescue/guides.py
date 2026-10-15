import re
from dataclasses import dataclass, field
from pathlib import Path

import frontmatter

_STEP_PATTERN = re.compile(r"^## Step (\d+): (.+)$", re.MULTILINE)


@dataclass
class GuideStep:
    number: int
    title: str
    body: str
    automatable: bool


@dataclass
class Guide:
    profile: str | None
    phase: int | None
    title: str
    estimated_time: str
    steps: list[GuideStep] = field(default_factory=list)
    automatable_steps: list[int] = field(default_factory=list)
    human_only_steps: list[int] = field(default_factory=list)
    remediates: list[str] = field(default_factory=list)
    # Optional {finding code: [step numbers]}: which steps matter for that
    # finding. A code with no entry gets every step.
    steps_for: dict[str, list[int]] = field(default_factory=dict)
    # True for walkthroughs about things someone close could use to watch a
    # person (remote access, monitoring apps, accounts, permissions). The app
    # then shows the advocate safety note above the steps.
    monitoring_risk: bool = False

    def steps_for_code(self, code: str | None) -> list[GuideStep]:
        wanted = self.steps_for.get(code) if code else None
        if not wanted:
            return list(self.steps)
        return [s for s in self.steps if s.number in wanted]


def parse_guide_markdown(text: str) -> Guide:
    post = frontmatter.loads(text)
    meta = post.metadata

    automatable_steps = list(meta.get("automatable_steps", []))
    human_only_steps = list(meta.get("human_only_steps", []))

    steps = [
        GuideStep(
            number=number,
            title=title,
            body=body,
            automatable=number in automatable_steps,
        )
        for number, title, body in _split_steps(post.content)
    ]

    return Guide(
        profile=meta.get("profile"),
        phase=meta.get("phase"),
        title=meta.get("title", ""),
        estimated_time=meta.get("estimated_time", ""),
        steps=steps,
        automatable_steps=automatable_steps,
        human_only_steps=human_only_steps,
        remediates=list(meta.get("remediates", []) or []),
        steps_for=_steps_for(meta.get("steps_for")),
        monitoring_risk=meta.get("monitoring_risk") is True,
    )


def _steps_for(raw) -> dict[str, list[int]]:
    if not isinstance(raw, dict):
        return {}
    return {
        str(code): [n for n in numbers if isinstance(n, int)]
        for code, numbers in raw.items()
        if isinstance(numbers, list)
    }


def load_guide(path: Path) -> Guide:
    # Guide content is UTF-8 and contains typographic punctuation. Without an
    # explicit encoding, Python uses the locale codec, which on Windows is
    # cp1252 — that silently mangles em-dashes and quotes into mojibake, and
    # raises outright on some byte sequences.
    return parse_guide_markdown(path.read_text(encoding="utf-8"))


def discover_guides(guides_dir: Path, profile_name: str) -> list[Guide]:
    profile_dir = guides_dir / profile_name
    if not profile_dir.is_dir():
        return []

    guides = [load_guide(path) for path in sorted(profile_dir.glob("*.md"))]
    guides.sort(key=lambda g: g.phase)
    return guides


def _split_steps(body: str) -> list[tuple[int, str, str]]:
    matches = list(_STEP_PATTERN.finditer(body))
    steps = []
    for i, match in enumerate(matches):
        number = int(match.group(1))
        title = match.group(2).strip()
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        steps.append((number, title, body[start:end].strip()))
    return steps
