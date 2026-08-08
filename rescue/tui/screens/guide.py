"""The guided-walkthrough flow: pick a guide set, pick a phase, work the steps.

This replaces `guide_placeholder.py`, which rendered three disabled checkboxes
and the words "coming in Plan 3". The guide model, the markdown content, and the
session store it needed have all existed for some time; only the screens were
missing, so the TUI silently had no access to the recovery walkthroughs that are
the reason someone opens this tool after being hacked (roadmap P1#5).

Three screens, in the order a person moves through them:

``GuideSetsScreen``
    Which walkthroughs exist, and how far through each one you are.
``GuidePhasesScreen``
    The phases of one walkthrough, with the phase you are on marked.
``GuideStepsScreen``
    The steps of one phase as a live checklist. Ticking a step writes through
    to the same ``SessionStore`` the CLI uses, so `rescue guide <profile>` and
    the TUI are two views of one piece of progress rather than two records that
    disagree.

Automatable and human-only steps are labelled distinctly and deliberately. Most
of what matters in a security reset — changing a password at the provider,
revoking a session, calling a bank — cannot be automated by anything running on
the affected device, and a checklist that blurs the two invites someone to
assume the tool did something it did not.
"""

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Checkbox, Footer, Header, Markdown, OptionList, Static
from textual.widgets.option_list import Option

from rescue.guides import Guide, discover_guides
from rescue.session import SessionStore

# Guide sets live one directory per profile under guides/. This one holds
# finding-triggered remediation walkthroughs rather than a phased recovery
# process, and is reached from a finding instead of from this menu.
_NOT_A_GUIDE_SET = {"remediation"}


def discover_guide_sets(guides_dir: Path) -> list[tuple[str, list[Guide]]]:
    """Return (name, phases) for every phased guide set on disk, sorted by name."""
    if not guides_dir.is_dir():
        return []
    sets: list[tuple[str, list[Guide]]] = []
    for directory in sorted(p for p in guides_dir.iterdir() if p.is_dir()):
        if directory.name in _NOT_A_GUIDE_SET:
            continue
        guides = discover_guides(guides_dir, directory.name)
        if guides:
            sets.append((directory.name, guides))
    return sets


def _completed(store: SessionStore, profile: str, phase: int) -> set[int]:
    return set(store.load(profile).completed_steps.get(phase, []))


def _phase_progress(store: SessionStore, profile: str, guide: Guide) -> tuple[int, int]:
    done = _completed(store, profile, guide.phase)
    return len(done & {step.number for step in guide.steps}), len(guide.steps)


class GuideSetsScreen(Screen):
    """Lists the phased walkthroughs available, with overall progress."""

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def __init__(self, guides_dir: Path, store: SessionStore):
        super().__init__()
        self.guides_dir = guides_dir
        self.store = store
        self.sets = discover_guide_sets(guides_dir)

    def compose(self) -> ComposeResult:
        yield Header()
        if not self.sets:
            yield Static(
                "No guided walkthroughs are installed. Guide content ships in "
                "guides/<profile>/phase_N.md.",
                id="guide-empty",
            )
            yield Footer()
            return

        options = []
        for name, guides in self.sets:
            done = sum(_phase_progress(self.store, name, g)[0] for g in guides)
            total = sum(len(g.steps) for g in guides)
            title = guides[0].title or name
            options.append(
                Option(
                    f"{name} — {title}  [{done}/{total} steps done]",
                    id=name,
                )
            )
        yield OptionList(*options, id="guide-set-list")
        yield Footer()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        name = event.option.id
        assert name is not None
        guides = dict(self.sets)[name]
        self.app.push_screen(GuidePhasesScreen(name, guides, self.store))


class GuidePhasesScreen(Screen):
    """Lists the phases of one walkthrough and where the session left off."""

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def __init__(self, profile_name: str, guides: list[Guide], store: SessionStore):
        super().__init__()
        self.profile_name = profile_name
        self.guides = guides
        self.store = store

    def compose(self) -> ComposeResult:
        yield Header()
        yield OptionList(*self._options(), id="guide-phase-list")
        yield Footer()

    def _options(self) -> list[Option]:
        state = self.store.load(self.profile_name)
        options = []
        for guide in self.guides:
            done, total = _phase_progress(self.store, self.profile_name, guide)
            marker = "▶ " if guide.phase == state.current_phase else "  "
            status = "complete" if total and done == total else f"{done}/{total}"
            time = f" · {guide.estimated_time}" if guide.estimated_time else ""
            options.append(
                Option(
                    f"{marker}Phase {guide.phase}: {guide.title} [{status}]{time}",
                    id=str(guide.phase),
                )
            )
        return options

    def on_screen_resume(self) -> None:
        """Refresh the counts after returning from a steps screen.

        Only the option list is rebuilt. Recomposing the whole screen would
        also tear down and re-mount the Header while its own mount callback is
        still in flight, which is a crash rather than a redraw.
        """
        try:
            option_list = self.query_one("#guide-phase-list", OptionList)
        except Exception:
            return
        option_list.clear_options()
        option_list.add_options(self._options())

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        assert event.option.id is not None
        phase = int(event.option.id)
        guide = next(g for g in self.guides if g.phase == phase)
        self.app.push_screen(GuideStepsScreen(self.profile_name, guide, self.store))


class GuideStepsScreen(Screen):
    """One phase as a working checklist, persisted to the session store."""

    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
        ("d", "show_detail", "Step detail"),
    ]

    def __init__(self, profile_name: str, guide: Guide, store: SessionStore):
        super().__init__()
        self.profile_name = profile_name
        self.guide = guide
        self.store = store
        self._step_by_checkbox: dict[str, int] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        done = _completed(self.store, self.profile_name, self.guide.phase)

        header = f"Phase {self.guide.phase}: {self.guide.title}"
        if self.guide.estimated_time:
            header += f"  ·  about {self.guide.estimated_time}"
        yield Static(header, id="guide-steps-title")

        automatable = len(self.guide.automatable_steps)
        yield Static(
            f"{len(self.guide.steps)} steps — {automatable} the tool can help with, "
            f"{len(self.guide.steps) - automatable} you do yourself. "
            "Press d on a step to read the full instructions.",
            id="guide-steps-summary",
        )

        with VerticalScroll(id="guide-step-list"):
            for step in self.guide.steps:
                checkbox_id = f"guide-step-{step.number}"
                self._step_by_checkbox[checkbox_id] = step.number
                label = "tool-assisted" if step.automatable else "you do this"
                yield Checkbox(
                    f"Step {step.number}: {step.title}  ({label})",
                    value=step.number in done,
                    id=checkbox_id,
                )
        yield Footer()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        checkbox_id = event.checkbox.id
        if checkbox_id not in self._step_by_checkbox:
            return
        step_number = self._step_by_checkbox[checkbox_id]
        state = self.store.load(self.profile_name)
        done = state.completed_steps.setdefault(self.guide.phase, [])

        if event.value and step_number not in done:
            done.append(step_number)
            done.sort()
        elif not event.value and step_number in done:
            # Un-ticking has to work. Someone who marked a step done and then
            # discovered it did not take needs to say so; a checklist that only
            # moves forward records a recovery that did not happen.
            done.remove(step_number)
        else:
            return

        self.store.save(state)
        self._advance_current_phase(state)

    def _advance_current_phase(self, state) -> None:
        """Move the session's current phase forward once this one is complete."""
        if not self.store.is_phase_complete(state, self.guide.phase, self.guide):
            return
        if state.current_phase <= self.guide.phase:
            self.store.advance_phase(self.profile_name, self.guide.phase + 1)

    def action_show_detail(self) -> None:
        focused = self.focused
        checkbox_id = getattr(focused, "id", None)
        if checkbox_id not in self._step_by_checkbox:
            return
        number = self._step_by_checkbox[checkbox_id]
        step = next(s for s in self.guide.steps if s.number == number)
        self.app.push_screen(GuideStepDetailScreen(step))


class GuideStepDetailScreen(Screen):
    """The full markdown body of a single step."""

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def __init__(self, step):
        super().__init__()
        self.step = step

    def compose(self) -> ComposeResult:
        yield Header()
        kind = "The tool can help with this step." if self.step.automatable else (
            "This step is yours to do — the tool cannot do it for you."
        )
        body = f"# Step {self.step.number}: {self.step.title}\n\n*{kind}*\n\n{self.step.body}"
        with VerticalScroll(id="guide-step-detail"):
            yield Markdown(body, id="guide-step-detail-body")
        yield Footer()
