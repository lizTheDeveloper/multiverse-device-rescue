import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rescue.guides import Guide


@dataclass
class SessionState:
    profile: str
    completed_steps: dict[int, list[int]] = field(default_factory=dict)
    current_phase: int = 0

    def to_dict(self) -> dict:
        return {
            "profile": self.profile,
            "completed_steps": {
                str(phase): steps for phase, steps in self.completed_steps.items()
            },
            "current_phase": self.current_phase,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SessionState":
        return cls(
            profile=data["profile"],
            completed_steps={
                int(phase): steps
                for phase, steps in data.get("completed_steps", {}).items()
            },
            current_phase=data.get("current_phase", 0),
        )


class SessionStore:
    def __init__(self, session_dir: Path):
        self._session_dir = session_dir
        self._session_dir.mkdir(parents=True, exist_ok=True)

    def load(self, profile_name: str) -> SessionState:
        path = self._path(profile_name)
        if not path.exists():
            return SessionState(profile=profile_name)
        with open(path, "r") as f:
            data = json.load(f)
        return SessionState.from_dict(data)

    def save(self, state: SessionState) -> None:
        path = self._path(state.profile)
        with open(path, "w") as f:
            json.dump(state.to_dict(), f, indent=2)

    def mark_step_complete(self, profile_name: str, phase: int, step: int) -> SessionState:
        state = self.load(profile_name)
        done = state.completed_steps.setdefault(phase, [])
        if step not in done:
            done.append(step)
            done.sort()
        self.save(state)
        return state

    def is_phase_complete(self, state: SessionState, phase: int, guide: "Guide") -> bool:
        step_numbers = {s.number for s in guide.steps}
        done = set(state.completed_steps.get(phase, []))
        return step_numbers.issubset(done)

    def advance_phase(self, profile_name: str, next_phase: int) -> SessionState:
        state = self.load(profile_name)
        state.current_phase = next_phase
        self.save(state)
        return state

    def _path(self, profile_name: str) -> Path:
        return self._session_dir / f"{profile_name}.json"
