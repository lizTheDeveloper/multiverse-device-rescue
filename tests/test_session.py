from rescue.guides import Guide, GuideStep
from rescue.session import SessionState, SessionStore


def _make_guide(phase: int, step_numbers: list[int]) -> Guide:
    return Guide(
        profile="test_profile",
        phase=phase,
        title="Test Phase",
        estimated_time="10 minutes",
        steps=[
            GuideStep(number=n, title=f"Step {n}", body="", automatable=False)
            for n in step_numbers
        ],
        automatable_steps=[],
        human_only_steps=step_numbers,
    )


def test_load_returns_fresh_state_when_no_file(tmp_path):
    store = SessionStore(session_dir=tmp_path)
    state = store.load("new_profile")

    assert state.profile == "new_profile"
    assert state.completed_steps == {}
    assert state.current_phase == 0


def test_save_and_load_round_trip(tmp_path):
    store = SessionStore(session_dir=tmp_path)
    state = SessionState(profile="test_profile", completed_steps={1: [1, 2]}, current_phase=1)

    store.save(state)
    loaded = store.load("test_profile")

    assert loaded.profile == "test_profile"
    assert loaded.completed_steps == {1: [1, 2]}
    assert loaded.current_phase == 1


def test_mark_step_complete_creates_and_updates(tmp_path):
    store = SessionStore(session_dir=tmp_path)

    store.mark_step_complete("test_profile", phase=2, step=1)
    state = store.mark_step_complete("test_profile", phase=2, step=3)

    assert state.completed_steps[2] == [1, 3]


def test_mark_step_complete_is_idempotent(tmp_path):
    store = SessionStore(session_dir=tmp_path)

    store.mark_step_complete("test_profile", phase=1, step=5)
    state = store.mark_step_complete("test_profile", phase=1, step=5)

    assert state.completed_steps[1] == [5]


def test_is_phase_complete_true_when_all_steps_done(tmp_path):
    store = SessionStore(session_dir=tmp_path)
    guide = _make_guide(phase=1, step_numbers=[1, 2, 3])

    store.mark_step_complete("test_profile", phase=1, step=1)
    store.mark_step_complete("test_profile", phase=1, step=2)
    state = store.mark_step_complete("test_profile", phase=1, step=3)

    assert store.is_phase_complete(state, phase=1, guide=guide) is True


def test_is_phase_complete_false_when_steps_missing(tmp_path):
    store = SessionStore(session_dir=tmp_path)
    guide = _make_guide(phase=1, step_numbers=[1, 2, 3])

    state = store.mark_step_complete("test_profile", phase=1, step=1)

    assert store.is_phase_complete(state, phase=1, guide=guide) is False


def test_advance_phase_updates_current_phase(tmp_path):
    store = SessionStore(session_dir=tmp_path)
    store.mark_step_complete("test_profile", phase=0, step=1)

    state = store.advance_phase("test_profile", next_phase=1)

    assert state.current_phase == 1
    # advancing preserves prior completed step history
    assert state.completed_steps[0] == [1]


def test_session_dir_created_if_missing(tmp_path):
    session_dir = tmp_path / "nested" / "sessions"
    assert not session_dir.exists()

    SessionStore(session_dir=session_dir)

    assert session_dir.exists()
