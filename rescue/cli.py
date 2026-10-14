import json
import re
import sys
from pathlib import Path

import click

import rescue
from rescue.ai.explainer import DiagnosticExplainer
from rescue.ai.factory import get_provider
from rescue.ai.providers.base import AIRequestError
from rescue.ai.recommender import ProfileRecommender
from rescue.app_fixes import AppFixesError, load_app_actions, load_app_fixes
from rescue.case import RescueCase, write_case
from rescue.guides import discover_guides
from rescue.models import ActionKind, CheckResult, Mode, RiskLevel
from rescue.orchestrator import Orchestrator
from rescue.profiler.base import detect_platform, gather_profile
from rescue.profiles import ProfileValidationError, discover_profiles, validate_profile_modules
from rescue.registry import discover_modules
from rescue.remediation import load_remediation_walkthroughs
from rescue.runtime import bundled_root, content_directory
from rescue.security.integrity import (
    DEFAULT_INTEGRITY_MANIFEST_PATH,
    IntegrityManifest,
    verify_package_integrity,
)
from rescue.security.signers import RevokedSignerStore, TrustConfigurationError
from rescue.session import SessionStore
from rescue.tui.app import run_tui
from rescue.update.config import default_config
from rescue.update.engine import UpdateEngine
from rescue.update.manifest import ManifestError
from rescue.update.repo import ContentRepo, GitError
from rescue.update.sideload import SideloadError, load_sideload_repo
from rescue.validate import validate_catalog


def _project_root() -> Path:
    """Root directory containing modules/, profiles/, and guides/.

    When running from a PyInstaller onefile bundle, these are extracted at
    startup to a temp directory exposed as sys._MEIPASS, mirroring the
    source tree layout (rescue.spec bundles them at the bundle root). We
    detect that case explicitly via sys.frozen rather than relying on
    __file__, since PyInstaller does not consistently resolve __file__ for
    the entry script across platforms/bootloaders.

    Outside of a frozen bundle (the normal `pip install`/source-checkout
    case), this is unchanged: two directories above this file.
    """
    return bundled_root()


def _get_modules_dir() -> Path:
    return _project_root() / "modules"


def _get_profiles_dir() -> Path:
    return content_directory("profiles")


def _get_guides_dir() -> Path:
    return content_directory("guides")


def _get_session_dir() -> Path:
    return Path.home() / ".rescue" / "sessions"


def _load_profile_or_exit(profile_name: str):
    profiles = discover_profiles(_get_profiles_dir())
    if profile_name not in profiles:
        click.echo(f"Unknown profile: {profile_name}", err=True)
        click.echo(f"Available: {', '.join(sorted(profiles.keys()))}", err=True)
        raise SystemExit(1)
    profile = profiles[profile_name]
    try:
        validate_profile_modules(profile, discover_modules(_get_modules_dir()))
    except ProfileValidationError as exc:
        click.echo(f"Invalid profile: {exc}", err=True)
        raise SystemExit(1) from exc
    return profile


@click.group(invoke_without_command=True)
@click.option("--auto", is_flag=True, help="Run all checks and apply safe fixes automatically.")
@click.option("--profile", "profile_name", default=None, help="Threat-model profile to apply (filters/configures modules).")
@click.option(
    "--copilot",
    is_flag=True,
    help="Enable AI-powered plain-language explanations (requires an API key or local Ollama).",
)
@click.pass_context
def main(ctx, auto, profile_name, copilot):
    """Multiverse Device Rescue — system diagnostic and repair toolkit."""
    _run_startup_integrity_check()
    if auto:
        _run_auto(profile_name, copilot=copilot)
    elif ctx.invoked_subcommand is None:
        run_tui(_get_modules_dir(), _get_guides_dir())


def _run_startup_integrity_check() -> None:
    """Best-effort, never blocking: warns if rescue's own installed files
    don't match the shipped integrity manifest, then always continues.

    Skipped entirely in a PyInstaller frozen bundle: the manifest is
    generated from loose .py files in a source checkout / pip install, but
    a onefile bundle has no such files on disk (they're compiled into the
    archive), so the comparison would always spuriously report everything
    as missing.
    """
    if getattr(sys, "frozen", False):
        return
    try:
        if not DEFAULT_INTEGRITY_MANIFEST_PATH.exists():
            return
        manifest = IntegrityManifest.from_json_bytes(DEFAULT_INTEGRITY_MANIFEST_PATH.read_bytes())
        package_root = Path(__file__).parent
        result = verify_package_integrity(package_root, manifest)
        if not result.ok:
            click.echo(
                "WARNING: rescue's own installed files do not match the expected integrity manifest.",
                err=True,
            )
            for rel in result.tampered:
                click.echo(f"  modified: {rel}", err=True)
            for rel in result.missing:
                click.echo(f"  missing:  {rel}", err=True)
            click.echo("Consider reinstalling the tool. Continuing with existing files.", err=True)
    except Exception:
        pass


@main.command()
def version():
    """Show version information."""
    click.echo(f"multiverse-device-rescue {rescue.__version__}")


@main.command()
@click.option("--json", "as_json", is_flag=True, help="Emit read-only check results as JSON on stdout.")
@click.option("--profile", "profile_name", default=None, help="Only run the modules a profile selects.")
@click.option(
    "--progress",
    is_flag=True,
    help='Write one {"progress": ...} JSON line per check to stderr as the scan runs.',
)
@click.option(
    "--trace",
    is_flag=True,
    help='Also write one {"exec": ...} JSON line to stderr for every external command run. Implies --progress.',
)
@click.option(
    "--no-attribution",
    is_flag=True,
    help='Skip the "Who made it?" lookups (code-signature checks) that add made_by to findings.',
)
def scan(as_json, profile_name, progress, trace, no_attribution):
    """Run read-only checks. With --json, print structured results to stdout."""
    from rescue.serialize import checks_to_json
    threat_profile = _load_profile_or_exit(profile_name) if profile_name else None
    profile = gather_profile()
    orch = Orchestrator(modules_dir=_get_modules_dir(), profile=threat_profile)
    if trace:
        results = _run_traced(orch)
    elif progress:
        results = orch.run_checks(on_progress=_emit_progress)
    else:
        results = orch.run_checks()
    if as_json:
        walkthroughs = load_remediation_walkthroughs(_get_guides_dir() / "remediation")
        made_by = None
        if not no_attribution:
            try:
                from rescue.attribution import compute_made_by
                made_by = compute_made_by(results, profile.platform.value)
            except Exception:
                made_by = None  # enrichment is optional; never break a scan
        try:
            app_fixes = load_app_fixes()
        except AppFixesError:
            app_fixes = {}  # unreadable list: offer nothing, never everything
        click.echo(checks_to_json(
            results, profile.platform.value, walkthroughs, app_fixes, made_by,
            app_actions=load_app_actions(),
        ))
        return
    for mod, check in results:
        click.echo(mod.report(check))


def _run_traced(orch):
    """Run the checks, reporting progress and every external command on stderr."""
    import json

    from rescue.trace import trace_commands

    current = {"module": None}

    def on_progress(phase, index, total, mod, check):
        current["module"] = mod.name if phase == "start" else None
        _emit_progress(phase, index, total, mod, check)

    def on_exec(event):
        click.echo(json.dumps({"exec": event}), err=True)

    with trace_commands(on_exec, current_module=lambda: current["module"]):
        return orch.run_checks(on_progress=on_progress)


def _emit_progress(phase, index, total, mod, check):
    """One machine-readable progress line on stderr (stdout stays pure JSON)."""
    import json

    event = {
        "phase": phase,
        "index": index,
        "total": total,
        "module": mod.name,
        "category": getattr(mod, "category", None),
    }
    if check is not None:
        event["findings"] = len(check.findings)
        event["error"] = check.error
    click.echo(json.dumps({"progress": event}), err=True)


@main.command()
@click.option("--profile", "profile_name", default=None, help="Only run the modules a profile selects.")
@click.option(
    "--output",
    "output_dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Directory to write the case into (default: ~/.rescue/cases).",
)
@click.option("--stdout", "to_stdout", is_flag=True, help="Print the JSON case instead of writing files.")
def export(profile_name, output_dir, to_stdout):
    """Run read-only checks and write a redacted rescue-case report.

    Produces a JSON record for tooling and a Markdown summary for people. Both
    are redacted: credential-shaped strings, email addresses, the account name,
    and the home-directory path are removed before anything is written.
    """
    profile = _load_profile_or_exit(profile_name) if profile_name else None

    system_profile = gather_profile()
    orch = Orchestrator(modules_dir=_get_modules_dir(), profile=profile)
    case = RescueCase(
        profile=system_profile,
        profile_name=profile_name,
        started_at=_utc_now(),
    )
    for mod, check in orch.run_checks():
        case.add(mod, check)
    case.finished_at = _utc_now()

    if to_stdout:
        from rescue.case import case_to_json

        click.echo(case_to_json(case))
        return

    directory = output_dir or (Path.home() / ".rescue" / "cases")
    json_path, md_path = write_case(case, directory)
    click.echo(f"Wrote {json_path}")
    click.echo(f"Wrote {md_path}")
    click.echo(
        "\nBoth files are redacted, but module output is free text — read them "
        "before sharing."
    )


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@main.command()
@click.option("--strict", is_flag=True, help="Treat warnings as failures (used by CI).")
def validate(strict):
    """Validate the shipped catalog: modules, profiles, guides, and their links.

    Checks that module names are unique, dependencies resolve without cycles,
    platforms and risk levels are declared correctly, every profile selects real
    modules, and no guide advertises a step as automatable that no module can
    perform. Exits non-zero when the catalog is inconsistent.
    """
    report = validate_catalog(
        modules_dir=_get_modules_dir(),
        profiles_dir=_get_profiles_dir(),
        guides_dir=_get_guides_dir(),
    )

    for problem in report.problems:
        click.echo(problem.format(), err=problem.severity.value == "error")

    click.echo(
        f"\n{report.module_count} modules, {report.profile_count} profiles, "
        f"{report.guide_count} guide phases checked: "
        f"{len(report.errors)} error(s), {len(report.warnings)} warning(s)."
    )
    if not report.ok(strict=strict):
        raise SystemExit(1)
    click.echo("Catalog is consistent.")


@main.command()
@click.argument("module_names", nargs=-1, required=True)
@click.option("--yes", is_flag=True, help="Skip confirmation prompts.")
@click.option(
    "--copilot",
    is_flag=True,
    help="Enable AI-powered plain-language explanations (requires an API key or local Ollama).",
)
def run(module_names, yes, copilot):
    """Run specific modules by name."""
    modules_dir = _get_modules_dir()
    all_modules = discover_modules(modules_dir)
    by_name = {m.name: m for m in all_modules}

    selected = []
    for name in module_names:
        if name not in by_name:
            click.echo(f"Unknown module: {name}", err=True)
            click.echo(f"Available: {', '.join(sorted(by_name.keys()))}", err=True)
            raise SystemExit(1)
        selected.append(by_name[name])

    profile = gather_profile()

    click.echo(f"System: {profile.os_name} {profile.os_version} | {profile.cpu_model} | {profile.architecture}")
    click.echo(f"Running {len(selected)} module(s)...\n")

    mode = Mode.CLI if yes else Mode.MANUAL

    checked = []
    for mod in selected:
        try:
            check = mod.check(profile)
        except Exception as exc:
            check = CheckResult(module_name=mod.name, error=str(exc))
        checked.append((mod, check))
        click.echo(mod.report(check))
        if check.error:
            click.echo()
            continue
        # Only apply a fix without asking when the operator passed --yes, or the
        # module has explicitly opted in to unattended, vetted SAFE mutation via
        # auto_apply. Otherwise confirm first — a fix() may perform a mutation,
        # and no externally-visible change should run unconfirmed (P0#5/#6).
        auto_ok = mod.risk_level == RiskLevel.SAFE and getattr(mod, "auto_apply", False)
        if check.has_issues and (yes or auto_ok):
            try:
                fix = mod.fix(check, mode)
            except Exception as exc:
                click.echo(f"Fix unavailable: {exc}", err=True)
                click.echo()
                continue
            click.echo(mod.report(check, fix))
        elif check.has_issues and not yes:
            if click.confirm(f"Apply fixes for {mod.name}?"):
                try:
                    fix = mod.fix(check, mode)
                except Exception as exc:
                    click.echo(f"Fix unavailable: {exc}", err=True)
                    click.echo()
                    continue
                click.echo(mod.report(check, fix))
        click.echo()

    if copilot:
        _print_ai_explanation(checked)


_MODULE_NAME = re.compile(r"^[a-z0-9_]+$")


def _fix_doc(module, **fields) -> dict:
    doc = {
        "module": module,
        "applied": False,
        "message": "",
        "changes": [],
        "how_to_undo": [],
        "verified": False,
        "status": "refused",
    }
    doc.update(fields)
    return doc


def _finding_keys(check) -> set:
    return {(f.code or "", f.title) for f in check.findings}


def _check_quietly(mod, profile):
    """Run check() with anything the module prints kept off stdout (it carries JSON)."""
    from contextlib import redirect_stdout

    with redirect_stdout(sys.stderr):
        return mod.check(profile)


def _apply_app_fix(module_name: str, acknowledged: bool) -> tuple[dict, int]:
    """Run one allowlisted fix. Returns (result document, exit code).

    Exit codes: 0 done or nothing to do, 1 not fixed, 2 refused, 3 unknown or
    unsupported module, 4 the check itself could not run.
    """
    from contextlib import redirect_stdout

    not_available = "This fix is not available in the app. Use the written steps instead."
    if not _MODULE_NAME.match(module_name):
        return _fix_doc(module_name, error="not_allowed", message=not_available), 2
    if not acknowledged:
        return _fix_doc(
            module_name,
            error="not_confirmed",
            message="Refusing to change anything without --i-understand.",
        ), 2
    try:
        allowed = load_app_fixes()
    except AppFixesError:
        allowed = {}
    entry = allowed.get(module_name)
    if entry is None:
        return _fix_doc(module_name, error="not_allowed", message=not_available), 2

    undo = list(entry.get("how_to_undo", []))
    by_name = {m.name: m for m in discover_modules(_get_modules_dir())}
    mod = by_name.get(module_name)
    if mod is None:
        return _fix_doc(module_name, error="unknown_module", message="That check was not found.", how_to_undo=undo), 3
    if mod.risk_level == RiskLevel.DESTRUCTIVE:
        return _fix_doc(module_name, error="not_allowed", message=not_available), 2
    if detect_platform() not in mod.platforms:
        return _fix_doc(
            module_name,
            error="unsupported_platform",
            message="This fix is not for this kind of computer.",
            how_to_undo=undo,
        ), 3

    profile = gather_profile()
    try:
        before = _check_quietly(mod, profile)
    except Exception as exc:
        before = CheckResult(module_name=module_name, error=str(exc))
    if before.error or not before.supported:
        return _fix_doc(
            module_name,
            error="check_failed",
            message="We could not check this setting, so we changed nothing: "
            + (before.error or before.unsupported_reason or "unsupported"),
            how_to_undo=undo,
        ), 4
    if not before.findings:
        return _fix_doc(
            module_name,
            status="nothing_to_fix",
            verified=True,
            message="There is nothing to fix. This already looks fine.",
            how_to_undo=undo,
        ), 0

    fix_error = None
    fix_result = None
    try:
        with redirect_stdout(sys.stderr):
            fix_result = mod.fix(before, Mode.CLI)
    except Exception as exc:
        fix_error = str(exc) or exc.__class__.__name__

    changes = []
    if fix_result is not None:
        changes = [
            {"title": a.title, "description": a.description, "success": bool(a.success), "error": a.error}
            for a in fix_result.actions
            if a.kind == ActionKind.MUTATION and a.executed
        ]
    failed = [c for c in changes if not c["success"]]
    applied = bool(changes) and not failed and fix_error is None

    # Always look again, even after a failure, so the answer reflects the computer.
    try:
        after = _check_quietly(mod, profile)
    except Exception as exc:
        after = CheckResult(module_name=module_name, error=str(exc))
    after_ok = not after.error and after.supported
    still = (_finding_keys(before) & _finding_keys(after)) if after_ok else _finding_keys(before)
    verified = applied and after_ok and not still

    if fix_error is not None:
        status, message = "failed", f"The change did not go through: {fix_error}"
    elif failed:
        status = "failed"
        message = "The change did not go through: " + "; ".join(c["error"] or c["title"] for c in failed)
    elif not applied:
        status, message = "failed", "Nothing was changed."
    elif verified:
        status, message = "fixed", "Done, and checked again: fixed."
    else:
        status = "not_fixed"
        message = "We made the change, but when we checked again the problem still shows."
    doc = _fix_doc(
        module_name,
        applied=applied,
        message=message,
        changes=changes,
        how_to_undo=undo,
        verified=bool(verified),
        status=status,
    )
    return doc, 0 if status == "fixed" else 1


def _apply_app_action(action: str, target: str | None, acknowledged: bool) -> tuple[dict, int]:
    """Run one allowlisted engine-level action (not a module fix())."""
    from rescue.actions import launch_agent

    if not acknowledged:
        return _fix_doc(
            action, action=action, error="not_confirmed",
            message="Refusing to change anything without --i-understand.",
        ), 2
    if action not in load_app_actions() or action != launch_agent.ACTION:
        return _fix_doc(
            action, action=action, error="not_allowed",
            message="This fix is not available in the app. Use the written steps instead.",
        ), 2
    if not target:
        return _fix_doc(action, action=action, error="not_allowed", message="No target was given. We changed nothing."), 2
    doc = launch_agent.disable(target)
    return doc, launch_agent.exit_code(doc)


@main.command(name="fix")
@click.argument("module_name", required=False)
@click.option("--action", "action", default=None, help="An engine-level action, e.g. disable_launch_agent.")
@click.option("--target", "target", default=None, help="What the action acts on (a plist path).")
@click.option("--json", "as_json", is_flag=True, help="Emit the result as one JSON document on stdout.")
@click.option(
    "--i-understand",
    "acknowledged",
    is_flag=True,
    help="Required. Confirms the person has been told what will change and agreed.",
)
def fix_cmd(module_name, action, target, as_json, acknowledged):
    """Apply one audited fix (only modules/actions listed in rescue/app_fixes.json)."""
    if action is not None and module_name is None:
        doc, code = _apply_app_action(action, target, acknowledged)
    elif module_name is not None and action is None and target is None:
        doc, code = _apply_app_fix(module_name, acknowledged)
    else:
        doc, code = _fix_doc(
            module_name or action or "", error="not_allowed",
            message="Name either a check, or --action with --target. We changed nothing.",
        ), 2
    if as_json:
        click.echo(json.dumps(doc, indent=2))
    else:
        click.echo(doc["message"])
        for step in doc["how_to_undo"]:
            click.echo(f"  To undo: {step}")
    if code:
        raise SystemExit(code)


@main.command(name="undo")
@click.option("--quarantine-id", "quarantine_id", required=True, help="The id returned when the job was turned off.")
@click.option("--json", "as_json", is_flag=True, help="Emit the result as one JSON document on stdout.")
def undo_cmd(quarantine_id, as_json):
    """Put back a background job that Device Rescue turned off."""
    from rescue.actions import launch_agent

    doc = launch_agent.restore(quarantine_id)
    if as_json:
        click.echo(json.dumps(doc, indent=2))
    else:
        click.echo(doc["message"])
    code = launch_agent.exit_code(doc)
    if code:
        raise SystemExit(code)


@main.command(name="profiles")
def list_profiles_cmd():
    """List available threat-model profiles."""
    profiles = discover_profiles(_get_profiles_dir())
    if not profiles:
        click.echo("No profiles found.")
        return
    for name in sorted(profiles):
        p = profiles[name]
        click.echo(f"{p.name} — {p.display_name}")
        if p.description:
            click.echo(f"    {p.description.strip()}")


@main.command()
@click.argument("profile_name")
@click.option("--complete", "complete_step", type=int, default=None, help="Mark a step number complete in the current phase.")
def guide(profile_name, complete_step):
    """Render the guide walkthrough for a profile, resuming saved progress."""
    profile = _load_profile_or_exit(profile_name)

    guides = discover_guides(_get_guides_dir(), profile_name)
    if not guides:
        click.echo(f"No guide content found for profile: {profile_name}")
        return

    store = SessionStore(session_dir=_get_session_dir())
    state = store.load(profile_name)

    phases_available = sorted(g.phase for g in guides)

    # If the session's current phase doesn't correspond to any authored
    # guide (e.g. a fresh session and this guide set's phases don't start
    # at 0), jump forward to the first authored phase *before* recording
    # any completion, so progress lands on the right phase.
    if state.current_phase not in phases_available and state.current_phase < phases_available[0]:
        state = store.advance_phase(profile_name, phases_available[0])

    if complete_step is not None:
        state = store.mark_step_complete(profile_name, state.current_phase, complete_step)
        click.echo(f"Marked step {complete_step} complete for phase {state.current_phase}.\n")

    current_guide = next((g for g in guides if g.phase == state.current_phase), None)
    if current_guide is None:
        click.echo("All phases complete!")
        return

    if store.is_phase_complete(state, current_guide.phase, current_guide):
        next_phase = current_guide.phase + 1
        next_guide = next((g for g in guides if g.phase == next_phase), None)
        if next_guide is not None:
            state = store.advance_phase(profile_name, next_phase)
            click.echo(f"Phase {current_guide.phase} complete! Moving to Phase {next_phase}.\n")
            current_guide = next_guide
        else:
            click.echo("All phases complete!")
            return

    done_steps = set(state.completed_steps.get(current_guide.phase, []))
    click.echo(f"=== {profile.display_name}: Phase {current_guide.phase} — {current_guide.title} ===")
    click.echo(f"Estimated time: {current_guide.estimated_time}\n")
    for step in current_guide.steps:
        tag = "automatable" if step.automatable else "human"
        status = "done" if step.number in done_steps else "pending"
        click.echo(f"[{tag}] [{status}] Step {step.number}: {step.title}")
    click.echo("\nRun again with --complete <step number> to mark a step done.")


def _run_auto(profile_name: str | None = None, copilot: bool = False):
    modules_dir = _get_modules_dir()
    profile = _load_profile_or_exit(profile_name) if profile_name else None

    orch = Orchestrator(modules_dir=modules_dir, profile=profile)
    results = orch.run_auto()

    total_issues = sum(len(check.findings) for _, check, _ in results)
    system_changes = sum(
        len(fix.executed_mutations)
        for _, _, fix in results
        if fix is not None
    )
    manual_actions = sum(
        len(fix.guidance_actions)
        for _, _, fix in results
        if fix is not None
    )

    click.echo("=" * 50)
    click.echo("Multiverse Device Rescue — Auto Mode")
    if profile:
        click.echo(f"Profile: {profile.display_name}")
    click.echo("=" * 50)
    click.echo(
        f"\nScanned {len(results)} module(s), found {total_issues} issue(s). "
        f"Auto mode is read-only: made {system_changes} system change(s); "
        f"{manual_actions} manual action(s) require you.\n"
    )

    for mod, check, fix in results:
        if check.has_issues:
            click.echo(mod.report(check, fix))
            click.echo()

    skipped = [
        (mod, check)
        for mod, check, fix in results
        if check.has_issues and fix is None
    ]
    if skipped:
        click.echo("--- Skipped (requires confirmation) ---")
        for mod, check in skipped:
            click.echo(f"  [{mod.risk_level.value}] {mod.name}: {len(check.findings)} issue(s)")
        click.echo("\nRun 'rescue run <module>' to address these individually.")

    if profile and profile.guides:
        click.echo("\n--- Guided walkthroughs available for this profile ---")
        for guide_name in profile.guides:
            click.echo(f"  Run 'rescue guide {guide_name}' to continue.")

    if copilot:
        _print_ai_explanation([(mod, check) for mod, check, _ in results])


def _print_ai_explanation(checked: list) -> None:
    """Only ever called when the user explicitly passed --copilot (or ran a
    command, like `explain`, that is itself an explicit opt-in to the AI layer).

    The AI layer is optional and must never take down the deterministic
    check/fix run that already happened by this point — any failure talking
    to the provider is caught and reported as a warning, not raised.
    """
    provider = get_provider()
    if provider is None:
        click.echo("--copilot requested but no AI provider is configured.")
        click.echo("Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or OLLAMA_HOST, then try again.\n")
        return
    explainer = DiagnosticExplainer(provider)
    try:
        explanation = explainer.explain(checked)
    except AIRequestError as exc:
        click.echo("--- AI Copilot Explanation ---")
        click.echo(f"AI explanation unavailable: {exc}")
        click.echo("(the scan results above are unaffected)\n")
        return
    click.echo("--- AI Copilot Explanation ---")
    click.echo(explanation.narrative)
    click.echo(f"(via {explanation.provider_name})\n")


@main.command()
def recommend():
    """Answer a few questions to get a recommended threat-model profile.

    This command is itself the explicit opt-in to the AI layer — like
    --copilot for --auto/run, it never runs unless the user asks for it.
    """
    provider = get_provider()
    if provider is None:
        click.echo("This feature requires an AI provider.")
        click.echo("Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or OLLAMA_HOST, then try again.")
        return

    recommender = ProfileRecommender(provider)
    click.echo("What brings you in today? (type 'quit' to exit)\n")

    user_input = click.prompt(">")
    while True:
        if user_input.strip().lower() in ("quit", "exit"):
            click.echo("No recommendation made.")
            return
        try:
            turn = recommender.ask(user_input)
        except AIRequestError as exc:
            click.echo(f"\nAI request failed: {exc}")
            click.echo("Try again, or type 'quit' to exit.\n")
            user_input = click.prompt(">")
            continue
        click.echo(f"\n{turn.message}\n")
        if turn.is_recommendation:
            click.echo(f"Recommended profile: {turn.profile_slug}")
            return
        user_input = click.prompt(">")


@main.command("remediation-catalog")
def remediation_catalog():
    """Regenerate docs/REMEDIATION_CATALOG.md from modules + walkthroughs."""
    from rescue.registry import discover_modules
    from rescue.remediation import (
        build_catalog, load_remediation_walkthroughs, render_catalog_markdown)

    modules = discover_modules(_get_modules_dir())
    index = load_remediation_walkthroughs(_get_guides_dir() / "remediation")
    rows = build_catalog(modules, index)
    out = _project_root() / "docs" / "REMEDIATION_CATALOG.md"
    # Explicit UTF-8: this markdown contains em-dashes and curly quotes, and
    # the locale codec on Windows (cp1252) either mangles them or raises.
    out.write_text(render_catalog_markdown(rows), encoding="utf-8")
    click.echo(f"Wrote {out} ({len(rows)} codes)")


@main.command("threat-remediation")
def threat_remediation():
    """Regenerate docs/THREAT_REMEDIATION.md from the threat map."""
    from rescue.profiles import discover_profiles
    from rescue.registry import discover_modules
    from rescue.threat_map import (
        load_threat_map, render_threat_markdown, validate_threat_map)

    mods = discover_modules(_get_modules_dir())
    all_modules = {m.name for m in mods}
    all_codes = set()
    for m in mods:
        all_codes |= set(getattr(m, "emits_codes", []))
    profs = discover_profiles(_get_profiles_dir())
    profiles = {n: ((set(p.include_modules) or all_modules) - set(p.exclude_modules))
                for n, p in profs.items()}
    threats = load_threat_map(_project_root() / "docs" / "threat_remediation_map.yaml")
    errors = validate_threat_map(threats, profiles, all_codes, all_modules)
    if errors:
        for e in errors:
            click.echo("ERROR: " + e, err=True)
        raise SystemExit(1)
    out = _project_root() / "docs" / "THREAT_REMEDIATION.md"
    out.write_text(render_threat_markdown(threats, profiles), encoding="utf-8")
    click.echo(f"Wrote {out} ({len(threats)} threats)")


@main.command()
def explain():
    """Run all diagnostic checks and print an AI plain-language explanation.

    This command is itself the explicit opt-in to the AI layer, like
    --copilot for --auto/run: it runs checks fresh (never applies fixes) and
    hands the findings to the configured AI provider for a narrative.
    """
    provider = get_provider()
    if provider is None:
        click.echo("This feature requires an AI provider.")
        click.echo("Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or OLLAMA_HOST, then try again.")
        return

    modules_dir = _get_modules_dir()
    all_modules = discover_modules(modules_dir)
    profile = gather_profile()

    checked = [(mod, mod.check(profile)) for mod in all_modules]
    _print_ai_explanation(checked)


@main.command()
@click.option("--check", is_flag=True, help="Check for updates without applying them.")
@click.option("--dry-run", is_flag=True, help="Show what would change without applying it.")
@click.option("--yes", is_flag=True, help="Apply without an interactive confirmation prompt.")
@click.option(
    "--sideload",
    "sideload_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Apply a signed update from a local git bundle file (air-gapped).",
)
@click.option(
    "--rollback",
    is_flag=True,
    help="Return to the content version that was applied before the current one.",
)
@click.option(
    "--use-bundled",
    "use_bundled",
    is_flag=True,
    help="Deactivate downloaded content and use what shipped with the install.",
)
def update(check, dry_run, yes, sideload_path, rollback, use_bundled):
    """Update module data and guide content from the content repository."""
    config = default_config()

    if rollback and use_bundled:
        click.echo("--rollback and --use-bundled cannot be combined.", err=True)
        raise SystemExit(2)

    if rollback or use_bundled:
        _update_recovery(config, rollback=rollback, dry_run=dry_run)
        return

    try:
        if sideload_path is not None:
            repo = load_sideload_repo(sideload_path, config)
            engine = UpdateEngine(config, repo=repo)
        else:
            engine = UpdateEngine(config)
            engine.refresh()
    except (GitError, SideloadError, TrustConfigurationError) as exc:
        click.echo(f"Update failed: {exc}", err=True)
        click.echo("Continuing with existing content.", err=True)
        raise SystemExit(1)

    result = engine.status()

    if result.status == "up_to_date":
        click.echo("Content is already up to date.")
        return

    if result.status == "pending_approval":
        click.echo(result.message)
        click.echo("Refusing to apply -- not enough maintainer approvals yet.")
        raise SystemExit(1)

    click.echo(f"Update available: {result.content_version or result.new_commit[:12]}")
    click.echo(result.message)
    if result.commits:
        click.echo("\nChanges:")
        for commit in result.commits:
            click.echo(f"  {commit.sha[:10]}  {commit.subject}  ({commit.author})")

    if check:
        return

    if dry_run:
        preview = engine.apply(result, dry_run=True)
        click.echo(f"\n{preview.message}")
        return

    if not yes and not click.confirm("\nApply this update?"):
        click.echo("Update cancelled.")
        return

    try:
        applied = engine.apply(result, dry_run=False)
    except ManifestError as exc:
        click.echo(f"Update rejected: {exc}", err=True)
        raise SystemExit(1) from exc
    click.echo(applied.message)


def _update_recovery(config, *, rollback: bool, dry_run: bool) -> None:
    """Back out of a content update (roadmap P0#2).

    Neither path fetches anything: rolling back to a version this machine
    already had, or falling back to what the install shipped with, must work
    when the network is the problem — or when the update is.
    """
    if not rollback:
        # Deliberately does NOT construct an UpdateEngine. Doing so validates
        # the trusted-signer configuration, and a machine whose trust config is
        # broken or unpopulated is exactly the machine that most needs to be
        # able to fall back to the content it was installed with. An escape
        # hatch that depends on the thing that failed is not an escape hatch.
        repo = ContentRepo(config.local_path, config.remote_url)
        repo.clear_applied_marker()
        click.echo(
            "Updated content is deactivated. The tool will use the modules, profiles "
            "and guides that shipped with the installed package. Nothing was deleted; "
            "`rescue update` can activate downloaded content again."
        )
        return

    try:
        engine = UpdateEngine(config)
    except (GitError, TrustConfigurationError) as exc:
        click.echo(f"Cannot load the content repository: {exc}", err=True)
        click.echo(
            "`rescue update --use-bundled` still works: it needs no signature check.",
            err=True,
        )
        raise SystemExit(1) from exc

    try:
        result = engine.rollback(dry_run=dry_run)
    except (GitError, ManifestError) as exc:
        click.echo(f"Rollback failed: {exc}", err=True)
        raise SystemExit(1) from exc

    click.echo(result.message)
    if result.status in ("no_previous_version", "pending_approval"):
        raise SystemExit(1)


@main.group()
def trust():
    """Manage locally-revoked content-repo signers."""


@trust.command("revoke")
@click.argument("signer_id")
@click.option("--reason", required=True, help="Why this signer is being revoked.")
def trust_revoke(signer_id, reason):
    """Stop trusting a signer's approvals on this machine, effective immediately."""
    config = default_config()
    store = RevokedSignerStore(config.revoked_signers_path)
    store.revoke(signer_id, reason)
    click.echo(f"Revoked signer '{signer_id}': {reason}")


@trust.command("list-revoked")
def trust_list_revoked():
    """List signer IDs revoked on this machine."""
    config = default_config()
    store = RevokedSignerStore(config.revoked_signers_path)
    revoked = store.revoked_signer_ids()
    if not revoked:
        click.echo("No signers revoked on this machine.")
        return
    for signer_id in sorted(revoked):
        click.echo(signer_id)


if __name__ == "__main__":
    # Entry point when this module is run directly, e.g. as the PyInstaller
    # bundle's frozen script (see rescue.spec). Normal installs invoke
    # `main` via the `rescue` console-script defined in pyproject.toml
    # instead, which never triggers this block.
    main()
