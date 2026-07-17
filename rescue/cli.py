import sys
from pathlib import Path

import click

import rescue
from rescue.ai.explainer import DiagnosticExplainer
from rescue.ai.factory import get_provider
from rescue.ai.providers.base import AIRequestError
from rescue.ai.recommender import ProfileRecommender
from rescue.guides import discover_guides
from rescue.models import Mode, RiskLevel
from rescue.orchestrator import Orchestrator
from rescue.profiler.base import gather_profile
from rescue.profiles import ProfileValidationError, discover_profiles, validate_profile_modules
from rescue.registry import discover_modules
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
from rescue.update.repo import GitError
from rescue.update.sideload import SideloadError, load_sideload_repo


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
        run_tui(_get_modules_dir())


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
        if check.has_issues and (yes or mod.risk_level == RiskLevel.SAFE):
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
def update(check, dry_run, yes, sideload_path):
    """Update module data and guide content from the content repository."""
    config = default_config()

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
