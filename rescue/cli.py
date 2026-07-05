from pathlib import Path

import click

import rescue
from rescue.models import Mode, RiskLevel
from rescue.orchestrator import Orchestrator
from rescue.profiler.base import gather_profile
from rescue.registry import discover_modules


def _get_modules_dir() -> Path:
    return Path(__file__).parent.parent / "modules"


@click.group(invoke_without_command=True)
@click.option("--auto", is_flag=True, help="Run all checks and apply safe fixes automatically.")
@click.pass_context
def main(ctx, auto):
    """Multiverse Device Rescue — system diagnostic and repair toolkit."""
    if auto:
        _run_auto()
    elif ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@main.command()
def version():
    """Show version information."""
    click.echo(f"multiverse-device-rescue {rescue.__version__}")


@main.command()
@click.argument("module_names", nargs=-1, required=True)
@click.option("--yes", is_flag=True, help="Skip confirmation prompts.")
def run(module_names, yes):
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

    for mod in selected:
        check = mod.check(profile)
        click.echo(mod.report(check))
        if check.has_issues and (yes or mod.risk_level == RiskLevel.SAFE):
            fix = mod.fix(check, mode)
            click.echo(mod.report(check, fix))
        elif check.has_issues and not yes:
            if click.confirm(f"Apply fixes for {mod.name}?"):
                fix = mod.fix(check, mode)
                click.echo(mod.report(check, fix))
        click.echo()


def _run_auto():
    modules_dir = _get_modules_dir()
    orch = Orchestrator(modules_dir=modules_dir)
    results = orch.run_auto()

    total_issues = sum(len(check.findings) for _, check, _ in results)
    fixed = sum(1 for _, _, fix in results if fix is not None)

    click.echo("=" * 50)
    click.echo("Multiverse Device Rescue — Auto Mode")
    click.echo("=" * 50)
    click.echo(f"\nScanned {len(results)} module(s), found {total_issues} issue(s), applied {fixed} fix(es).\n")

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
