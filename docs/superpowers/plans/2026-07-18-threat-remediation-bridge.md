# Threat ↔ Remediation Bridge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A validated threat→remediation map in the tool that generates a public `THREAT_REMEDIATION.md`, wired both ways with the curriculum's threat content.

**Architecture:** `docs/threat_remediation_map.yaml` (source of truth) → `rescue/threat_map.py` (load/validate/render) → `rescue threat-remediation` subcommand → `docs/THREAT_REMEDIATION.md`. A validation gate enforces that each threat's run target actually scans the modules owning its codes. Phase 2 adds reverse links in the curriculum.

**Tech Stack:** Python 3.14, dataclasses, PyYAML, Click, pytest. Phase 2: Obsidian vault (git) + Pages CMS (`/x/`) + HedgeDoc, per `docs/AGENT_PUBLISHING_GUIDE.md`.

## Global Constraints

- Purely additive to the tool repo — no change to existing modules, profiles, walkthroughs, `remediation-catalog`, or the catalog.
- Code→module parsing uses the `<category>.<module>.<slug>` scheme (`code.split(".")[1]` is the owning module).
- A threat's `run` block has **exactly one** of `profile` / `modules` / `full`.
- **Coverage rule:** the modules owning a threat's resolved `codes` must be scanned by its run target — a subset of the profile's effective modules (`include`−`exclude`, empty include = all), of the explicit `modules` list, or trivially satisfied by `full`.
- Profile effective modules: `(set(include) or all_module_names) - set(exclude)`.
- Every threat needs non-empty `id` (unique, kebab-case), `title`, `summary`, `curriculum_url`.
- Generator output is deterministic (regenerating with no change is a no-op).
- Curriculum→tool links target `https://github.com/lizTheDeveloper/multiverse-device-rescue/blob/main/docs/THREAT_REMEDIATION.md#<id>`. **Prerequisite for those links to resolve: the tool work must be on `main`.** (Flagged in Phase 2.)

---

### Task 1: `threat_map.py` — model, loader, validation

**Files:**
- Create: `rescue/threat_map.py`
- Test: `tests/test_threat_map.py`

**Interfaces:**
- Produces: `Threat`, `RunTarget` dataclasses; `load_threat_map(path)->list[Threat]`; `expand_codes(patterns, all_codes)->set[str]`; `modules_for_codes(codes)->set[str]`; `run_target_modules(run, profiles)->set[str]|None`; `validate_threat_map(threats, profiles, all_codes, all_modules)->list[str]`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_threat_map.py`:

```python
from rescue.threat_map import (
    RunTarget, Threat, expand_codes, modules_for_codes,
    run_target_modules, validate_threat_map,
)

ALL_CODES = {
    "security.ai_worm_persistence.deadman_switch_launchagent",
    "security.ai_worm_persistence.known_malicious_launchagent",
    "security.ssh_key_audit.world_readable_key",
    "security.firewall_audit.firewall_disabled",
}
ALL_MODULES = {"ai_worm_persistence", "ssh_key_audit", "firewall_audit", "remote_login_check"}
PROFILES = {"ai_worm_response": {"ai_worm_persistence"}, "hygiene": {"remote_login_check"}}


def test_expand_codes_exact_glob_and_nomatch():
    assert expand_codes(["security.ssh_key_audit.world_readable_key"], ALL_CODES) == {
        "security.ssh_key_audit.world_readable_key"}
    assert expand_codes(["security.ai_worm_persistence.*"], ALL_CODES) == {
        "security.ai_worm_persistence.deadman_switch_launchagent",
        "security.ai_worm_persistence.known_malicious_launchagent"}
    assert expand_codes(["security.nope.*"], ALL_CODES) == set()


def test_modules_for_codes():
    assert modules_for_codes({"security.ssh_key_audit.world_readable_key"}) == {"ssh_key_audit"}


def test_run_target_modules_variants():
    assert run_target_modules(RunTarget(profile="ai_worm_response"), PROFILES) == {"ai_worm_persistence"}
    assert run_target_modules(RunTarget(modules=["ssh_key_audit"]), PROFILES) == {"ssh_key_audit"}
    assert run_target_modules(RunTarget(full=True), PROFILES) is None


def _threat(**kw):
    base = dict(id="t", title="T", summary="S", run=RunTarget(full=True),
                codes=["security.ssh_key_audit.world_readable_key"],
                curriculum_url="https://x", curriculum_section="Sec")
    base.update(kw)
    return Threat(**base)


def test_valid_map_has_no_errors():
    t = _threat(run=RunTarget(modules=["ssh_key_audit"]))
    assert validate_threat_map([t], PROFILES, ALL_CODES, ALL_MODULES) == []


def test_two_run_targets_errors():
    t = _threat(run=RunTarget(profile="ai_worm_response", full=True))
    assert any("exactly one" in e for e in validate_threat_map([t], PROFILES, ALL_CODES, ALL_MODULES))


def test_unknown_profile_and_module_error():
    assert any("unknown profile" in e for e in validate_threat_map(
        [_threat(run=RunTarget(profile="ghost"))], PROFILES, ALL_CODES, ALL_MODULES))
    assert any("unknown module" in e for e in validate_threat_map(
        [_threat(run=RunTarget(modules=["ghost"]))], PROFILES, ALL_CODES, ALL_MODULES))


def test_zero_resolving_code_error():
    assert any("no real code" in e for e in validate_threat_map(
        [_threat(codes=["security.ghost.x"])], PROFILES, ALL_CODES, ALL_MODULES))


def test_coverage_violation_error():
    # run target is ai_worm_response (only scans ai_worm_persistence), but the
    # code is owned by ssh_key_audit -> coverage violation.
    t = _threat(run=RunTarget(profile="ai_worm_response"),
                codes=["security.ssh_key_audit.world_readable_key"])
    assert any("does not scan" in e for e in validate_threat_map([t], PROFILES, ALL_CODES, ALL_MODULES))


def test_missing_field_and_dup_id_errors():
    assert any("missing summary" in e for e in validate_threat_map(
        [_threat(summary="")], PROFILES, ALL_CODES, ALL_MODULES))
    errs = validate_threat_map([_threat(id="dup"), _threat(id="dup")], PROFILES, ALL_CODES, ALL_MODULES)
    assert any("duplicate id" in e for e in errs)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_threat_map.py -v`
Expected: FAIL (`ModuleNotFoundError: rescue.threat_map`)

- [ ] **Step 3: Implement `rescue/threat_map.py`**

```python
"""Threat -> remediation map: load, validate, and (Task 2) render.

A threat maps a curriculum-described threat type to what to RUN in the tool
(a profile, explicit modules, or a full scan), the finding-code clusters it
covers, and the curriculum write-up that explains it. The validation gate
guarantees the run target actually scans the modules owning the threat's codes.
"""

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class RunTarget:
    profile: str | None = None
    modules: list[str] = field(default_factory=list)
    full: bool = False


@dataclass
class Threat:
    id: str
    title: str
    summary: str
    run: RunTarget
    codes: list[str] = field(default_factory=list)
    curriculum_url: str = ""
    curriculum_section: str = ""


def load_threat_map(path: Path) -> list[Threat]:
    data = yaml.safe_load(path.read_text()) or {}
    threats: list[Threat] = []
    for t in data.get("threats", []) or []:
        run = t.get("run", {}) or {}
        threats.append(Threat(
            id=(t.get("id") or "").strip(),
            title=(t.get("title") or "").strip(),
            summary=(t.get("summary") or "").strip(),
            run=RunTarget(
                profile=run.get("profile"),
                modules=list(run.get("modules", []) or []),
                full=bool(run.get("full", False)),
            ),
            codes=list(t.get("codes", []) or []),
            curriculum_url=(t.get("curriculum_url") or "").strip(),
            curriculum_section=(t.get("curriculum_section") or "").strip(),
        ))
    return threats


def expand_codes(patterns, all_codes) -> set[str]:
    all_codes = set(all_codes)
    out: set[str] = set()
    for p in patterns:
        if p in all_codes:
            out.add(p)
        elif any(ch in p for ch in "*?["):
            out |= {c for c in all_codes if fnmatch.fnmatch(c, p)}
    return out


def modules_for_codes(codes) -> set[str]:
    return {c.split(".")[1] for c in codes if c.count(".") >= 2}


def run_target_modules(run: RunTarget, profiles) -> set[str] | None:
    if run.full:
        return None
    if run.profile is not None:
        return set(profiles.get(run.profile, set()))
    return set(run.modules)


def _target_count(run: RunTarget) -> int:
    return sum([run.profile is not None, bool(run.modules), bool(run.full)])


def validate_threat_map(threats, profiles, all_codes, all_modules) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for t in threats:
        where = f"threat '{t.id or '<no id>'}'"
        if not t.id:
            errors.append(f"{where}: missing id")
        elif t.id in seen:
            errors.append(f"{where}: duplicate id")
        else:
            seen.add(t.id)
        for fld in ("title", "summary", "curriculum_url"):
            if not getattr(t, fld):
                errors.append(f"{where}: missing {fld}")
        n = _target_count(t.run)
        if n != 1:
            errors.append(f"{where}: run must have exactly one of profile/modules/full (found {n})")
        else:
            if t.run.profile is not None and t.run.profile not in profiles:
                errors.append(f"{where}: unknown profile '{t.run.profile}'")
            for m in t.run.modules:
                if m not in all_modules:
                    errors.append(f"{where}: unknown module '{m}'")
        resolved: set[str] = set()
        for p in t.codes:
            got = expand_codes([p], all_codes)
            if not got:
                errors.append(f"{where}: code pattern '{p}' matches no real code")
            resolved |= got
        target = run_target_modules(t.run, profiles)
        if target is not None:  # not a full scan
            missing = modules_for_codes(resolved) - target
            if missing:
                errors.append(
                    f"{where}: run target does not scan module(s) owning its codes: {sorted(missing)}")
    return errors
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_threat_map.py -v`
Expected: PASS (all)

- [ ] **Step 5: Run full suite + commit**

```bash
pytest -q
git add rescue/threat_map.py tests/test_threat_map.py
git commit -m "feat: threat map model, loader, and validation"
```

---

### Task 2: `render_threat_markdown`

**Files:**
- Modify: `rescue/threat_map.py` (append)
- Test: `tests/test_threat_map.py` (append)

**Interfaces:**
- Consumes: `Threat`, `RunTarget` (Task 1).
- Produces: `render_threat_markdown(threats, profiles) -> str`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_threat_map.py`:

```python
def test_render_markdown_all_run_variants_and_links():
    from rescue.threat_map import render_threat_markdown
    threats = [
        _threat(id="worm", title="AI worm", run=RunTarget(profile="ai_worm_response"),
                codes=["security.ai_worm_persistence.known_malicious_launchagent"]),
        _threat(id="ssh", title="SSH keys", run=RunTarget(modules=["ssh_key_audit"])),
        _threat(id="all", title="General", run=RunTarget(full=True)),
    ]
    md = render_threat_markdown(threats, PROFILES)
    assert '<a id="worm"></a>' in md and '<a id="ssh"></a>' in md and '<a id="all"></a>' in md
    assert "`rescue --profile ai_worm_response`" in md
    assert "`rescue run ssh_key_audit`" in md
    assert "`rescue`" in md  # full scan
    assert "[Sec](https://x)" in md  # curriculum link uses section as label
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_threat_map.py -k render -v`
Expected: FAIL (`ImportError: cannot import name 'render_threat_markdown'`)

- [ ] **Step 3: Implement**

Append to `rescue/threat_map.py`:

```python
def _run_line(run: RunTarget) -> str:
    if run.full:
        return "`rescue`  (full interactive scan)"
    if run.profile is not None:
        return f"`rescue --profile {run.profile}`"
    return "`rescue run " + " ".join(run.modules) + "`"


def render_threat_markdown(threats, profiles) -> str:
    lines = [
        "# Threat Remediation",
        "",
        "> Generated by `rescue threat-remediation`. Do not edit by hand.",
        "",
        "For each threat the security curriculum describes, here is what to run in "
        "Multiverse Device Rescue to check and remediate your own device.",
        "",
    ]
    for t in threats:
        lines.append(f"## {t.title}")
        lines.append(f'<a id="{t.id}"></a>')
        lines.append("")
        if t.summary:
            lines.append(t.summary)
            lines.append("")
        lines.append(f"**Run:** {_run_line(t.run)}")
        lines.append("")
        if t.codes:
            lines.append("**Covers:** " + ", ".join(f"`{c}`" for c in t.codes))
            lines.append("")
        if t.curriculum_url:
            label = t.curriculum_section or "the curriculum"
            lines.append(f"**Learn more:** [{label}]({t.curriculum_url})")
            lines.append("")
    return "\n".join(lines) + "\n"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_threat_map.py -k render -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add rescue/threat_map.py tests/test_threat_map.py
git commit -m "feat: render THREAT_REMEDIATION markdown"
```

---

### Task 3: Ship the map, subcommand, generated doc, README pointer, and gate

**Files:**
- Create: `docs/threat_remediation_map.yaml`
- Modify: `rescue/cli.py` (Click subcommand), `README.md` (pointer)
- Create: `docs/THREAT_REMEDIATION.md` (generated), `tests/test_threat_map_validation.py`

**Interfaces:**
- Consumes: `discover_modules` (registry), `discover_profiles` (profiles), Task 1-2 functions, `_get_modules_dir`/`_get_profiles_dir`/`_project_root` (cli.py).

- [ ] **Step 1: Author `docs/threat_remediation_map.yaml`**

Write the 8 threats from the spec. For each: pick the run target so the coverage rule holds (profile only when it includes the code-owning modules; else `modules`; else `full`), and `codes` globs over that threat's real namespaces. Reference real namespaces: `security.ai_worm_{filesystem,git_ssh,persistence,network,lateral}.*`, `security.mvt_spyware_scan.*`, `security.ssh_key_audit.*`, `security.firewall_audit.*`, `security.remote_login_check.*`, `security.win_rdp_check.*`, `security.launchd_persistence_audit.*`, `security.launch_agent_audit.*`. Example first entry:

```yaml
threats:
  - id: ai-worm-supply-chain
    title: "AI worm / malicious package supply-chain compromise"
    summary: >
      Self-propagating worms (Shai-Hulud, Miasma) spread via npm/git/SSH and
      AI-agent tooling, planting persistence and command-and-control.
    run:
      profile: ai_worm_response
    codes:
      - "security.ai_worm_persistence.*"
      - "security.ai_worm_filesystem.*"
      - "security.ai_worm_git_ssh.*"
      - "security.ai_worm_lateral.*"
    curriculum_url: "https://themultiverse.school/x/agentic-ai-security-cases"
    curriculum_section: "Criminal Tooling & AI-Written Malware"
  # ... 7 more per the spec's draft set (mobile-spyware, credential-ssh-compromise,
  #     unwanted-remote-access, launch-persistence-malware, network-c2-beaconing,
  #     weak-firewall-exposure, general-device-compromise)
```

Run targets per spec: `mobile-spyware`→`profile: ai_worm_response` (`security.mvt_spyware_scan.*`); `credential-ssh-compromise`→`modules: [ssh_key_audit]`; `unwanted-remote-access`→`modules: [remote_login_check, win_rdp_check]`; `launch-persistence-malware`→`modules: [launchd_persistence_audit, launch_agent_audit]`; `network-c2-beaconing`→`profile: ai_worm_response` (`security.ai_worm_network.*`); `weak-firewall-exposure`→`modules: [firewall_audit]`; `general-device-compromise`→`full: true` (broad `codes` set for context). All `curriculum_url` = the `/x/agentic-ai-security-cases` page; vary `curriculum_section`.

- [ ] **Step 2: Write the gate test (RED)**

Create `tests/test_threat_map_validation.py`:

```python
from rescue.cli import _get_modules_dir, _get_profiles_dir, _project_root
from rescue.profiles import discover_profiles
from rescue.registry import discover_modules
from rescue.threat_map import load_threat_map, validate_threat_map


def _ctx():
    mods = discover_modules(_get_modules_dir())
    all_modules = {m.name for m in mods}
    all_codes = set()
    for m in mods:
        all_codes |= set(getattr(m, "emits_codes", []))
    profs = discover_profiles(_get_profiles_dir())
    profiles = {n: ((set(p.include_modules) or all_modules) - set(p.exclude_modules))
                for n, p in profs.items()}
    return profiles, all_codes, all_modules


def test_shipped_threat_map_is_valid():
    profiles, all_codes, all_modules = _ctx()
    threats = load_threat_map(_project_root() / "docs" / "threat_remediation_map.yaml")
    assert threats, "threat map is empty"
    errors = validate_threat_map(threats, profiles, all_codes, all_modules)
    assert errors == [], "threat map invalid:\n" + "\n".join(errors)
```

Run: `pytest tests/test_threat_map_validation.py -v`
Expected: FAIL initially IF the map has any coverage/typo error — iterate on the YAML (Step 1) until it passes. (A missing-file error means Step 1 wasn't saved.)

- [ ] **Step 3: Add the Click subcommand**

In `rescue/cli.py`, after the `remediation-catalog` command, add:

```python
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
    out.write_text(render_threat_markdown(threats, profiles))
    click.echo(f"Wrote {out} ({len(threats)} threats)")
```

- [ ] **Step 4: Generate the doc + confirm gate passes**

Run: `python -m rescue.cli threat-remediation`
Expected: `Wrote .../docs/THREAT_REMEDIATION.md (8 threats)`; no ERROR lines.
Run: `pytest tests/test_threat_map_validation.py -v` → PASS.

- [ ] **Step 5: README pointer**

In `README.md`, add near the support/roadmap section:

```markdown
## Threat coverage

`docs/THREAT_REMEDIATION.md` maps common threats (AI worms, mobile spyware,
credential compromise, unwanted remote access, …) to the exact `rescue` command
that checks and remediates them. Regenerate it with `rescue threat-remediation`.
```

- [ ] **Step 6: Full suite + commit**

```bash
pytest -q
git add docs/threat_remediation_map.yaml docs/THREAT_REMEDIATION.md rescue/cli.py README.md tests/test_threat_map_validation.py
git commit -m "feat: threat_remediation_map + threat-remediation subcommand + gate"
```

---

### Task 4: Phase 2 — curriculum reverse links (vault)

**Controller-executed (content + production publish), not TDD.** Run after Phase 1 is merged to the tool's `main` so the GitHub links resolve.

**Files (curriculum vault repo `multiverse_school_curriculum`, branch `main`):**
- Modify: `Curriculum/CyberSecurity/Agentic AI Security/AI-Assisted Hacking — Case Studies.md`
- Modify: `Curriculum/CyberSecurity/Agentic AI Security/Agentic AI Security — Course Index.md`

- [ ] **Step 1: Add the "Remediate on your own device" section**

Near the top of the AI-Assisted Hacking note (after the intro callouts, before the category table), insert a section listing each threat → its `rescue` command, linking to `https://github.com/lizTheDeveloper/multiverse-device-rescue/blob/main/docs/THREAT_REMEDIATION.md#<id>`. Mirror the 8 threat ids from the map. Plus one compact inline pointer line under the `## Real-World Incidents` and `## Criminal Tooling & AI-Written Malware` headings:
`> **Remediate on your own device →** run [Multiverse Device Rescue](https://github.com/lizTheDeveloper/multiverse-device-rescue/blob/main/docs/THREAT_REMEDIATION.md#ai-worm-supply-chain): \`rescue --profile ai_worm_response\`.`

- [ ] **Step 2: Course Index pointer**

In the Course Index note, add one line under the "Deep dives" or "Companion" area:
`- **Check your own device** — worried you're affected? [Multiverse Device Rescue](https://github.com/lizTheDeveloper/multiverse-device-rescue/blob/main/docs/THREAT_REMEDIATION.md) maps each threat to a command that scans and remediates it.`

- [ ] **Step 3: Commit + push the vault**

```bash
VAULT="/Users/annhoward/Library/Mobile Documents/iCloud~md~obsidian/Documents/multiverse_school_curriculum"
DEST="Curriculum/CyberSecurity/Agentic AI Security"
git -C "$VAULT" add "$DEST/AI-Assisted Hacking — Case Studies.md" "$DEST/Agentic AI Security — Course Index.md"
git -C "$VAULT" commit -m "Cross-link Device Rescue as remediation from AI-hacking case studies" -- "$DEST/AI-Assisted Hacking — Case Studies.md" "$DEST/Agentic AI Security — Course Index.md"
git -C "$VAULT" push origin main
```
Verify local == remote (`git -C "$VAULT" rev-parse main` == `git -C "$VAULT" ls-remote origin refs/heads/main`).

---

### Task 5: Phase 2 — republish `/x/` + HedgeDoc

**Controller-executed production publish, per `docs/AGENT_PUBLISHING_GUIDE.md`.** The published surfaces are stale until refreshed.

- [ ] **Step 1: Rebuild the `/x/` cases page content**

Convert the updated vault `AI-Assisted Hacking — Case Studies.md` to publish form (wiki-links → absolute URLs, per the earlier `_pub2` conversion), producing the new page body.

- [ ] **Step 2: SQL UPDATE the `/x/` page (id 1151, slug `agentic-ai-security-cases`)**

Via the app container's `psycopg2` (parameterized, base64 the body):
```
UPDATE pages SET content_html=%s, updated_at=NOW() WHERE slug='agentic-ai-security-cases'
```
Expected: 1 row updated. Verify: `curl -s https://themultiverse.school/x/agentic-ai-security-cases | grep -c "THREAT_REMEDIATION"` ≥ 1.

- [ ] **Step 3: Update the HedgeDoc Course Index note**

If the Course Index pointer was added: `UPDATE "Notes" SET content=%s, "updatedAt"=NOW(), "lastchangeAt"=NOW() WHERE alias='agentic-ai-security'` on the `hedgedoc` DB (the note is `permission=locked`, owner set — updating content in place is the established path). Verify via the internal `/download` endpoint that the pointer is present.

- [ ] **Step 4: Confirmation**

Report the two live URLs and that both now show the Device Rescue remediation links.

---

## Self-Review Notes

- Spec §Phase 1 map schema → Task 3 YAML; `threat_map.py` (load/validate/render) → Tasks 1-2; subcommand + doc + README + gate → Task 3. §Phase 2 curriculum + publish → Tasks 4-5.
- Types consistent: `RunTarget`, `Threat`, `load_threat_map`, `expand_codes`, `modules_for_codes`, `run_target_modules`, `validate_threat_map(threats, profiles, all_codes, all_modules)`, `render_threat_markdown(threats, profiles)`.
- Coverage rule tested (Task 1 `test_coverage_violation_error`) and enforced on real content (Task 3 gate).
- Task 4/5 are controller-executed ops (content + production publish); flagged non-TDD, and Task 4 notes the merge-to-`main` prerequisite for the GitHub links to resolve.
