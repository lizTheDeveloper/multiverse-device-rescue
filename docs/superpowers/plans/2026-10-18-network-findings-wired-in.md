# Network findings wired in (N2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every finding from the eight `modules/network/*` checks carries a stable finding code. Each warning or critical code has a remediation walkthrough. Network findings get "Open in System Settings" buttons where their own advice points to a settings page. `docs/commands.md` tells the truth about what the network checks run.

**Architecture:** Codes are `network.<module>.<slug>`, where `<slug>` is the finding's existing `data["check"]` value, so `fix()` and the existing tests keep working unchanged. Walkthroughs are new `guides/remediation/*.md` files, plus one existing file extended. They reach the game through the existing `rescue/serialize.py` code→walkthrough lookup. Desktop changes are data only (`CODE_PANES`), plus a stable per-instance `data["target"]` so `findingIdentity` keeps separate devices and interfaces apart. Lesson links need no change: `lessonForModule` matches by module, and `whos-on-wifi` already lists the LAN, ARP, router and Wi-Fi modules. The command-catalog generator learns to follow `load_content_module(...)` paths, helper runners, and sockets.

**Tech Stack:** Python 3 (pytest, ruff), Node test runner for the desktop (`node --test`), Markdown walkthroughs with YAML front matter.

**Spec:** `docs/superpowers/specs/2026-10-18-network-analysis-training-design.md` (piece N2). It builds on `docs/superpowers/specs/2026-10-18-command-center-signal-or-noise-design.md`.

## Global Constraints

- Read-only: no check gains a new command, probe, or network call. Only finding metadata, docs and generator logic change. (`AGENTS.md` rule 1.)
- Code format: `network.<module>.<slug>`, exactly three dot-separated parts matching `^[a-z0-9_]+\.[a-z0-9_]+\.[a-z0-9_]+$` (`desktop/mark-policy.js:24`). The literal goes **at the `Finding(...)` call site**: no f-strings and no conditional expressions (CONTRIBUTING.md:104-109; enforced by `tests/test_module_code_consistency.py`).
- `<slug>` = the finding's existing `data["check"]` value. Keep `data["check"]` exactly as it is.
- Every WARNING/CRITICAL code needs a walkthrough (`tests/test_remediation_catalog.py::test_every_warning_or_critical_code_has_a_walkthrough`). Don't add entries to `_NO_WALKTHROUGH_NEEDED`.
- Walkthrough text comes from **text already in the repo**: the module's own "What to do" description, its `fix()` action text, `guides/home_network_intrusion/phase_*.md`, and for router/DNS the vendored Reclaim City `desktop/vendor/reclaim-city/src/data/missions-grid.js` (Quad9 listed first). Don't invent menu paths, button names or commands that aren't already in those sources. (Earlier drafts that invented menus were caught; see project memory.)
- Walkthroughs never ask for a password, one-time code or recovery code. Steps that change something are `human_only_steps`, with `automatable_steps: []`.
- Any walkthrough for a module whose findings carry the domestic-violence hotline paragraph (`arp_spoof_check`, `lan_device_inventory`, `router_security_audit`) sets `monitoring_risk: true`, and its first step is the safety check before changing anything.
- No time estimates: give new walkthroughs `estimated_time: ""` (the loader defaults it to `""`, `rescue/guides.py:64`) and no durations in the prose. (User's global CLAUDE.md.)
- `rescue/*.py` is not touched, so the integrity manifest needn't be regenerated. If a task does touch `rescue/`, run `python scripts/generate_integrity_manifest.py`.
- Test commands: Python `RESCUE_TEST_MODE=1 .venv/bin/python -m pytest -q`; lint `.venv/bin/ruff check .`; `.venv/bin/python -m rescue.cli validate`; desktop `cd desktop && npm test`.

## Review Focus

1. **Several devices, interfaces or ports collapsing into one mission.** Today `findingIdentity` is `module|title`, and the titles include the IP or interface. With a code it becomes `module|code`, so three unrecognised devices would merge into one mission. Each per-instance finding must set `data["target"]` (a key already in `STABLE_KEYS`). Tests: in Tasks 1–7, "two instances → two different `target`s"; in Task 8, the desktop `findingIdentity` test.
2. **A Wi-Fi security type that can't be read, reported as a CRITICAL open network** (`wifi_security_audit:269`, `security == "unknown"`). The person would expect "couldn't check", not an alarm. Test in Task 3.
3. **Router admin ports share one code across severities** (CRITICAL for 23, INFO for 80/443). The walkthrough must not tell someone with only a normal web admin page to panic. Its `steps_for` must keep the Telnet/FTP/SSH/TR-069 step general to "a risky service is open." Test in Task 2: the INFO finding still gets the code, and the walkthrough has no "attacker" wording on step 1.
4. **A remote PAC URL and a local proxy on the same Mac.** These are two codes from one module that both point to `remove_unwanted_proxy.md`, and `steps_for` must send each to the right step. Test in Task 6.
5. **Saved progress keyed by the old title-based identity.** After upgrading, a network mission the person marked "later" reopens once. This is accepted, not migrated, and noted in `desktop/MANUAL-QA.md` (Task 8).

---

### Task 1: Codes for `arp_spoof_check` + ARP walkthrough

**Files:**
- Modify: `modules/network/arp_spoof_check/__init__.py` (Finding sites at :199, :238, :278, :309; class attrs)
- Create: `guides/remediation/respond_to_arp_spoofing.md`
- Create: `tests/test_network_codes.py` (shared by Tasks 1–7)
- Test: `tests/test_module_arp_spoof_check.py`

**Interfaces:**
- Produces: `tests/test_network_codes.py` with `EXPECTED_CODES: dict[str, set[str]]` (module name → full code set). Tasks 2–7 each add their module's entry. Also `assert_codes_match_check(findings, module_name)`, a helper asserting `f.code == f"network.{module_name}.{f.data['check']}"` for every finding.
- Produces codes: `network.arp_spoof_check.{gateway_impersonation,duplicate_mac,locally_administered_gateway,multiple_gateways}`.

- [ ] **Step 1: Write the failing tests**

In `tests/test_network_codes.py`:
```python
EXPECTED_CODES = {
    "arp_spoof_check": {
        "network.arp_spoof_check.gateway_impersonation",
        "network.arp_spoof_check.duplicate_mac",
        "network.arp_spoof_check.locally_administered_gateway",
        "network.arp_spoof_check.multiple_gateways",
    },
}

@pytest.mark.parametrize("name", sorted(EXPECTED_CODES))
def test_declared_codes(name):
    mod = load_module(name)  # same loader the per-module tests use
    assert set(mod.emits_codes) == EXPECTED_CODES[name]
```
In `tests/test_module_arp_spoof_check.py`, reuse the existing fixtures that trigger each of the four findings:
- `test_every_finding_carries_its_check_code`: calls `assert_codes_match_check(findings, "arp_spoof_check")`.
- `test_duplicate_mac_findings_have_distinct_targets`: two spoofing MACs → two findings whose `data["target"]` values differ and equal the MACs.

- [ ] **Step 2: Run them and confirm they fail**

Run: `RESCUE_TEST_MODE=1 .venv/bin/python -m pytest -q tests/test_network_codes.py tests/test_module_arp_spoof_check.py`
Expected: FAIL (`emits_codes` is empty, `code` is None).

- [ ] **Step 3: Add `emits_codes`, `code=` literals, and `data["target"]`**

Per-instance findings set `data["target"]`:
- `duplicate_mac` → the MAC
- `locally_administered_gateway` → the gateway IP
- `gateway_impersonation` → the gateway MAC

`multiple_gateways` is a single finding and needs no target.

- [ ] **Step 4: Write `guides/remediation/respond_to_arp_spoofing.md`**

Front matter:
- `platforms: [macos, windows, linux]`
- `remediates:` the four codes
- `monitoring_risk: true`
- `human_only_steps:` all steps; `automatable_steps: []`
- `estimated_time: ""`

Steps:
1. Safety check first (from `guides/home_network_intrusion/phase_0.md`).
2. Confirm from the router's own device list (phase_1).
3. Take the router back (phase_2).
4. When multiple gateways is the only finding, check for a second router or a VPN.

Use `steps_for` so `multiple_gateways` gets steps 1 and 4.

- [ ] **Step 5: Run the module tests, the code-consistency test, the remediation-catalog test, and validate**

Run: `RESCUE_TEST_MODE=1 .venv/bin/python -m pytest -q tests/test_network_codes.py tests/test_module_arp_spoof_check.py tests/test_module_code_consistency.py tests/test_remediation_catalog.py && .venv/bin/python -m rescue.cli validate`
Expected: all pass; validate reports no errors.

- [ ] **Step 6: Commit**

```bash
git add modules/network/arp_spoof_check guides/remediation/respond_to_arp_spoofing.md tests/test_network_codes.py tests/test_module_arp_spoof_check.py
git commit -m "arp_spoof_check: finding codes and an ARP-spoofing walkthrough"
```

### Task 2: Codes for `lan_device_inventory` and `router_security_audit` + two walkthroughs

**Files:**
- Modify: `modules/network/lan_device_inventory/__init__.py` (:203, :229, :263)
- Modify: `modules/network/router_security_audit/__init__.py` (:271, :305, :329)
- Create: `guides/remediation/review_unknown_lan_devices.md`
- Create: `guides/remediation/secure_home_router.md`
- Test: `tests/test_network_codes.py`, `tests/test_module_lan_device_inventory.py`, `tests/test_module_router_security_audit.py`

**Interfaces:**
- Consumes: `EXPECTED_CODES` and `assert_codes_match_check` from Task 1.
- Produces codes:
  - `network.lan_device_inventory.{lan_inventory,unrecognised_device,device_count_exceeded}`
  - `network.router_security_audit.{admin_service_open,upnp_enabled,router_manual_review}`

- [ ] **Step 1: Write the failing tests**
  - Add both modules to `EXPECTED_CODES`.
  - Per module: `test_every_finding_carries_its_check_code`.
  - `test_unrecognised_devices_have_distinct_targets`: two unknown MACs give two different `data["target"]` values, equal to the MACs.
  - `test_admin_ports_have_distinct_targets`: ports 23 and 80 open → `target` values `"23"` and `"80"`.
  - `test_info_admin_port_still_coded`: port 443 alone → severity INFO, code `network.router_security_audit.admin_service_open`.

- [ ] **Step 2: Run them and confirm they fail**

Run: `RESCUE_TEST_MODE=1 .venv/bin/python -m pytest -q tests/test_network_codes.py tests/test_module_lan_device_inventory.py tests/test_module_router_security_audit.py`
Expected: FAIL.

- [ ] **Step 3: Add `emits_codes`, the literal codes, and `data["target"]` (MAC; port number as a string)**

Router `:271` keeps one call site with one literal code. Severity stays `entry["severity"]`.

- [ ] **Step 4: Write the two walkthroughs**

Both have `monitoring_risk: true` and a safety-check step first.
- **`review_unknown_lan_devices.md`:**
  - Covers `unrecognised_device` and `device_count_exceeded`, from `whos-on-wifi` lesson facts and phase_1. The steps: most extra devices are your own; check the router's device list; don't block hardware addresses as a fix; change the Wi-Fi passphrase.
  - `lan_inventory` gets the "check the router's device list" step only.
- **`secure_home_router.md`:**
  - Covers all three router codes, from `missions-grid.js` `smart_network-recon-router`: admin password, WPS off, UPnP off, firmware, default Wi-Fi password.
  - Plus the module's own "What to do" text for open admin services.
  - The open-service step stays general (Review Focus 3).

- [ ] **Step 5: Run the module tests, the consistency and catalog tests, and validate (same command as Task 1, Step 5, with these test files)**

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git commit -m "lan_device_inventory, router_security_audit: finding codes and walkthroughs"
```
(Add the files listed above first.)

### Task 3: Codes for `wifi_security_audit`, an "unknown" fix, and a Wi-Fi walkthrough

**Files:**
- Modify: `modules/network/wifi_security_audit/__init__.py` (:246, :269-271, :294, :317, :352, :376, :417)
- Create: `guides/remediation/secure_wifi_connection.md`
- Test: `tests/test_network_codes.py`, `tests/test_module_wifi_security_audit.py`

**Interfaces:**
- Produces codes: `network.wifi_security_audit.{wep_connected,open_network_connected,wpa2_only,hidden_network,wep_saved,open_saved,wifi_summary,security_unknown}`

- [ ] **Step 1: Write the failing tests**
  - Register the codes.
  - `test_every_finding_carries_its_check_code`.
  - `test_unknown_security_is_not_open`: current network security `"unknown"`:
    - no finding with `data["check"] == "open_network_connected"`
    - exactly one INFO finding with `data["check"] == "security_unknown"`, title `"Couldn't read your Wi-Fi's security type"`, and a description saying this was not checked (rather than calling the network safe)

- [ ] **Step 2: Run them and confirm they fail**

Run: `RESCUE_TEST_MODE=1 .venv/bin/python -m pytest -q tests/test_network_codes.py tests/test_module_wifi_security_audit.py`
Expected: FAIL.

- [ ] **Step 3: Implement**
  - Split `"unknown"` out of the open-network branch into its own INFO finding.
  - Add `emits_codes` and the literal codes.
  - Current-network findings need no target (there's one current network). Saved-network findings are counts, so none there either.

- [ ] **Step 4: Write `secure_wifi_connection.md`** (`platforms: [macos]`)

Use each warning/critical code's own "What to do" text:
- forget saved WEP/open networks on the Mac
- for WEP/WPA2 on your own network, change it on the router (point to `secure_home_router.md`)
- on an open network, avoid sensitive logins or use a VPN

Use `steps_for` per code.

- [ ] **Step 5: Run the tests and validate (as in Task 1, Step 5)**

Expected: PASS.

- [ ] **Step 6: Commit** `"wifi_security_audit: finding codes, unknown security is couldn't-check, walkthrough"`

### Task 4: Codes for `dns_over_https_check` + DNS walkthrough

**Files:**
- Modify: `modules/network/dns_over_https_check/__init__.py` (:42, :65, :87, :105, :117, :135, :153, :177)
- Create: `guides/remediation/encrypt_dns_lookups.md`
- Test: `tests/test_network_codes.py`, `tests/test_module_dns_over_https_check.py`

**Interfaces:**
- Produces codes: `network.dns_over_https_check.{dns_configuration,unencrypted_dns,encrypted_dns_provider,no_dns_found,encrypted_dns_profile,local_dns_resolver,doh_tls_configured,no_encryption_configured}`

- [ ] **Step 1: Write the failing tests**
  - Register the codes.
  - `test_every_finding_carries_its_check_code`.
  - `test_both_unencrypted_findings_coded`: the fixture where :65 and :177 both fire produces two findings with different codes.

- [ ] **Step 2: Run them and confirm they fail**
- [ ] **Step 3: Add `emits_codes` and the literal codes**
- [ ] **Step 4: Write `encrypt_dns_lookups.md`** (`platforms: [macos]`)

From the vendored `missions-grid.js` `smart_network-reclaim-dns` text:
- Quad9 first.
- Keep its corrections: "This changes who answers, not who can see", and "one layer, not invisibility".
- Browser-level and device-level options as listed there, plus the verify step (on.quad9.net / 1.1.1.1/help).

- [ ] **Step 5: Run the tests and validate**

Also add `test_dns_walkthrough_lists_quad9_first` in `tests/test_remediation_catalog.py`: "Quad9" appears before "Cloudflare" in the walkthrough body.

- [ ] **Step 6: Commit** `"dns_over_https_check: finding codes and an encrypted-DNS walkthrough"`

### Task 5: Codes for `vpn_leak_check` + VPN walkthrough

**Files:**
- Modify: `modules/network/vpn_leak_check/__init__.py` (:36, :69, :91, :120, :143)
- Create: `guides/remediation/fix_vpn_leaks.md`
- Test: `tests/test_network_codes.py`, `tests/test_module_vpn_leak_check.py`

**Interfaces:**
- Produces codes: `network.vpn_leak_check.{no_vpns_configured,vpn_config_summary,dns_leak,split_tunneling,vpn_not_connected}`

- [ ] **Step 1: Write the failing tests** (register the codes; `test_every_finding_carries_its_check_code`)
- [ ] **Step 2: Run them and confirm they fail**
- [ ] **Step 3: Add `emits_codes` and the literal codes**
- [ ] **Step 4: Write `fix_vpn_leaks.md`** (`platforms: [macos]`)

From the three warnings' "What to do" text, with `steps_for` per code. If a step has nothing in the repo to source it from, point to `review_vpn_config.md` rather than inventing one.

- [ ] **Step 5: Run the tests and validate**
- [ ] **Step 6: Commit** `"vpn_leak_check: finding codes and a VPN-leak walkthrough"`

### Task 6: Codes for `network_proxy_check` routed to the existing proxy walkthrough

**Files:**
- Modify: `modules/network/network_proxy_check/__init__.py` (:34, :60, :86, :134, :161, :192, :218, :236)
- Modify: `guides/remediation/remove_unwanted_proxy.md` (front matter only, unless a step is missing)
- Test: `tests/test_network_codes.py`, `tests/test_module_network_proxy_check.py`, `tests/test_remediation_catalog.py`

**Interfaces:**
- Produces codes: `network.network_proxy_check.{network_query_failed,remote_pac_url,pac_url_detected,suspicious_localhost_proxy,proxy_enabled,proxy_bypass_domains,proxy_config_summary,no_proxies}`

- [ ] **Step 1: Write the failing tests**
  - Register the codes.
  - `test_every_finding_carries_its_check_code`.
  - `test_per_interface_targets`: proxies on two interfaces → `data["target"]` equals each interface name.
  - In `tests/test_remediation_catalog.py`, `test_proxy_codes_route_to_right_steps`. Load the walkthrough index and check:
    - `remote_pac_url` → step 1
    - `pac_url_detected` → step 1
    - `suspicious_localhost_proxy` → step 2
    - `proxy_enabled` → step 2
    - `no_proxies` → step 3

- [ ] **Step 2: Run them and confirm they fail**
- [ ] **Step 3: Add `emits_codes`, the literal codes, and `data["target"]` (the interface) on the per-interface findings**
- [ ] **Step 4: Add the five codes to `remediates` and `steps_for` in `remove_unwanted_proxy.md`**
- [ ] **Step 5: Run the tests and validate**
- [ ] **Step 6: Commit** `"network_proxy_check: finding codes routed to the proxy walkthrough"`

### Task 7: Codes for `ethernet_diagnostics` + Ethernet walkthrough

**Files:**
- Modify: `modules/network/ethernet_diagnostics/__init__.py` (:35, :210, :237, :268, :374, :455, :500)
- Create: `guides/remediation/fix_ethernet_connection.md`
- Test: `tests/test_network_codes.py`, `tests/test_module_ethernet_diagnostics.py`

**Interfaces:**
- Produces codes: `network.ethernet_diagnostics.{no_ethernet,interface_inactive,self_assigned_ip,non_standard_mtu,link_speed_mismatch,high_packet_errors,ethernet_summary}`

- [ ] **Step 1: Write the failing tests**
  - Register the codes.
  - `test_every_finding_carries_its_check_code`.
  - `test_two_interfaces_distinct_targets`: two inactive interfaces → `target` values `en0` and `en1`.
- [ ] **Step 2: Run them and confirm they fail**
- [ ] **Step 3: Add `emits_codes`, the literal codes, and `data["target"]` (the interface)**
- [ ] **Step 4: Write `fix_ethernet_connection.md`** (`platforms: [macos]`), from each finding's "What to do", with `steps_for` per code
- [ ] **Step 5: Run the tests and validate**
- [ ] **Step 6: Commit** `"ethernet_diagnostics: finding codes and an Ethernet walkthrough"`

### Task 8: Desktop — network setting panes and identity

**Files:**
- Modify: `desktop/renderer/setting-panes.js` (`MAC_PANES`, `CODE_PANES`, header comment)
- Modify: `desktop/MANUAL-QA.md`
- Test: `desktop/test/setting-panes.test.js`, `desktop/test/game-findings-to-city.test.js` (or wherever `findingIdentity` is tested now; find it with `grep -l findingIdentity desktop/test`)

**Interfaces:**
- Consumes: codes from Tasks 1–7.
- Produces new `MAC_PANES` keys:
  - `wifi`: `x-apple.systempreferences:com.apple.wifi-settings-extension`, page `'Wi-Fi page'`
  - `networkDns`: `…com.apple.Network-Settings.extension?DNS`
  - `networkProxies`: `…?Proxies`
  - `networkVpn`: `…?VPN`
  - `networkEthernet`: `…?Ethernet`

  These were verified on this machine (macOS 26, 2026-10-18):
  - `Wi-Fi.appex` has `CFBundleIdentifier = com.apple.wifi-settings-extension` and `allowsXAppleSystemPreferencesURLScheme = true`.
  - `DNS`, `Proxies`, `VPN` and `Ethernet` are keys in `Network.appex/.../NetworkSearchGroups.searchTerms`, the same file that verifies `Firewall`.

  Add these facts to the header comment.

- [ ] **Step 1: Write the failing tests**
  - `test/setting-panes.test.js` cases:
    - `network.network_proxy_check.proxy_enabled` → `networkProxies`
    - `network.wifi_security_audit.open_saved` → `wifi`
    - `network.vpn_leak_check.dns_leak` → `networkVpn`
    - `network.wifi_security_audit.wpa2_only` → **no pane** (its fix is on the router, not the Mac)
    - `network.router_security_audit.admin_service_open` → no pane
  - Identity test: two findings with the same `module` and `code` and different `data.target` → different `findingIdentity`.

- [ ] **Step 2: Run them and confirm they fail**

Run: `cd desktop && npm test`
Expected: the new pane cases FAIL. The identity test should already pass (`target` is in `STABLE_KEYS`); keep it as a guard.

- [ ] **Step 3: Add the `MAC_PANES` entries and `CODE_PANES` rows**

The rule is the file's own: add a code only where that finding's "What to do" sends the person to that pane. Check each warning or critical code's description and map only those:
- saved/open Wi-Fi → `wifi`
- proxy codes → `networkProxies`
- VPN codes → `networkVpn`
- Ethernet codes whose advice is a Mac setting → `networkEthernet`
- DNS codes only if their advice names the Mac's DNS settings → `networkDns`

Router, ARP and LAN codes get no pane.

- [ ] **Step 4: Run `npm test` and confirm it passes**
- [ ] **Step 5: Add a MANUAL-QA step**

Run a scan on a Mac with a proxy configured, then:
- Confirm the Wires mission shows walkthrough steps and an "Open in System Settings" button that opens Network › Proxies.
- Also note that after upgrading, network missions marked "later" reopen once (Review Focus 5).

- [ ] **Step 6: Commit** `"Desktop: System Settings buttons for network findings"`

### Task 9: Command catalog follows helpers and sockets

**Files:**
- Modify: `scripts/generate_command_catalog.py`
- Modify: `.github/workflows/docs.yml` (`pull_request.paths`)
- Regenerate: `docs/commands.md`
- Test: `tests/test_generate_command_catalog.py` (create it if it doesn't exist)

**Interfaces:**
- Produces in `generate_command_catalog.py`:
  - `_runner_helpers(tree) -> dict[str, int]`: for each function defined in the file, the index of the parameter that is passed as `args[0]` to a command call.
  - `_content_module_paths(tree) -> list[Path]`: string literals passed as the first argument to `load_content_module(...)`, resolved against `REPO_ROOT`.
  - `_uses_sockets(tree) -> bool`: true if the file calls `socket.socket(...)` or `socket.create_connection(...)`.
  - `commands_for(module_dir) -> tuple[list[str], int, bool]`: adds the sockets flag.

- [ ] **Step 1: Write the failing tests**
  - `test_lan_device_inventory_lists_neighbor_commands`:
    - The rendered section for `lan_device_inventory` contains `arp -a -n`, `ip neigh show`, `route -n get default` and `route print -4`.
    - It does not contain "Runs no external commands".
  - `test_helper_param_call_not_counted_dynamic`: the `lan_common` section has no "built at runtime" line.
  - `test_router_audit_mentions_sockets`: the `router_security_audit` section contains `Also opens network connections directly from Python (sockets), without an external command.`
  - `test_catalog_is_fresh`: `main()` with `--check` returns 0 after regeneration.

- [ ] **Step 2: Run them and confirm they fail**

Run: `RESCUE_TEST_MODE=1 .venv/bin/python -m pytest -q tests/test_generate_command_catalog.py`
Expected: FAIL.

- [ ] **Step 3: Implement**

In `commands_for`:
1. Parse the module's own files.
2. Also parse each `_content_module_paths` target, once per module.
3. In each parsed file, render literal argv lists passed to `_runner_helpers` functions at their parameter index.
4. Don't count a command call whose `args[0]` is that helper's own parameter as dynamic.
5. OR the sockets flag across all parsed files.

`render()` prints the sockets line after the commands (or in place of "Runs no external commands" when there are none).

Add `'modules/**'` to `pull_request.paths` in `docs.yml`.

- [ ] **Step 4: Regenerate and run the tests**

Run: `.venv/bin/python scripts/generate_command_catalog.py && RESCUE_TEST_MODE=1 .venv/bin/python -m pytest -q tests/test_generate_command_catalog.py && git diff --stat docs/commands.md`
Expected: PASS. The diff touches the network sections (and any other module that newly resolves through a helper; read those hunks and confirm each is a real command).

- [ ] **Step 5: Commit** `"Command catalog: follow load_content_module helpers and report sockets"`

### Task 10: Catalog, full suites, and a real-scan check

**Files:**
- Regenerate: `docs/REMEDIATION_CATALOG.md`

- [ ] **Step 1: Regenerate the remediation catalog**

Run: `.venv/bin/rescue remediation-catalog`
Expected: the new `network.*` rows appear, and every WARNING/CRITICAL network code shows a walkthrough title.

- [ ] **Step 2: Run the full suites**

Run: `RESCUE_TEST_MODE=1 .venv/bin/python -m pytest -q && .venv/bin/ruff check . && .venv/bin/python -m rescue.cli validate && (cd desktop && npm test)`
Expected: all pass, with 0 validate errors.

- [ ] **Step 3: Real read-only check on this Mac**

Run: `.venv/bin/rescue run router_security_audit < /dev/null` and `.venv/bin/rescue run dns_over_https_check < /dev/null`. Then `.venv/bin/rescue scan --json --module router_security_audit` (read-only; no `--auto`/`--yes`).
Expected: every finding carries a `network.…` code. Warning/critical ones carry a `remediation` block with steps.

- [ ] **Step 4: Commit** `"Regenerate the remediation catalog for network codes"`
