---
title: "Review and remove unexpected Windows proxy settings"
estimated_time: "10 minutes"
platforms: [windows]
remediates:
  - security.win_proxy_detect.localhost_suspicious
  - security.win_proxy_detect.ie_proxy_enabled
  - security.win_proxy_detect.pac_configured
  - security.win_proxy_detect.system_proxy
  - security.win_proxy_detect.no_proxies
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

A configured proxy is not automatically malicious — corporate networks, VPN
clients, and some parental-control or ad-blocking tools legitimately set a
system or browser proxy. But it's also a common technique for
malware/adware to intercept and inject traffic (especially a proxy pointing
at `127.0.0.1`/localhost on a non-standard port, which likely means a local
process is sitting between your browser and the internet). **Before removing
any proxy setting, verify whether you (or a VPN/corporate policy) intend it
to be there** — check if you're on a work network, connected to a VPN, or
recently installed software that legitimately proxies traffic (some
ad-blockers and parental-control tools do this by design).

## Step 1: Proxy points to localhost on an unusual port (critical)

This is the strongest indicator of malicious interception: a proxy pointing
at `127.0.0.1`/`localhost` on a port outside the common legitimate proxy
range (80, 443, 3128, 8000-8003, 8080, 8888, 9090) usually means a
locally-running process — not your browser or OS — is intercepting traffic.

1. Confirm current state: `reg query
   "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v
   ProxyServer`.
2. Check what's actually listening on that local port before removing
   anything: `netstat -ano | findstr :<port>` then look up the owning PID
   in Task Manager → Details tab. If it's a process you don't recognize,
   treat this alongside `triage_windows_suspicious_processes.md` and
   `respond_to_windows_malware_indicators.md` — this pattern is consistent
   with adware/malware traffic injection, not routine misconfiguration.
3. If you don't recognize the source, remove the proxy: Settings → Network
   & Internet → Proxy → under "Manual proxy setup" turn off "Use a proxy
   server". Then restart your browser and run a full antivirus scan (see
   `enable_windows_antivirus.md` for re-enabling Defender if it's also been
   disabled).

## Step 2: Browser proxy enabled (not localhost)

A manual proxy is configured and enabled, pointing at a non-localhost
address.

1. Confirm current state via Settings → Network & Internet → Proxy, or the
   registry path above.
2. If this matches a VPN client, corporate policy, or ad-blocking tool you
   installed intentionally, no action is needed — this is informational for
   most users.
3. If you don't recognize the proxy address and don't use a VPN/corporate
   network, disable it: Settings → Network & Internet → Proxy → toggle off
   "Use a proxy server" under Manual proxy setup.

## Step 3: PAC (auto-config) URL configured

An automatic proxy configuration script URL is set. PAC files can route
specific traffic through a proxy selectively, which is both a legitimate
enterprise pattern and a way malware can redirect only certain sites (e.g.
banking domains) through an attacker-controlled proxy while leaving
everything else untouched — making it harder to notice than a blanket
system-wide proxy.

1. Confirm current state: Settings → Network & Internet → Proxy → check
   "Automatic proxy setup" / "Use setup script", or `reg query
   "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v
   AutoConfigURL`.
2. If you recognize the URL (e.g. it points to your employer's internal
   domain or VPN provider), leave it — this is expected for managed
   networks.
3. If you don't recognize the URL, especially if it points to an unfamiliar
   external domain or IP, disable automatic proxy setup: Settings → Network
   & Internet → Proxy → toggle off "Use setup script". Treat an unfamiliar
   PAC URL as a possible sign of DNS/traffic redirection — cross-reference
   with `clean_windows_hosts_file.md` for similarly suspicious redirection
   entries.

## Step 4: System-wide proxy detected (informational)

`netsh winhttp show proxy` reports a system-wide WinHTTP proxy — this is
separate from the per-user browser proxy setting and is used by some system
services and older applications.

1. Confirm current state: `netsh winhttp show proxy`.
2. If this was set intentionally (common when configuring proxies for
   Windows Update or enterprise tools via `netsh winhttp set proxy`), no
   action is needed.
3. If unrecognized, reset it: `netsh winhttp reset proxy` (run from an
   elevated prompt). This only affects the WinHTTP-level setting, not your
   browser's own proxy configuration.

## No issues found

If the scan reports only the `no_proxies` INFO finding, no proxy is
configured anywhere Windows checks — this is the normal state for most home
systems and no action is needed.
