import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import Mode, Platform, RiskLevel, Severity, SystemProfile
from rescue.registry import discover_modules

ROUTE_OUTPUT = "default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n"


def _make_profile():
    return SystemProfile(
        platform=Platform.LINUX,
        os_name="Ubuntu",
        os_version="24.04",
        architecture="x86_64",
        cpu_model="Intel",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "router_security_audit")


def _module_namespace(mod):
    """The loaded module object, so module-level helpers can be patched."""
    return sys.modules[type(mod).__module__]


def _route_command(*args, **kwargs):
    command = args[0] if args else kwargs.get("args", [])
    if command[:2] == ["ip", "route"]:
        return MagicMock(stdout=ROUTE_OUTPUT, returncode=0)
    return MagicMock(stdout="", returncode=0)


def _check(open_ports=(), upnp=""):
    mod = _get_module()
    namespace = _module_namespace(mod)
    with patch("subprocess.run", side_effect=_route_command):
        with patch.object(
            namespace, "_tcp_open", side_effect=lambda host, port: port in open_ports
        ):
            with patch.object(namespace, "_ssdp_discover", return_value=upnp):
                return mod, mod.check(_make_profile())


def test_module_discovered():
    mod = _get_module()
    assert mod.name == "router_security_audit"
    assert mod.category == "network"
    assert mod.risk_level == RiskLevel.SAFE


def test_no_gateway_is_reported_as_unavailable_not_healthy():
    mod = _get_module()
    with patch("subprocess.run", return_value=MagicMock(stdout="", returncode=0)):
        result = mod.check(_make_profile())
    assert result.error is not None
    assert not result.findings


def test_closed_router_reports_only_the_manual_review_reminder():
    _, result = _check(open_ports=())
    assert [f.data["check"] for f in result.findings] == ["router_manual_review"]
    assert result.findings[0].severity == Severity.INFO
    assert result.findings[0].data["gateway_ip"] == "192.168.1.1"


def test_telnet_on_the_router_is_critical():
    _, result = _check(open_ports=(23,))
    telnet = next(
        f for f in result.findings if f.data.get("port") == 23
    )
    assert telnet.severity == Severity.CRITICAL
    assert telnet.data["check"] == "admin_service_open"


def test_https_admin_page_is_informational_not_a_problem():
    _, result = _check(open_ports=(443,))
    https = next(f for f in result.findings if f.data.get("port") == 443)
    assert https.severity == Severity.INFO


def test_tr069_management_port_is_flagged():
    _, result = _check(open_ports=(7547,))
    assert any(f.data.get("port") == 7547 for f in result.findings)


def test_upnp_response_is_flagged():
    _, result = _check(upnp="HTTP/1.1 200 OK\r\nST: InternetGatewayDevice\r\n")
    assert any(f.data["check"] == "upnp_enabled" for f in result.findings)


def test_silent_upnp_is_not_flagged():
    _, result = _check(upnp="")
    assert not any(f.data["check"] == "upnp_enabled" for f in result.findings)


def test_fix_is_guidance_only_and_always_offers_the_reclaim_procedure():
    mod, result = _check(open_ports=(23, 80))
    fix = mod.fix(result, Mode.CLI)

    assert all(action.kind.value == "guidance" for action in fix.actions)
    assert all(not action.executed for action in fix.actions)
    assert any("reclaim" in action.title.lower() for action in fix.actions)


def test_fix_does_not_ask_to_disable_the_expected_admin_page():
    mod, result = _check(open_ports=(443,))
    fix = mod.fix(result, Mode.CLI)
    assert not any(action.data.get("port") == 443 for action in fix.actions)
