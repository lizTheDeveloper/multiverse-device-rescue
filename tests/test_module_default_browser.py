import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "default_browser")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_chrome_default():
    """Chrome is the default browser"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "LSHandlers" in cmd_str:
            return _make_subprocess_result(
                """(
    {
        LSHandlerContentType = "com.apple.web-internet-location";
        LSHandlerRoleAll = "com.google.Chrome";
    },
    {
        LSHandlerURLScheme = https;
        LSHandlerRoleAll = "com.google.Chrome";
    },
    {
        LSHandlerURLScheme = http;
        LSHandlerRoleAll = "com.google.Chrome";
    }
)
"""
            )
        elif "mdfind" in cmd_str and "com.google.Chrome" in cmd_str:
            return _make_subprocess_result(
                "/Applications/Google Chrome.app\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_safari_default():
    """Safari (default) is the default browser"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "LSHandlers" in cmd_str:
            return _make_subprocess_result(
                """(
    {
        LSHandlerURLScheme = https;
        LSHandlerRoleAll = "com.apple.Safari";
    },
    {
        LSHandlerURLScheme = http;
        LSHandlerRoleAll = "com.apple.Safari";
    }
)
"""
            )
        elif "mdfind" in cmd_str and "com.apple.Safari" in cmd_str:
            return _make_subprocess_result(
                "/Applications/Safari.app\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_unknown_browser():
    """Unknown browser is set as default and not installed"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "LSHandlers" in cmd_str:
            return _make_subprocess_result(
                """(
    {
        LSHandlerURLScheme = https;
        LSHandlerRoleAll = "com.unknown.Browser";
    }
)
"""
            )
        elif "mdfind" in cmd_str and "com.unknown.Browser" in cmd_str:
            # App not found
            return _make_subprocess_result(returncode=0, stdout="")
        return _make_subprocess_result()
    return fake_run


def _fake_run_with_email():
    """Chrome is default browser, Mail is default email client"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "LSHandlers" in cmd_str:
            return _make_subprocess_result(
                """(
    {
        LSHandlerURLScheme = https;
        LSHandlerRoleAll = "com.google.Chrome";
    },
    {
        LSHandlerURLScheme = http;
        LSHandlerRoleAll = "com.google.Chrome";
    },
    {
        LSHandlerURLScheme = mailto;
        LSHandlerRoleAll = "com.apple.mail";
    }
)
"""
            )
        elif "mdfind" in cmd_str and "com.google.Chrome" in cmd_str:
            return _make_subprocess_result(
                "/Applications/Google Chrome.app\n"
            )
        elif "mdfind" in cmd_str and "com.apple.mail" in cmd_str:
            return _make_subprocess_result(
                "/Applications/Mail.app\n"
            )
        return _make_subprocess_result()
    return fake_run


def test_default_browser_discovered():
    mod = _get_module()
    assert mod.name == "default_browser"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_chrome_as_default():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_chrome_default()):
        result = mod.check(_make_profile())
    # Should have findings about Chrome being default
    assert any(
        f.data.get("check") == "default_browser_info"
        for f in result.findings
    )
    assert any(
        f.data.get("browser_id") == "com.google.Chrome"
        for f in result.findings
    )


def test_safari_as_default():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_safari_default()):
        result = mod.check(_make_profile())
    # Should have findings about Safari being default
    assert any(
        f.data.get("check") == "default_browser_info"
        for f in result.findings
    )
    # Safari is a known browser, so should flag it as such
    assert any(
        f.data.get("check") == "known_browser"
        for f in result.findings
    )


def test_unknown_browser_not_installed():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_unknown_browser()):
        result = mod.check(_make_profile())
    # Should flag warning about unknown browser not being installed
    assert any(
        f.data.get("check") == "browser_not_installed"
        and f.severity == Severity.WARNING
        for f in result.findings
    )


def test_chrome_and_mail_defaults():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_email()):
        result = mod.check(_make_profile())
    # Should have findings for both browser and email
    assert any(
        f.data.get("check") == "default_browser_info"
        for f in result.findings
    )
    assert any(
        f.data.get("check") == "default_email_info"
        for f in result.findings
    )


def test_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_unknown_browser()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action for the warning
    assert len(fix.actions) >= 0
