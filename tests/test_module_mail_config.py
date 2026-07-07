import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import tempfile

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
    return next(m for m in modules if m.name == "mail_config")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_no_accounts():
    """No mail accounts configured"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "MailAccounts" in cmd_str:
            return _make_subprocess_result(stderr="User defaults out of range.", returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_with_accounts_imap():
    """Mail with IMAP accounts"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "MailAccounts" in cmd_str:
            return _make_subprocess_result(stdout="""(
    {
        AccountID = "12345";
        AccountName = "Work Mail";
    },
    {
        AccountID = "67890";
        AccountName = "Personal Mail";
    }
)
""")
        elif "defaults read" in cmd_str and "AutoFetchingEnabled" in cmd_str:
            return _make_subprocess_result(stdout="1")
        elif "defaults read" in cmd_str and "PollInterval" in cmd_str:
            return _make_subprocess_result(stdout="300")
        return _make_subprocess_result()
    return fake_run


def _fake_run_with_pop_accounts():
    """Mail with POP accounts"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "MailAccounts" in cmd_str:
            return _make_subprocess_result(stdout="""(
    {
        AccountID = "12345";
        AccountName = "POP Account";
        POPAuthentication = "default";
    }
)
""")
        elif "defaults read" in cmd_str and "AutoFetchingEnabled" in cmd_str:
            return _make_subprocess_result(stdout="0")
        return _make_subprocess_result()
    return fake_run


def _fake_run_with_disabled_accounts():
    """Mail with disabled accounts"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "MailAccounts" in cmd_str:
            return _make_subprocess_result(stdout="""(
    {
        AccountID = "12345";
        AccountName = "Active Account";
    },
    {
        AccountID = "67890";
        AccountName = "Disabled Account";
        Enabled = 0;
    }
)
""")
        elif "defaults read" in cmd_str and "AutoFetchingEnabled" in cmd_str:
            return _make_subprocess_result(stdout="1")
        elif "defaults read" in cmd_str and "PollInterval" in cmd_str:
            return _make_subprocess_result(stdout="600")
        return _make_subprocess_result()
    return fake_run


def test_mail_config_discovered():
    mod = _get_module()
    assert mod.name == "mail_config"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_mail_config_no_accounts():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_accounts()):
        with patch.object(mod, '_get_mail_directory_size', return_value=0):
            with patch.object(mod, '_get_mail_check_frequency', return_value=None):
                result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "mail_accounts" for f in result.findings)


def test_mail_config_with_imap_accounts():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_accounts_imap()):
        with patch.object(mod, '_get_mail_directory_size', return_value=2 * 1024**3):
            result = mod.check(_make_profile())
    assert len(result.findings) > 0
    # Should report account count
    assert any(f.data.get("check") == "mail_accounts" for f in result.findings)
    # Should NOT have POP warnings
    assert not any(f.data.get("check") == "pop_accounts" for f in result.findings)


def test_mail_config_with_pop_accounts():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_pop_accounts()):
        with patch.object(mod, '_get_mail_directory_size', return_value=1 * 1024**3):
            result = mod.check(_make_profile())
    assert len(result.findings) > 0
    # Should warn about POP accounts
    assert any(f.data.get("check") == "pop_accounts" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_mail_config_with_disabled_accounts():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_disabled_accounts()):
        with patch.object(mod, '_get_mail_directory_size', return_value=3 * 1024**3):
            result = mod.check(_make_profile())
    assert len(result.findings) > 0
    # Should warn about disabled accounts
    assert any(f.data.get("check") == "disabled_accounts" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_mail_config_large_mail_directory():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_accounts_imap()):
        with patch.object(mod, '_get_mail_directory_size', return_value=15 * 1024**3):
            result = mod.check(_make_profile())
    assert len(result.findings) > 0
    # Should warn about large mail directory
    assert any(f.data.get("check") == "mail_size" and f.severity == Severity.WARNING for f in result.findings)


def test_mail_config_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_accounts_imap()):
        with patch.object(mod, '_get_mail_directory_size', return_value=2 * 1024**3):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    assert len(fix.actions) > 0


def test_mail_config_fix_check_frequency():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_disabled_accounts()):
        with patch.object(mod, '_get_mail_directory_size', return_value=1 * 1024**3):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)
    # Should have actions for all findings
    assert len(fix.actions) > 0
    assert fix.all_succeeded
