import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open
import stat

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
    return next(m for m in modules if m.name == "ssh_key_audit")


def test_ssh_key_audit_discovered():
    """Test that module is discovered and has correct metadata."""
    mod = _get_module()
    assert mod.name == "ssh_key_audit"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_ssh_key_audit_no_ssh_dir():
    """Test when ~/.ssh does not exist - should have no key-related findings."""
    mod = _get_module()

    def mock_subprocess(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 1
        result.stderr = "Could not open a connection to your authentication agent"
        result.stdout = ""
        return result

    with patch("pathlib.Path.home", return_value=Path.home()):
        with patch.object(Path, "exists", return_value=False):
            with patch("subprocess.run", side_effect=mock_subprocess):
                result = mod.check(_make_profile())
    # Should only report SSH agent status, not key-related issues
    key_related_findings = [f for f in result.findings if "key" in f.data.get("check", "").lower()]
    assert len(key_related_findings) == 0


def test_ssh_key_audit_dsa_key_critical():
    """Test that DSA keys are flagged as CRITICAL."""
    mod = _get_module()

    def mock_ssh_keygen(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stdout = "1024 SHA256:xyz (DSA)\n"
        result.stderr = ""
        return result

    ssh_dir = Path.home() / ".ssh"
    with patch("pathlib.Path.home", return_value=Path.home()):
        with patch.object(Path, "exists", return_value=True):
            with patch.object(Path, "iterdir") as mock_iterdir:
                mock_key = MagicMock()
                mock_key.name = "id_dsa"
                mock_key.is_file.return_value = True
                mock_key.stat.return_value = MagicMock(st_mode=0o100600)
                mock_iterdir.return_value = [mock_key]

                with patch("subprocess.run", side_effect=mock_ssh_keygen):
                    result = mod.check(_make_profile())

    assert result.has_issues
    dsa_findings = [f for f in result.findings if f.data.get("check") == "dsa_key_found"]
    assert len(dsa_findings) == 1
    assert dsa_findings[0].severity == Severity.CRITICAL


def test_ssh_key_audit_weak_rsa_key():
    """Test that RSA keys < 2048 bits are flagged as WARNING."""
    mod = _get_module()

    def mock_ssh_keygen(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stdout = "1024 SHA256:xyz (RSA)\n"
        result.stderr = ""
        return result

    with patch("pathlib.Path.home", return_value=Path.home()):
        with patch.object(Path, "exists", return_value=True):
            with patch.object(Path, "iterdir") as mock_iterdir:
                mock_key = MagicMock()
                mock_key.name = "id_rsa"
                mock_key.is_file.return_value = True
                mock_key.stat.return_value = MagicMock(st_mode=0o100600)
                mock_iterdir.return_value = [mock_key]

                with patch("subprocess.run", side_effect=mock_ssh_keygen):
                    result = mod.check(_make_profile())

    assert result.has_issues
    weak_findings = [f for f in result.findings if f.data.get("check") == "weak_rsa_key"]
    assert len(weak_findings) == 1
    assert weak_findings[0].severity == Severity.WARNING
    assert weak_findings[0].data.get("key_bits") == 1024


def test_ssh_key_audit_strong_rsa_key():
    """Test that RSA keys >= 2048 bits are flagged as INFO."""
    mod = _get_module()

    def mock_ssh_keygen(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stdout = "4096 SHA256:xyz (RSA)\n"
        result.stderr = ""
        return result

    with patch("pathlib.Path.home", return_value=Path.home()):
        with patch.object(Path, "exists", return_value=True):
            with patch.object(Path, "iterdir") as mock_iterdir:
                mock_key = MagicMock()
                mock_key.name = "id_rsa"
                mock_key.is_file.return_value = True
                mock_key.stat.return_value = MagicMock(st_mode=0o100600)
                mock_iterdir.return_value = [mock_key]

                with patch("subprocess.run", side_effect=mock_ssh_keygen):
                    result = mod.check(_make_profile())

    rsa_findings = [f for f in result.findings if f.data.get("check") == "rsa_keys"]
    assert len(rsa_findings) == 1
    assert rsa_findings[0].severity == Severity.INFO


def test_ssh_key_audit_ed25519_key():
    """Test that Ed25519 keys are flagged as INFO."""
    mod = _get_module()

    def mock_ssh_keygen(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stdout = "256 SHA256:xyz (ED25519)\n"
        result.stderr = ""
        return result

    with patch("pathlib.Path.home", return_value=Path.home()):
        with patch.object(Path, "exists", return_value=True):
            with patch.object(Path, "iterdir") as mock_iterdir:
                mock_key = MagicMock()
                mock_key.name = "id_ed25519"
                mock_key.is_file.return_value = True
                mock_key.stat.return_value = MagicMock(st_mode=0o100600)
                mock_iterdir.return_value = [mock_key]

                with patch("subprocess.run", side_effect=mock_ssh_keygen):
                    result = mod.check(_make_profile())

    ed_findings = [f for f in result.findings if f.data.get("check") == "ed25519_keys"]
    assert len(ed_findings) == 1
    assert ed_findings[0].severity == Severity.INFO


def test_ssh_key_audit_bad_ssh_dir_perms():
    """Test that incorrect ~/.ssh directory permissions are flagged."""
    mod = _get_module()

    with patch("pathlib.Path.home", return_value=Path.home()):
        with patch.object(Path, "exists", return_value=True):
            with patch.object(Path, "iterdir") as mock_iterdir:
                mock_iterdir.return_value = []

                with patch.object(Path, "stat") as mock_stat:
                    # Simulate 755 permissions instead of 700
                    mock_stat.return_value = MagicMock(st_mode=0o40755)
                    with patch("subprocess.run"):
                        result = mod.check(_make_profile())

    perm_findings = [f for f in result.findings if f.data.get("check") == "bad_ssh_dir_perms"]
    assert len(perm_findings) == 1
    assert perm_findings[0].severity == Severity.WARNING


def test_ssh_key_audit_bad_key_perms():
    """Test that incorrect private key permissions are flagged."""
    mod = _get_module()

    def mock_ssh_keygen(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stdout = "4096 SHA256:xyz (RSA)\n"
        result.stderr = ""
        return result

    with patch("pathlib.Path.home", return_value=Path.home()):
        with patch.object(Path, "exists", return_value=True):
            with patch.object(Path, "iterdir") as mock_iterdir:
                mock_key = MagicMock()
                mock_key.name = "id_rsa"
                mock_key.is_file.return_value = True
                # Simulate 644 permissions instead of 600
                mock_key.stat.return_value = MagicMock(st_mode=0o100644)
                mock_iterdir.return_value = [mock_key]

                with patch("pathlib.Path.stat") as mock_ssh_stat:
                    mock_ssh_stat.return_value = MagicMock(st_mode=0o40700)

                    with patch("subprocess.run", side_effect=mock_ssh_keygen):
                        result = mod.check(_make_profile())

    perm_findings = [f for f in result.findings if f.data.get("check") == "bad_key_perms"]
    assert len(perm_findings) == 1
    assert perm_findings[0].severity == Severity.WARNING
    assert perm_findings[0].data.get("key_file") == "id_rsa"


def test_ssh_key_audit_authorized_keys():
    """Test detection of authorized_keys entries."""
    mod = _get_module()
    auth_keys_content = "ssh-rsa AAAA... user@host1\nssh-rsa BBBB... user@host2\n"

    home_path = Path.home()

    def mock_exists(path_obj):
        path_str = str(path_obj)
        if path_str == str(home_path / ".ssh"):
            return True
        if path_str == str(home_path / ".ssh" / "authorized_keys"):
            return True
        if path_str == "/etc/ssh/sshd_config":
            return False
        return False

    with patch("pathlib.Path.home", return_value=home_path):
        with patch.object(Path, "exists", side_effect=lambda: True):
            with patch.object(Path, "iterdir") as mock_iterdir:
                mock_iterdir.return_value = []

                with patch("builtins.open", mock_open(read_data=auth_keys_content)):
                    with patch.object(Path, "stat", return_value=MagicMock(st_mode=0o40700)):
                        with patch("subprocess.run"):
                            result = mod.check(_make_profile())

    auth_findings = [f for f in result.findings if f.data.get("check") == "authorized_keys"]
    assert len(auth_findings) == 1
    assert auth_findings[0].data.get("count") == 2
    assert auth_findings[0].severity == Severity.INFO


def test_ssh_key_audit_ssh_agent_running():
    """Test detection of SSH agent with loaded keys."""
    mod = _get_module()

    def mock_subprocess(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stdout = "2048 SHA256:xxx (RSA)\n2048 SHA256:yyy (RSA)\n"
        result.stderr = ""
        return result

    with patch("pathlib.Path.home", return_value=Path.home()):
        with patch.object(Path, "exists", return_value=True):
            with patch.object(Path, "iterdir") as mock_iterdir:
                mock_iterdir.return_value = []

                with patch("pathlib.Path.stat", return_value=MagicMock(st_mode=0o40700)):
                    with patch("subprocess.run", side_effect=mock_subprocess):
                        result = mod.check(_make_profile())

    agent_findings = [f for f in result.findings if f.data.get("check") == "ssh_agent_running"]
    assert len(agent_findings) == 1
    assert agent_findings[0].data.get("key_count") == 2
    assert agent_findings[0].severity == Severity.INFO


def test_ssh_key_audit_ssh_agent_not_running():
    """Test when SSH agent is not running."""
    mod = _get_module()

    def mock_subprocess(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 1
        result.stderr = "Could not open a connection to your authentication agent"
        result.stdout = ""
        return result

    with patch("pathlib.Path.home", return_value=Path.home()):
        with patch.object(Path, "exists", return_value=True):
            with patch.object(Path, "iterdir") as mock_iterdir:
                mock_iterdir.return_value = []

                with patch("pathlib.Path.stat", return_value=MagicMock(st_mode=0o40700)):
                    with patch("subprocess.run", side_effect=mock_subprocess):
                        result = mod.check(_make_profile())

    agent_findings = [f for f in result.findings if f.data.get("check") == "ssh_agent_not_running"]
    assert len(agent_findings) == 1
    assert agent_findings[0].severity == Severity.INFO


def test_ssh_key_audit_permit_root_login():
    """Test detection of PermitRootLogin yes in sshd_config."""
    mod = _get_module()
    sshd_config_content = "Port 22\nPermitRootLogin yes\n"

    def mock_ssh_keygen(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 1
        result.stderr = "no identity files found"
        result.stdout = ""
        return result

    def mock_exists_func():
        return True

    with patch("pathlib.Path.home", return_value=Path.home()):
        with patch.object(Path, "exists", return_value=True):
            with patch.object(Path, "iterdir") as mock_iterdir:
                mock_iterdir.return_value = []

                with patch("builtins.open", mock_open(read_data=sshd_config_content)):
                    with patch.object(Path, "stat", return_value=MagicMock(st_mode=0o40700)):
                        with patch("subprocess.run", side_effect=mock_ssh_keygen):
                            result = mod.check(_make_profile())

    sshd_findings = [f for f in result.findings if f.data.get("check") == "permit_root_login"]
    assert len(sshd_findings) == 1
    assert sshd_findings[0].severity == Severity.WARNING


def test_ssh_key_audit_password_auth_enabled():
    """Test detection of PasswordAuthentication yes in sshd_config."""
    mod = _get_module()
    sshd_config_content = "Port 22\nPasswordAuthentication yes\n"

    def mock_ssh_keygen(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 1
        result.stderr = "no identity files found"
        result.stdout = ""
        return result

    with patch("pathlib.Path.home", return_value=Path.home()):
        with patch.object(Path, "exists", return_value=True):
            with patch.object(Path, "iterdir") as mock_iterdir:
                mock_iterdir.return_value = []

                with patch("builtins.open", mock_open(read_data=sshd_config_content)):
                    with patch.object(Path, "stat", return_value=MagicMock(st_mode=0o40700)):
                        with patch("subprocess.run", side_effect=mock_ssh_keygen):
                            result = mod.check(_make_profile())

    auth_findings = [f for f in result.findings if f.data.get("check") == "password_auth_enabled"]
    assert len(auth_findings) == 1
    assert auth_findings[0].severity == Severity.WARNING


def test_ssh_key_audit_known_hosts():
    """Test detection of known_hosts entries."""
    mod = _get_module()
    known_hosts_content = "github.com ssh-rsa AAAA...\ngitlab.com ssh-ed25519 BBBB...\n"

    def mock_ssh_keygen(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 1
        result.stderr = "no identity files found"
        result.stdout = ""
        return result

    with patch("pathlib.Path.home", return_value=Path.home()):
        with patch.object(Path, "exists", return_value=True):
            with patch.object(Path, "iterdir") as mock_iterdir:
                mock_iterdir.return_value = []

                with patch("builtins.open", mock_open(read_data=known_hosts_content)):
                    with patch.object(Path, "stat", return_value=MagicMock(st_mode=0o40700)):
                        with patch("subprocess.run", side_effect=mock_ssh_keygen):
                            result = mod.check(_make_profile())

    known_findings = [f for f in result.findings if f.data.get("check") == "known_hosts"]
    assert len(known_findings) == 1
    assert known_findings[0].data.get("count") == 2
    assert known_findings[0].severity == Severity.INFO


def test_ssh_key_audit_fix_dsa_key():
    """Test fix suggestions for DSA keys."""
    mod = _get_module()
    dsa_finding = MagicMock()
    dsa_finding.title = "DSA key detected"
    dsa_finding.description = "DSA is broken"
    dsa_finding.data = {"check": "dsa_key_found", "key_file": "id_dsa"}

    check = MagicMock()
    check.findings = [dsa_finding]

    fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) == 1
    assert fix.all_succeeded
    assert "Regenerate DSA keys" in fix.actions[0].title


def test_ssh_key_audit_fix_weak_rsa():
    """Test fix suggestions for weak RSA keys."""
    mod = _get_module()
    weak_rsa_finding = MagicMock()
    weak_rsa_finding.title = "Weak RSA key"
    weak_rsa_finding.description = "RSA key too small"
    weak_rsa_finding.data = {"check": "weak_rsa_key", "key_file": "id_rsa", "key_bits": 1024}

    check = MagicMock()
    check.findings = [weak_rsa_finding]

    fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) == 1
    assert fix.all_succeeded
    assert "Regenerate weak RSA key" in fix.actions[0].title


def test_ssh_key_audit_fix_bad_perms():
    """Test fix suggestions for bad permissions."""
    mod = _get_module()
    perm_finding = MagicMock()
    perm_finding.title = "Bad key perms"
    perm_finding.description = "Bad perms"
    perm_finding.data = {"check": "bad_key_perms", "key_file": "id_rsa", "current_perms": "644"}

    check = MagicMock()
    check.findings = [perm_finding]

    fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) == 1
    assert fix.all_succeeded
    assert "Fix private key file permissions" in fix.actions[0].title
