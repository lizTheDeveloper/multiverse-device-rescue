import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from rescue.security.signers import TrustedSigner, TrustedSignerSet
from rescue.update.verify import verify_commit_approval

TRUSTED = TrustedSignerSet(signers=[
    TrustedSigner(signer_id="maintainer-a", key_id="AAAA000000000001", key_format="gpg", public_key="DUMMY-A", name="Alice"),
    TrustedSigner(signer_id="maintainer-b", key_id="BBBB000000000002", key_format="gpg", public_key="DUMMY-B", name="Bob"),
    TrustedSigner(signer_id="maintainer-c", key_id="CCCC000000000003", key_format="gpg", public_key="DUMMY-C", name="Carol"),
])


def _good_gpg_result(key_id: str):
    return SimpleNamespace(
        returncode=0,
        stdout="",
        stderr=(
            "[GNUPG:] NEWSIG\n"
            f"[GNUPG:] GOODSIG {key_id} Maintainer <m@example.com>\n"
            "[GNUPG:] TRUST_ULTIMATE\n"
        ),
    )


def _good_ssh_result(fingerprint: str):
    return SimpleNamespace(
        returncode=0,
        stdout="",
        stderr=f'Good "git" signature for maintainer@example.com with RSA key {fingerprint}\n',
    )


def _bad_result():
    return SimpleNamespace(returncode=1, stdout="", stderr="[GNUPG:] BADSIG deadbeef\n")


def _fake_repo(tags, verify_results):
    """The fake's verify_tag_raw accepts (and ignores) extra_env/
    extra_git_config -- verify.py always passes them, but these unit
    tests care about the aggregation logic, not the hermetic plumbing
    itself (that's what the real end-to-end test below is for)."""
    repo = MagicMock()
    repo.tags_at_commit.return_value = tags
    repo.verify_tag_raw.side_effect = (
        lambda tag, extra_env=None, extra_git_config=None: verify_results[tag]
    )
    return repo


def test_approved_with_two_of_three_trusted_signers():
    tags = ["approved/maintainer-a/1", "approved/maintainer-b/1"]
    repo = _fake_repo(tags, {
        "approved/maintainer-a/1": _good_gpg_result("AAAA000000000001"),
        "approved/maintainer-b/1": _good_gpg_result("BBBB000000000002"),
    })

    result = verify_commit_approval(repo, "deadbeef", TRUSTED, required_approvals=2)

    assert result.approved
    assert result.approving_signer_ids == ["maintainer-a", "maintainer-b"]


def test_not_approved_with_only_one_signature():
    tags = ["approved/maintainer-a/1"]
    repo = _fake_repo(tags, {"approved/maintainer-a/1": _good_gpg_result("AAAA000000000001")})

    result = verify_commit_approval(repo, "deadbeef", TRUSTED, required_approvals=2)

    assert not result.approved
    assert "1" in result.reason and "2" in result.reason


def test_bad_signature_does_not_count():
    tags = ["approved/maintainer-a/1", "approved/maintainer-b/1"]
    repo = _fake_repo(tags, {
        "approved/maintainer-a/1": _good_gpg_result("AAAA000000000001"),
        "approved/maintainer-b/1": _bad_result(),
    })

    result = verify_commit_approval(repo, "deadbeef", TRUSTED, required_approvals=2)

    assert not result.approved
    assert result.approving_signer_ids == ["maintainer-a"]


def test_untrusted_key_id_does_not_count():
    tags = ["approved/maintainer-a/1", "approved/unknown-signer/1"]
    repo = _fake_repo(tags, {
        "approved/maintainer-a/1": _good_gpg_result("AAAA000000000001"),
        "approved/unknown-signer/1": _good_gpg_result("FFFFFFFFFFFFFFFF"),
    })

    result = verify_commit_approval(repo, "deadbeef", TRUSTED, required_approvals=2)

    assert not result.approved
    assert result.approving_signer_ids == ["maintainer-a"]


def test_revoked_signer_does_not_count():
    tags = ["approved/maintainer-a/1", "approved/maintainer-b/1"]
    repo = _fake_repo(tags, {
        "approved/maintainer-a/1": _good_gpg_result("AAAA000000000001"),
        "approved/maintainer-b/1": _good_gpg_result("BBBB000000000002"),
    })

    result = verify_commit_approval(
        repo, "deadbeef", TRUSTED, required_approvals=2, revoked_signer_ids={"maintainer-b"}
    )

    assert not result.approved
    assert result.approving_signer_ids == ["maintainer-a"]


def test_duplicate_tags_from_same_signer_count_once():
    tags = ["approved/maintainer-a/1", "approved/maintainer-a/2"]
    repo = _fake_repo(tags, {
        "approved/maintainer-a/1": _good_gpg_result("AAAA000000000001"),
        "approved/maintainer-a/2": _good_gpg_result("AAAA000000000001"),
    })

    result = verify_commit_approval(repo, "deadbeef", TRUSTED, required_approvals=2)

    assert not result.approved
    assert result.approving_signer_ids == ["maintainer-a"]


def test_tags_not_matching_prefix_are_ignored():
    repo = MagicMock()
    repo.tags_at_commit.return_value = ["release/v1.0", "approved/maintainer-a/1"]
    repo.verify_tag_raw.side_effect = (
        lambda tag, extra_env=None, extra_git_config=None: _good_gpg_result("AAAA000000000001")
    )

    result = verify_commit_approval(repo, "deadbeef", TRUSTED, required_approvals=1)

    assert result.approved
    called_tags = [call.args[0] for call in repo.verify_tag_raw.call_args_list]
    assert called_tags == ["approved/maintainer-a/1"]


def test_exception_from_verify_tag_is_treated_as_not_approved():
    repo = MagicMock()
    repo.tags_at_commit.return_value = ["approved/maintainer-a/1"]
    repo.verify_tag_raw.side_effect = RuntimeError("boom")

    result = verify_commit_approval(repo, "deadbeef", TRUSTED, required_approvals=1)

    assert not result.approved
    assert result.approving_signer_ids == []


def test_ssh_signed_tag_is_recognized():
    tags = ["approved/maintainer-b/1"]
    repo = _fake_repo(tags, {"approved/maintainer-b/1": _good_ssh_result("SHA256:abcdefg")})
    trusted = TrustedSignerSet(
        signers=[
            TrustedSigner(
                signer_id="maintainer-b",
                key_id="SHA256:abcdefg",
                key_format="ssh",
                public_key="ssh-ed25519 AAAAdummykeydata maintainer-b",
            )
        ]
    )

    result = verify_commit_approval(repo, "deadbeef", trusted, required_approvals=1)

    assert result.approved
    assert result.approving_signer_ids == ["maintainer-b"]


pytestmark_gpg = pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg is not installed")


@pytestmark_gpg
def test_verification_succeeds_without_the_signing_key_in_the_ambient_keyring(
    tmp_path, make_origin, monkeypatch
):
    """Regression test for the core security property of this task: a
    freshly installed rescue has no maintainer keys in its ambient GPG
    keyring. This generates a real keypair in one throwaway GNUPGHOME,
    signs a real tag with it, then verifies with the ambient GNUPGHOME
    pointed at a *different*, empty directory that never saw that key --
    simulating exactly what a real end user's machine looks like."""
    from rescue.update.repo import ContentRepo

    # Short paths are required here: gpg-agent's control socket has a
    # small max path length that tmp_path's nested pytest directories can
    # exceed on some platforms.
    signing_gnupghome = tempfile.mkdtemp(prefix="mdr-gpg-", dir="/tmp")
    empty_ambient_gnupghome = tempfile.mkdtemp(prefix="mdr-gpg-empty-", dir="/tmp")
    try:
        params_file = Path(signing_gnupghome) / "params.txt"
        params_file.write_text(
            "%no-protection\nKey-Type: eddsa\nKey-Curve: ed25519\n"
            "Name-Real: Test Maintainer\nName-Email: maintainer@example.com\n"
            "Expire-Date: 0\n%commit\n"
        )
        subprocess.run(
            ["gpg", "--homedir", signing_gnupghome, "--batch", "--generate-key", str(params_file)],
            capture_output=True, text=True,
        )
        list_out = subprocess.run(
            ["gpg", "--homedir", signing_gnupghome, "--list-secret-keys", "--keyid-format=long"],
            capture_output=True, text=True,
        ).stdout
        key_id = next(
            line for line in list_out.splitlines() if line.strip().startswith("sec")
        ).split("/")[1].split()[0]
        armored_public_key = subprocess.run(
            ["gpg", "--homedir", signing_gnupghome, "--armor", "--export", key_id],
            capture_output=True, text=True,
        ).stdout

        origin = make_origin()
        commit_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=origin, capture_output=True, text=True
        ).stdout.strip()

        sign_env = {**os.environ, "GNUPGHOME": signing_gnupghome}
        tag_result = subprocess.run(
            [
                "git", "-c", f"user.signingkey={key_id}", "-c", "gpg.program=gpg",
                "tag", "-s", "approved/maintainer-a/1", "-m", "approved", commit_sha,
            ],
            cwd=origin, capture_output=True, text=True, env=sign_env,
        )
        assert tag_result.returncode == 0, tag_result.stderr

        # Verification runs with GNUPGHOME pointed at a directory that has
        # NEVER seen this key -- simulating a real end-user machine.
        monkeypatch.setenv("GNUPGHOME", empty_ambient_gnupghome)

        trusted = TrustedSignerSet(signers=[
            TrustedSigner(
                signer_id="maintainer-a",
                key_id=key_id,
                key_format="gpg",
                public_key=armored_public_key,
            )
        ])
        repo = ContentRepo(local_path=origin, remote_url="unused")

        result = verify_commit_approval(repo, commit_sha, trusted, required_approvals=1)

        assert result.approved, result.reason
        assert result.approving_signer_ids == ["maintainer-a"]
    finally:
        shutil.rmtree(signing_gnupghome, ignore_errors=True)
        shutil.rmtree(empty_ambient_gnupghome, ignore_errors=True)
