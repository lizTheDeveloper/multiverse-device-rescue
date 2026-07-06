"""M-of-N approval of a content-repo commit via signed git tags.

Trust model: after reviewing an update, each maintainer creates and
pushes a signed tag (GPG or SSH signed, via `git tag -s`) pointing at the
exact commit they're approving, following the convention
`<tag_prefix><signer_id>/<content_version>` (e.g.
"approved/maintainer-a/2026.07.10-1"). A commit is accepted once at least
`required_approvals` *distinct* trusted, non-revoked signers have a
validly-signed tag pointing at it.

Critical detail: verification never depends on the ambient environment's
own GPG keyring or SSH allowed-signers file. On a normal end-user
machine, neither contains the maintainers' keys -- `git verify-tag`
against ambient state fails closed with NO_PUBKEY / "No principal
matched", which would make every real, correctly-signed update
permanently stuck at "not approved". Instead, this module builds a
throwaway, hermetic verification context per call: a scratch GNUPGHOME
populated only with the GPG public keys shipped in trusted_signers.json,
and a scratch `allowed_signers` file populated only with the SSH public
keys shipped there. Every `git verify-tag` invocation is pointed at that
scratch context via environment/config overrides, never the user's own
keyring or SSH config. Trust is decided entirely by what this deployment
ships, never by what happens to be locally configured.

This still does no cryptography of its own -- `git verify-tag` (via
ContentRepo.verify_tag_raw) does 100% of the actual signature
verification; this module only supplies the trusted key material and
interprets the result. Any unexpected output, parse failure, or nonzero
exit is treated as "this tag doesn't count" -- fail closed, always.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from rescue.security.signers import TrustedSignerSet

_GPG_GOODSIG_RE = re.compile(r"\[GNUPG:\] GOODSIG ([0-9A-Fa-f]+) ")
_SSH_GOODSIG_RE = re.compile(r'Good "git" signature .*?key (SHA256:\S+)')


@dataclass(frozen=True)
class TagApproval:
    tag: str
    signer_id: str


@dataclass
class ApprovalResult:
    approved: bool
    approving_signer_ids: list[str] = field(default_factory=list)
    reason: str = ""


def verify_commit_approval(
    repo,
    commit_sha: str,
    trusted_signers: TrustedSignerSet,
    required_approvals: int,
    tag_prefix: str = "approved/",
    revoked_signer_ids: set[str] | None = None,
) -> ApprovalResult:
    revoked = revoked_signer_ids or set()

    candidate_tags = [
        tag for tag in repo.tags_at_commit(commit_sha) if tag.startswith(tag_prefix)
    ]

    approving_signer_ids: set[str] = set()
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        gnupghome = _build_hermetic_gnupghome(tmp_path, trusted_signers)
        allowed_signers_path = _build_allowed_signers_file(tmp_path, trusted_signers)

        for tag in candidate_tags:
            key_id = _verify_tag_hermetically(repo, tag, gnupghome, allowed_signers_path)
            if key_id is None:
                continue

            signer = trusted_signers.by_key_id(key_id)
            if signer is None or signer.signer_id in revoked:
                continue

            approving_signer_ids.add(signer.signer_id)

    approved = len(approving_signer_ids) >= required_approvals
    reason = (
        ""
        if approved
        else f"only {len(approving_signer_ids)} of required {required_approvals} maintainer approvals"
    )
    return ApprovalResult(
        approved=approved,
        approving_signer_ids=sorted(approving_signer_ids),
        reason=reason,
    )


def _build_hermetic_gnupghome(tmp_path: Path, trusted_signers: TrustedSignerSet) -> Path | None:
    """Imports every GPG-format trusted signer's shipped public key into a
    throwaway GNUPGHOME, so verification depends only on what this
    deployment trusts -- never on whatever is (or isn't) in the
    operator's own keyring. Returns None (skip GPG verification entirely)
    if there are no GPG-format signers configured."""
    gpg_signers = [s for s in trusted_signers.signers if s.key_format == "gpg" and s.public_key]
    if not gpg_signers:
        return None

    gnupghome = tmp_path / "gnupg"
    gnupghome.mkdir(mode=0o700)
    keys_file = tmp_path / "trusted_gpg_keys.asc"
    keys_file.write_text("\n".join(s.public_key for s in gpg_signers))

    try:
        subprocess.run(
            ["gpg", "--homedir", str(gnupghome), "--batch", "--import", str(keys_file)],
            capture_output=True,
            text=True,
        )
    except Exception:
        pass  # fail closed: an import failure just means later GOODSIG checks miss

    return gnupghome


def _build_allowed_signers_file(tmp_path: Path, trusted_signers: TrustedSignerSet) -> Path | None:
    """Writes an `allowed_signers` file (git's SSH-signature verification
    format) containing only the SSH-format trusted signers' shipped
    public keys. Returns None if there are no SSH-format signers."""
    ssh_signers = [s for s in trusted_signers.signers if s.key_format == "ssh" and s.public_key]
    if not ssh_signers:
        return None

    path = tmp_path / "allowed_signers"
    lines = [f"{s.signer_id} {s.public_key}" for s in ssh_signers]
    path.write_text("\n".join(lines) + "\n")
    return path


def _verify_tag_hermetically(
    repo, tag: str, gnupghome: Path | None, allowed_signers_path: Path | None
) -> str | None:
    """Tries GPG verification (via the hermetic GNUPGHOME) then SSH
    verification (via the hermetic allowed_signers file), returning the
    key ID/fingerprint git reports for whichever succeeds. A tag is only
    ever signed one way, so trying both costs nothing but an extra
    subprocess call when the first guess doesn't apply."""
    if gnupghome is not None:
        key_id = _try_verify(repo, tag, extra_env={"GNUPGHOME": str(gnupghome)})
        if key_id is not None:
            return key_id

    if allowed_signers_path is not None:
        key_id = _try_verify(
            repo,
            tag,
            extra_git_config={
                "gpg.format": "ssh",
                "gpg.ssh.allowedSignersFile": str(allowed_signers_path),
            },
        )
        if key_id is not None:
            return key_id

    return None


def _try_verify(
    repo,
    tag: str,
    extra_env: dict[str, str] | None = None,
    extra_git_config: dict[str, str] | None = None,
) -> str | None:
    try:
        result = repo.verify_tag_raw(tag, extra_env=extra_env, extra_git_config=extra_git_config)
    except Exception:
        return None
    return _extract_signer_key_id(result.returncode, result.stdout, result.stderr)


def _extract_signer_key_id(returncode: int, stdout: str, stderr: str) -> str | None:
    """Fails closed: a nonzero exit is always rejected outright, since
    `git verify-tag` exits nonzero for any bad, expired, or (for SSH)
    not-allowed signature. Only on a zero exit do we parse out which key
    git says signed the tag."""
    if returncode != 0:
        return None

    combined = stdout + "\n" + stderr

    match = _GPG_GOODSIG_RE.search(combined)
    if match:
        return match.group(1)

    match = _SSH_GOODSIG_RE.search(combined)
    if match:
        return match.group(1)

    return None
