"""Trusted git-tag signers (baked into the package at build time) and the
locally-persisted set of signers that have since been revoked.

A "signer" here is identified by whatever key material git's own
verification surfaces: a GPG long key ID (from `git verify-tag --raw`'s
GOODSIG line) or an SSH key fingerprint (from git's SSH-signature
verification output, e.g. "SHA256:AbCd..."). rescue never re-implements
signature verification itself -- it only decides whether the identity git
already verified is one this deployment trusts.
"""

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class TrustedSigner:
    signer_id: str  # human-readable label, e.g. "maintainer-a"
    key_id: str  # GPG long key id (hex) or SSH fingerprint ("SHA256:...") -- used only to look up which signer a *verified* tag belongs to
    key_format: str = "gpg"  # "gpg" | "ssh"
    public_key: str = ""  # the actual key material: an armored GPG public key block, or an SSH public key line (e.g. "ssh-ed25519 AAAA... maintainer-a")
    name: str = ""


@dataclass(frozen=True)
class TrustedSignerSet:
    signers: list[TrustedSigner]

    def by_key_id(self, key_id: str) -> TrustedSigner | None:
        for signer in self.signers:
            if signer.key_id == key_id:
                return signer
        return None


DEFAULT_TRUSTED_SIGNERS_PATH = Path(__file__).parent / "trusted_signers.json"


class TrustConfigurationError(ValueError):
    pass


def load_trusted_signers(path: Path) -> TrustedSignerSet:
    data = json.loads(path.read_text())
    signers = [
        TrustedSigner(
            signer_id=entry["signer_id"],
            key_id=entry["key_id"],
            key_format=entry.get("key_format", "gpg"),
            public_key=entry.get("public_key", ""),
            name=entry.get("name", ""),
        )
        for entry in data["signers"]
    ]
    return TrustedSignerSet(signers=signers)


def validate_trusted_signers(signers: TrustedSignerSet, required_approvals: int) -> None:
    if required_approvals < 1:
        raise TrustConfigurationError("required approvals must be at least one")
    if len(signers.signers) < required_approvals:
        raise TrustConfigurationError(
            f"configured {len(signers.signers)} trusted signers, but {required_approvals} are required"
        )

    signer_ids: set[str] = set()
    key_ids: set[str] = set()
    for signer in signers.signers:
        values = (signer.signer_id, signer.key_id, signer.public_key)
        if not signer.public_key or any(value.startswith("REPLACE_WITH_") for value in values):
            raise TrustConfigurationError(
                "trusted signer configuration contains placeholder or missing key material"
            )
        if signer.signer_id in signer_ids or signer.key_id in key_ids:
            raise TrustConfigurationError("trusted signer IDs and key IDs must be unique")
        signer_ids.add(signer.signer_id)
        key_ids.add(signer.key_id)


class RevokedSignerStore:
    """Locally-persisted set of revoked signer IDs. Revocation is a local
    operator decision (see `rescue trust revoke` in the CLI), not a
    threshold-signed protocol action -- it exists so a machine can stop
    trusting a signer's approvals immediately, without waiting for a new
    threshold-approved commit to remove them from trusted_signers.json."""

    def __init__(self, path: Path):
        self._path = path
        self._revoked: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            data = json.loads(self._path.read_text())
            self._revoked = dict(data.get("revoked", {}))

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps({"revoked": self._revoked}, indent=2, sort_keys=True))

    def is_revoked(self, signer_id: str) -> bool:
        return signer_id in self._revoked

    def revoke(self, signer_id: str, reason: str) -> None:
        self._revoked[signer_id] = reason
        self._save()

    def revoked_signer_ids(self) -> set[str]:
        return set(self._revoked.keys())
