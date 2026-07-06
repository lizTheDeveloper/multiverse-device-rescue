import json

from rescue.security.signers import RevokedSignerStore, TrustedSigner, load_trusted_signers


def test_load_trusted_signers(tmp_path):
    path = tmp_path / "trusted_signers.json"
    path.write_text(json.dumps({
        "signers": [
            {"signer_id": "maintainer-a", "key_id": "AAAA1111BBBB2222", "name": "Alice"},
            {"signer_id": "maintainer-b", "key_id": "SHA256:abcdefg", "name": "Bob"},
        ]
    }))

    signer_set = load_trusted_signers(path)

    assert len(signer_set.signers) == 2
    assert signer_set.by_key_id("AAAA1111BBBB2222") == TrustedSigner(
        signer_id="maintainer-a", key_id="AAAA1111BBBB2222", name="Alice"
    )
    assert signer_set.by_key_id("does-not-exist") is None


def test_revoked_signer_store_starts_empty(tmp_path):
    store = RevokedSignerStore(tmp_path / "revoked.json")
    assert store.revoked_signer_ids() == set()
    assert not store.is_revoked("maintainer-a")


def test_revoked_signer_store_revoke_and_check(tmp_path):
    store = RevokedSignerStore(tmp_path / "revoked.json")
    store.revoke("maintainer-c", "private key exposed in a public repo")
    assert store.is_revoked("maintainer-c")
    assert not store.is_revoked("maintainer-a")
    assert store.revoked_signer_ids() == {"maintainer-c"}


def test_revoked_signer_store_persists_across_instances(tmp_path):
    path = tmp_path / "revoked.json"
    RevokedSignerStore(path).revoke("maintainer-b", "compromised laptop")
    assert RevokedSignerStore(path).is_revoked("maintainer-b")


def test_revoked_signer_store_missing_file_is_empty(tmp_path):
    store = RevokedSignerStore(tmp_path / "does_not_exist.json")
    assert store.revoked_signer_ids() == set()
