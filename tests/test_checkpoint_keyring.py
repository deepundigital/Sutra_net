import json
import os
import stat

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from sutra_net.compliance.trusted_checkpoint import (
    TrustedKeyRing,
    TrustedKeyRingError,
    create_checkpoint,
    generate_keypair,
    public_key_fingerprint,
    sign_checkpoint,
    verify_signed_checkpoint,
)


@pytest.fixture
def keypair():
    return generate_keypair()


@pytest.fixture
def other_keypair():
    return generate_keypair()


@pytest.fixture
def ring(tmp_path):
    return TrustedKeyRing(tmp_path / "keys" / "trusted_keys.json")


# --------------------------------------------------------------------- add


def test_add_and_get_roundtrip(ring, keypair):
    _, public_key = keypair
    ring.add_key("operator-key-01", public_key)

    assert ring.has_key("operator-key-01")
    assert (
        public_key_fingerprint(ring.get_key("operator-key-01"))
        == public_key_fingerprint(public_key)
    )
    assert ring.key_ids() == ["operator-key-01"]


def test_add_same_key_twice_is_idempotent(ring, keypair):
    _, public_key = keypair
    ring.add_key("operator-key-01", public_key)
    before = ring.registry_path.read_bytes()

    ring.add_key("operator-key-01", public_key)

    assert ring.registry_path.read_bytes() == before


def test_add_different_key_under_same_id_refused(ring, keypair, other_keypair):
    ring.add_key("operator-key-01", keypair[1])

    with pytest.raises(TrustedKeyRingError, match="Refusing to replace"):
        ring.add_key("operator-key-01", other_keypair[1])


def test_unsafe_key_id_rejected(ring, keypair):
    for bad_id in ["../escape", "with/slash", ".hidden", "sp ace", ""]:
        with pytest.raises(TrustedKeyRingError, match="key_id"):
            ring.add_key(bad_id, keypair[1])


def test_non_ed25519_key_rejected(ring):
    ec_key = ec.generate_private_key(ec.SECP256R1())

    with pytest.raises(TrustedKeyRingError, match="Ed25519"):
        ring.add_key("bad-key", ec_key.public_key())


# -------------------------------------------------------------------- read


def test_missing_key_raises(ring):
    with pytest.raises(TrustedKeyRingError, match="Unknown signing key ID"):
        ring.get_key("does-not-exist")


def test_missing_file_is_empty_registry(ring):
    assert ring.trusted_keys() == {}
    assert ring.key_ids() == []
    assert not ring.has_key("anything")


def test_keyring_is_stateless_across_instances(ring, keypair):
    _, public_key = keypair
    ring.add_key("operator-key-01", public_key)

    reopened = TrustedKeyRing(ring.registry_path)
    assert reopened.has_key("operator-key-01")


def test_registry_file_has_owner_only_permissions(ring, keypair):
    ring.add_key("operator-key-01", keypair[1])

    mode = stat.S_IMODE(os.lstat(ring.registry_path).st_mode)
    assert mode == 0o600


def test_loose_registry_permissions_rejected(ring, keypair):
    ring.add_key("operator-key-01", keypair[1])
    os.chmod(ring.registry_path, 0o644)

    with pytest.raises(TrustedKeyRingError, match="too open"):
        ring.trusted_keys()


def _write_registry_file(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.chmod(path, 0o600)


def test_tampered_registry_entry_detected(ring, keypair, other_keypair, tmp_path):
    ring.add_key("operator-key-01", keypair[1])
    registry_path = ring.registry_path

    # Replace the stored PEM with a different, structurally valid Ed25519 key
    # while keeping the recorded fingerprint: the mismatch must be caught.
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    impostor_pem = other_keypair[1].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    data["keys"]["operator-key-01"]["public_key_pem"] = impostor_pem
    _write_registry_file(registry_path, data)

    with pytest.raises(TrustedKeyRingError, match="tampered"):
        ring.trusted_keys()


def test_corrupt_registry_json_rejected(ring, keypair):
    ring.add_key("operator-key-01", keypair[1])
    ring.registry_path.write_bytes(b"{broken json")

    with pytest.raises(TrustedKeyRingError, match="corrupt"):
        ring.trusted_keys()


def test_unsupported_registry_version_rejected(ring, tmp_path):
    _write_registry_file(
        tmp_path / "keys" / "trusted_keys.json",
        {"registry_version": 99, "keys": {}},
    )

    with pytest.raises(TrustedKeyRingError, match="version"):
        TrustedKeyRing(tmp_path / "keys" / "trusted_keys.json").trusted_keys()


# ------------------------------------------------------------ integration


def test_trusted_keys_feed_checkpoint_verification(ring, keypair):
    private_key, public_key = keypair
    ring.add_key("operator-key-01", public_key)

    checkpoint = create_checkpoint(
        ledger_id="case-ring-ledger",
        sequence=3,
        last_entry_hash="c" * 64,
        signing_key_id="operator-key-01",
        timestamp_utc="2026-11-02T06:00:00Z",
    )
    envelope = sign_checkpoint(checkpoint, private_key)

    verified = verify_signed_checkpoint(envelope, ring.trusted_keys())

    assert verified == checkpoint


def test_verify_fails_when_key_not_in_ring(ring, keypair):
    private_key, _ = keypair
    checkpoint = create_checkpoint(
        ledger_id="case-ring-ledger",
        sequence=3,
        last_entry_hash="c" * 64,
        signing_key_id="operator-key-01",
        timestamp_utc="2026-11-02T06:00:00Z",
    )
    envelope = sign_checkpoint(checkpoint, private_key)

    with pytest.raises(ValueError, match="Unknown signing key ID"):
        verify_signed_checkpoint(envelope, ring.trusted_keys())
