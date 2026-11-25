import json
import os

import pytest

from sutra_net.compliance.trusted_checkpoint import (
    CheckpointStorage,
    TrustedCheckpointService,
    TrustedCheckpointServiceError,
    TrustedKeyRing,
    generate_keypair,
)


@pytest.fixture
def env(tmp_path):
    """Wired service with a fresh store, registry and key file path."""

    private_key_path = tmp_path / "keys" / "signing_key.pem"
    service = TrustedCheckpointService(
        storage=CheckpointStorage(tmp_path / "checkpoints"),
        keyring=TrustedKeyRing(tmp_path / "keys" / "trusted_keys.json"),
        private_key_path=private_key_path,
    )
    return {"service": service, "private_key_path": private_key_path, "tmp_path": tmp_path}


def seal_args(sequence, ledger_id="case-svc-ledger"):
    return {
        "ledger_id": ledger_id,
        "sequence": sequence,
        "last_entry_hash": "a" * 64,
        "signing_key_id": "svc-key-01",
    }


# ---------------------------------------------------------------- lifecycle


def test_full_lifecycle_seal_and_audit(env):
    service = env["service"]
    public_pem = service.generate_signing_key()
    assert b"BEGIN PUBLIC KEY" in public_pem

    service.register_signing_key("svc-key-01")

    first = service.seal(**seal_args(1))
    second = service.seal(**seal_args(2))

    assert first["sequence"] == 1
    assert second["sequence"] == 2

    report = service.chain_report("case-svc-ledger")
    assert report["valid"] is True
    assert report["count"] == 2
    assert service.stored_checkpoints("case-svc-ledger") is not None


def test_encrypted_signing_key_lifecycle(env):
    service = env["service"]
    service.generate_signing_key(passphrase=b"op-secret")
    service.register_signing_key("svc-key-01", passphrase=b"op-secret")

    service.seal(**seal_args(1), passphrase=b"op-secret")

    report = service.chain_report("case-svc-ledger")
    assert report["valid"] is True


def test_key_file_is_owner_only(env):
    service = env["service"]
    service.generate_signing_key()

    mode = os.stat(env["private_key_path"]).st_mode & 0o777
    assert mode == 0o600


# ------------------------------------------------------------------ refusal


def test_seal_refuses_when_key_file_missing(env):
    service = env["service"]

    with pytest.raises(TrustedCheckpointServiceError, match="does not exist"):
        service.seal(**seal_args(1))


def test_seal_refuses_unregistered_signing_key(env):
    service = env["service"]
    service.generate_signing_key()

    with pytest.raises(TrustedCheckpointServiceError, match="not registered"):
        service.seal(**seal_args(1))


def test_seal_refuses_mismatched_registered_key(env):
    service = env["service"]
    # Register a different key than the one that will sit on disk.
    service.keyring.add_key("svc-key-01", generate_keypair()[1])
    service.generate_signing_key()

    with pytest.raises(TrustedCheckpointServiceError, match="does not match"):
        service.seal(**seal_args(1))


def test_seal_refuses_loose_key_file_permissions(env):
    service = env["service"]
    service.generate_signing_key()
    os.chmod(env["private_key_path"], 0o644)

    with pytest.raises(TrustedCheckpointServiceError, match="too open"):
        service.seal(**seal_args(1))


def test_reseal_same_state_is_idempotent(env):
    service = env["service"]
    service.generate_signing_key()
    service.register_signing_key("svc-key-01")

    first = service.seal(**seal_args(1), timestamp_utc="2026-11-04T06:00:00Z")
    second = service.seal(**seal_args(1), timestamp_utc="2026-11-04T06:00:00Z")

    assert first["digest"] == second["digest"]
    assert first["filename"] == second["filename"]


def test_reseal_same_sequence_different_content_refused(env):
    service = env["service"]
    service.generate_signing_key()
    service.register_signing_key("svc-key-01")

    service.seal(**seal_args(1), timestamp_utc="2026-11-04T06:00:00Z")

    with pytest.raises(TrustedCheckpointServiceError, match="already sealed"):
        service.seal(**seal_args(1), timestamp_utc="2026-11-04T07:00:00Z")


# ------------------------------------------------------------------- audit


def test_chain_report_detects_post_seal_tampering(env):
    service = env["service"]
    service.generate_signing_key()
    service.register_signing_key("svc-key-01")
    service.seal(**seal_args(1))

    target = next(service.storage.base_dir.glob("*.checkpoint.json"))
    envelope = json.loads(target.read_text(encoding="utf-8"))
    envelope["checkpoint"]["last_entry_hash"] = "f" * 64
    target.write_text(json.dumps(envelope), encoding="utf-8")

    report = service.chain_report("case-svc-ledger")
    assert report["valid"] is False


def test_chain_report_spans_multiple_ledgers_when_unscoped(env):
    service = env["service"]
    service.generate_signing_key()
    service.register_signing_key("svc-key-01")

    service.seal(**seal_args(1, ledger_id="case-a"))
    service.seal(**seal_args(2, ledger_id="case-b"))

    report = service.chain_report()
    assert report["valid"] is False  # two different ledger ids in one chain
    assert report["count"] == 2


def test_constructor_validates_component_types():
    with pytest.raises(TrustedCheckpointServiceError):
        TrustedCheckpointService(storage="nope", keyring="nope", private_key_path="x")
