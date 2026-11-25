import base64
import copy

import pytest

from sutra_net.compliance.trusted_checkpoint import (
    create_checkpoint,
    generate_keypair,
    load_private_key,
    load_public_key,
    serialize_private_key,
    serialize_public_key,
    sign_checkpoint,
    verify_signed_checkpoint,
)


@pytest.fixture
def keypair():
    return generate_keypair()


@pytest.fixture
def checkpoint():
    return create_checkpoint(
        ledger_id="sutra-net-test-ledger",
        sequence=10,
        last_entry_hash="a" * 64,
        signing_key_id="test-key-01",
        timestamp_utc="2026-10-31T06:00:00Z",
    )


@pytest.fixture
def signed_checkpoint(checkpoint, keypair):
    private_key, public_key = keypair
    envelope = sign_checkpoint(checkpoint, private_key)
    trusted_keys = {"test-key-01": public_key}
    return envelope, trusted_keys


def test_sign_and_verify_checkpoint(signed_checkpoint, checkpoint):
    envelope, trusted_keys = signed_checkpoint

    verified = verify_signed_checkpoint(envelope, trusted_keys)

    assert verified == checkpoint


def test_wrong_public_key_is_rejected(signed_checkpoint):
    envelope, _ = signed_checkpoint
    _, wrong_public_key = generate_keypair()

    with pytest.raises(ValueError, match="signature verification failed"):
        verify_signed_checkpoint(
            envelope,
            {"test-key-01": wrong_public_key},
        )


def test_modified_checkpoint_is_rejected(signed_checkpoint):
    envelope, trusted_keys = signed_checkpoint
    modified = copy.deepcopy(envelope)
    modified["checkpoint"]["sequence"] = 11

    with pytest.raises(ValueError, match="signature verification failed"):
        verify_signed_checkpoint(modified, trusted_keys)


def test_modified_signature_is_rejected(signed_checkpoint):
    envelope, trusted_keys = signed_checkpoint
    modified = copy.deepcopy(envelope)
    modified["signature"] = "A" * len(modified["signature"])

    with pytest.raises(ValueError):
        verify_signed_checkpoint(modified, trusted_keys)


def test_unknown_signing_key_id_is_rejected(signed_checkpoint):
    envelope, trusted_keys = signed_checkpoint
    modified = copy.deepcopy(envelope)
    modified["checkpoint"]["signing_key_id"] = "unknown-key"

    with pytest.raises(ValueError, match="Unknown signing key ID"):
        verify_signed_checkpoint(modified, trusted_keys)


def test_malformed_base64_signature_is_rejected(signed_checkpoint):
    envelope, trusted_keys = signed_checkpoint
    modified = copy.deepcopy(envelope)
    modified["signature"] = "not-valid-base64!"

    with pytest.raises(ValueError, match="Malformed base64"):
        verify_signed_checkpoint(modified, trusted_keys)


def test_private_and_public_key_serialization_roundtrip(keypair):
    private_key, public_key = keypair

    private_pem = serialize_private_key(private_key)
    public_pem = serialize_public_key(public_key)

    restored_private = load_private_key(private_pem)
    restored_public = load_public_key(public_pem)

    message = b"trusted checkpoint test"
    signature = restored_private.sign(message)

    restored_public.verify(signature, message)


def test_invalid_envelope_schema_is_rejected(signed_checkpoint):
    envelope, trusted_keys = signed_checkpoint
    modified = copy.deepcopy(envelope)
    modified["unexpected"] = "field"

    with pytest.raises(ValueError, match="schema"):
        verify_signed_checkpoint(modified, trusted_keys)


def test_unsupported_algorithm_is_rejected(signed_checkpoint):
    envelope, trusted_keys = signed_checkpoint
    modified = copy.deepcopy(envelope)
    modified["signature_algorithm"] = "RSA"

    with pytest.raises(ValueError, match="algorithm"):
        verify_signed_checkpoint(modified, trusted_keys)
def test_signature_has_exact_ed25519_length(signed_checkpoint):
    envelope, trusted_keys = signed_checkpoint
    modified = copy.deepcopy(envelope)
    modified["signature"] = "YQ=="

    with pytest.raises(ValueError, match="signature length"):
        verify_signed_checkpoint(modified, trusted_keys)


def test_signing_does_not_mutate_original_checkpoint(checkpoint, keypair):
    import copy

    original = copy.deepcopy(checkpoint)
    private_key, _ = keypair

    sign_checkpoint(checkpoint, private_key)

    assert checkpoint == original


def test_signature_length_boundary_is_rejected(signed_checkpoint):
    """63- and 65-byte signatures must fail the explicit length check."""

    envelope, trusted_keys = signed_checkpoint
    for length in (63, 65):
        modified = copy.deepcopy(envelope)
        modified["signature"] = base64.b64encode(b"\x01" * length).decode("ascii")

        with pytest.raises(ValueError, match="signature length"):
            verify_signed_checkpoint(modified, trusted_keys)


def test_exactly_64_byte_garbage_fails_verification_not_length(signed_checkpoint):
    """A 64-byte signature passes the length gate and fails cryptographic
    verification instead - proving the boundary is exact."""

    envelope, trusted_keys = signed_checkpoint
    modified = copy.deepcopy(envelope)
    modified["signature"] = base64.b64encode(b"\x00" * 64).decode("ascii")

    with pytest.raises(ValueError, match="verification failed"):
        verify_signed_checkpoint(modified, trusted_keys)