
"""Verification utilities for signed trusted audit checkpoints."""

import base64
import binascii
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .checkpoint import canonical_checkpoint_bytes, validate_checkpoint
from .signer import ENVELOPE_VERSION, SIGNATURE_ALGORITHM

_ENVELOPE_FIELDS = {
    "envelope_version",
    "signature_algorithm",
    "checkpoint",
    "signature",
}


def validate_envelope(envelope: Any) -> dict[str, Any]:
    """Validate an envelope's structure and return its checkpoint payload.

    This is the single source of truth for the signed envelope schema; the
    storage layer reuses it so both layers reject malformed envelopes in
    exactly the same way. Raises ValueError on any structural problem.
    """

    if not isinstance(envelope, dict):
        raise ValueError("Signed envelope must be an object")

    if set(envelope) != _ENVELOPE_FIELDS:
        raise ValueError("Invalid signed envelope schema")

    if (
        type(envelope["envelope_version"]) is not int
        or envelope["envelope_version"] != ENVELOPE_VERSION
    ):
        raise ValueError("Unsupported envelope version")

    if envelope["signature_algorithm"] != SIGNATURE_ALGORITHM:
        raise ValueError("Unsupported signature algorithm")

    checkpoint = envelope["checkpoint"]
    validate_checkpoint(checkpoint)

    if not isinstance(envelope["signature"], str):
        raise ValueError("Signature must be a base64 string")

    return checkpoint


def verify_signed_checkpoint(
    envelope: dict[str, Any],
    trusted_public_keys: dict[str, Ed25519PublicKey],
) -> dict[str, Any]:
    """Verify a signed checkpoint and return its checkpoint payload.

    trusted_public_keys maps signing_key_id to a trusted Ed25519 public key.
    Raises ValueError if the envelope, key ID, or signature is invalid.
    """

    checkpoint = validate_envelope(envelope)

    key_id = checkpoint["signing_key_id"]
    public_key = trusted_public_keys.get(key_id)

    if public_key is None:
        raise ValueError(f"Unknown signing key ID: {key_id}")

    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError(
            "Trusted key registry contains a non-Ed25519 key"
        )

    signature_text = envelope["signature"]

    try:
        signature = base64.b64decode(
            signature_text,
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Malformed base64 signature") from exc

    # Ed25519 signatures must always be exactly 64 bytes.
    if len(signature) != 64:
        raise ValueError("Invalid Ed25519 signature length")

    try:
        public_key.verify(
            signature,
            canonical_checkpoint_bytes(checkpoint),
        )
    except InvalidSignature as exc:
        raise ValueError(
            "Checkpoint signature verification failed"
        ) from exc

    return checkpoint
