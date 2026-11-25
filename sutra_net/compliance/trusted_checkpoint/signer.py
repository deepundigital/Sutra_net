"""Ed25519 signing utilities for trusted audit checkpoints."""

import copy
import base64
from typing import Any

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .checkpoint import canonical_checkpoint_bytes, validate_checkpoint

ENVELOPE_VERSION = 1
SIGNATURE_ALGORITHM = "Ed25519"

_PASSPHRASE_TYPES = (bytes, bytearray)


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate an Ed25519 private/public key pair."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def _validate_passphrase(passphrase: bytes | bytearray | None) -> None:
    if passphrase is not None and not isinstance(passphrase, _PASSPHRASE_TYPES):
        raise ValueError(
            "Passphrase must be bytes (not str) or None to avoid encoding ambiguity"
        )
    if isinstance(passphrase, _PASSPHRASE_TYPES) and len(passphrase) == 0:
        raise ValueError("Passphrase must not be empty")


def serialize_private_key(
    private_key: Ed25519PrivateKey,
    passphrase: bytes | bytearray | None = None,
) -> bytes:
    """Serialize a private key as PKCS8 PEM.

    Without a passphrase the PEM is unencrypted: protect such output carefully
    and never commit it to source control. With a passphrase the key is
    encrypted with the best available PBES2 scheme (PBKDF2 + AES).
    """
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("Expected an Ed25519 private key")
    _validate_passphrase(passphrase)

    if passphrase is None:
        encryption_algorithm = serialization.NoEncryption()
    else:
        encryption_algorithm = serialization.BestAvailableEncryption(
            bytes(passphrase)
        )

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    )


def serialize_public_key(public_key: Ed25519PublicKey) -> bytes:
    """Serialize a public key as SubjectPublicKeyInfo PEM."""
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("Expected an Ed25519 public key")
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key(
    pem_data: bytes | bytearray,
    passphrase: bytes | bytearray | None = None,
) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from PKCS8 PEM.

    All malformed-input failures are normalized to ValueError with a stable
    message so callers never depend on backend-specific exception types.
    """
    if not isinstance(pem_data, _PASSPHRASE_TYPES):
        raise ValueError("Private key PEM data must be bytes")
    _validate_passphrase(passphrase)

    try:
        key = serialization.load_pem_private_key(
            bytes(pem_data),
            password=bytes(passphrase) if passphrase is not None else None,
        )
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise ValueError("Invalid or unsupported private key PEM data") from exc

    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Expected an Ed25519 private key")
    return key


def load_public_key(pem_data: bytes | bytearray) -> Ed25519PublicKey:
    """Load an Ed25519 public key from SubjectPublicKeyInfo PEM.

    All malformed-input failures are normalized to ValueError.
    """
    if not isinstance(pem_data, _PASSPHRASE_TYPES):
        raise ValueError("Public key PEM data must be bytes")

    try:
        key = serialization.load_pem_public_key(bytes(pem_data))
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise ValueError("Invalid or unsupported public key PEM data") from exc

    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Expected an Ed25519 public key")
    return key


def sign_checkpoint(
    checkpoint: dict[str, Any],
    private_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    """Sign canonical checkpoint bytes and return a signed envelope."""
    validate_checkpoint(checkpoint)

    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("Expected an Ed25519 private key")

    signature = private_key.sign(canonical_checkpoint_bytes(checkpoint))

    return {
        "envelope_version": ENVELOPE_VERSION,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "checkpoint": copy.deepcopy(checkpoint),
        "signature": base64.b64encode(signature).decode("ascii"),
    }
