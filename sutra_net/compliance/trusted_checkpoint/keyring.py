"""Trusted signing-key registry for checkpoint verification.

Maps stable key identifiers to pinned Ed25519 public keys. The registry is a
single owner-only JSON file; each entry records a SHA-256 fingerprint of the
raw public key so that any tampering with the stored PEM is detected when the
registry is read.

The registry never stores private key material and never replaces a key
silently: adding a different key under an existing identifier is an explicit
error, which keeps the trust anchor as immutable as the checkpoints it
verifies.

Concurrency note: the registry is read fresh on every operation and written
atomically, which makes it safe for multi-reader deployments. Writes assume
a single operator at a time — two simultaneous ``add_key`` calls can lose
one update (last writer wins), so key registration is an explicit,
one-at-a-time ceremony by design.
"""

import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._fs_utils import (
    TrustedFsError,
    atomic_write_bytes,
    require_owner_only_file,
)
from .storage import SAFE_ID_PATTERN

REGISTRY_VERSION = 1
KEYRING_FILE_MODE = 0o600

_REGISTRY_FIELDS = {"registry_version", "keys"}
_ENTRY_FIELDS = {"public_key_pem", "fingerprint"}


class TrustedKeyRingError(ValueError):
    """Raised when the trusted key registry cannot be used safely."""


def public_key_fingerprint(public_key: Ed25519PublicKey) -> str:
    """Return the SHA-256 hex fingerprint of the raw Ed25519 public key."""

    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def _public_key_pem(public_key: Ed25519PublicKey) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _load_public_key_from_entry(key_id: str, entry: Any) -> Ed25519PublicKey:
    """Parse and fingerprint-check a single registry entry."""

    if not isinstance(entry, dict) or set(entry) != _ENTRY_FIELDS:
        raise TrustedKeyRingError(
            f"Malformed registry entry for key_id={key_id!r}"
        )

    pem_text = entry["public_key_pem"]
    if not isinstance(pem_text, str):
        raise TrustedKeyRingError(
            f"Registry entry for key_id={key_id!r} has invalid PEM data"
        )

    try:
        key = serialization.load_pem_public_key(pem_text.encode("utf-8"))
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise TrustedKeyRingError(
            f"Stored public key for key_id={key_id!r} is not valid PEM"
        ) from exc

    if not isinstance(key, Ed25519PublicKey):
        raise TrustedKeyRingError(
            f"Stored key for key_id={key_id!r} is not an Ed25519 public key"
        )

    if public_key_fingerprint(key) != entry["fingerprint"]:
        raise TrustedKeyRingError(
            f"Fingerprint mismatch for key_id={key_id!r}; "
            "the registry entry has been tampered with"
        )

    return key


class TrustedKeyRing:
    """Owner-only file-backed registry of trusted Ed25519 public keys."""

    def __init__(self, registry_path: Path | str):
        self.registry_path = Path(registry_path)

    # ------------------------------------------------------------------ read

    def _read_registry(self) -> dict[str, tuple[Ed25519PublicKey, str]]:
        """Parse the registry file into {key_id: (public_key, fingerprint)}."""

        if not self.registry_path.exists():
            return {}

        try:
            require_owner_only_file(
                self.registry_path, description="trusted key registry"
            )
        except TrustedFsError as exc:
            raise TrustedKeyRingError(str(exc)) from exc

        try:
            data = json.loads(self.registry_path.read_bytes().decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TrustedKeyRingError(
                "Trusted key registry is unreadable or corrupt"
            ) from exc

        if not isinstance(data, dict) or set(data) != _REGISTRY_FIELDS:
            raise TrustedKeyRingError("Invalid trusted key registry schema")

        if (
            isinstance(data["registry_version"], bool)
            or data["registry_version"] != REGISTRY_VERSION
        ):
            raise TrustedKeyRingError("Unsupported trusted key registry version")

        keys = data["keys"]
        if not isinstance(keys, dict):
            raise TrustedKeyRingError("Invalid trusted key registry keys section")

        loaded: dict[str, tuple[Ed25519PublicKey, str]] = {}
        for key_id, entry in keys.items():
            if not isinstance(key_id, str) or not SAFE_ID_PATTERN.fullmatch(key_id):
                raise TrustedKeyRingError(
                    f"Registry contains an unsafe key identifier: {key_id!r}"
                )
            public_key = _load_public_key_from_entry(key_id, entry)
            loaded[key_id] = (public_key, entry["fingerprint"])

        return loaded

    def trusted_keys(self) -> dict[str, Ed25519PublicKey]:
        """Return all trusted keys, ready for checkpoint verification."""

        return {
            key_id: public_key
            for key_id, (public_key, _) in self._read_registry().items()
        }

    def get_key(self, key_id: str) -> Ed25519PublicKey:
        """Return one trusted key, raising when the identifier is unknown."""

        registry = self._read_registry()
        if key_id not in registry:
            raise TrustedKeyRingError(f"Unknown signing key ID: {key_id!r}")
        return registry[key_id][0]

    def has_key(self, key_id: str) -> bool:
        return key_id in self._read_registry()

    def key_ids(self) -> list[str]:
        return sorted(self._read_registry())

    # ----------------------------------------------------------------- write

    def add_key(self, key_id: str, public_key: Ed25519PublicKey) -> None:
        """Register a trusted public key under a stable identifier.

        Adding the same key again is an idempotent no-op; adding a different
        key under an existing identifier is refused (no silent replacement).
        """

        if not isinstance(key_id, str) or not SAFE_ID_PATTERN.fullmatch(key_id):
            raise TrustedKeyRingError(
                "key_id must match [A-Za-z0-9][A-Za-z0-9._-]{0,127}"
            )

        if not isinstance(public_key, Ed25519PublicKey):
            raise TrustedKeyRingError("Expected an Ed25519 public key")

        registry = self._read_registry()

        if key_id in registry:
            _, existing_fingerprint = registry[key_id]
            if public_key_fingerprint(public_key) == existing_fingerprint:
                return
            raise TrustedKeyRingError(
                f"Refusing to replace trusted key {key_id!r}; "
                "key rotation requires an explicit registry rebuild"
            )

        registry[key_id] = (public_key, public_key_fingerprint(public_key))
        self._write_registry(self._serializable_registry(registry))

    # ------------------------------------------------------------- internals

    def _serializable_registry(
        self, registry: dict[str, tuple[Ed25519PublicKey, str]]
    ) -> dict[str, Any]:
        """Serialize parsed entries back to the on-disk schema."""

        keys: dict[str, Any] = {}
        for key_id, (public_key, fingerprint) in registry.items():
            keys[key_id] = {
                "public_key_pem": _public_key_pem(public_key),
                "fingerprint": fingerprint,
            }

        return {"registry_version": REGISTRY_VERSION, "keys": keys}

    def _write_registry(self, payload: dict[str, Any]) -> None:
        encoded = (
            json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
        ).encode("utf-8")

        try:
            self.registry_path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_bytes(self.registry_path, encoded, mode=KEYRING_FILE_MODE)
        except (OSError, TrustedFsError) as exc:
            raise TrustedKeyRingError(
                "Failed to persist trusted key registry"
            ) from exc
