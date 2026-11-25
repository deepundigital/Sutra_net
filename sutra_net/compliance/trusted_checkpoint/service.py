"""High-level orchestration for the trusted checkpoint lifecycle.

Bridges the Ed25519 signer, the trusted key registry and the immutable
checkpoint store into one operator-facing facade:

    generate/register a signing key  ->  seal ledger state  ->  audit chain

The audit ledger itself is deliberately not imported here: callers obtain the
ledger's verified tail hash through the ledger's own integrity report and
pass it in. This module never writes to the ledger.

Underlying sub-module errors (storage, keyring, signer) are allowed to bubble
up unchanged so operators can tell exactly which layer refused; this module
raises TrustedCheckpointServiceError only for orchestration-level failures
(missing key file, key/registry mismatch, sequence already sealed).
"""

from pathlib import Path
from typing import Any

from ._fs_utils import TrustedFsError, atomic_write_bytes, require_owner_only_file
from .chain import blank_chain_report, verify_checkpoint_chain
from .checkpoint import checkpoint_digest, create_checkpoint
from .keyring import TrustedKeyRing, public_key_fingerprint
from .signer import (
    generate_keypair,
    load_private_key,
    serialize_private_key,
    serialize_public_key,
    sign_checkpoint,
)
from .storage import CheckpointStorage, CheckpointStorageError


class TrustedCheckpointServiceError(ValueError):
    """Raised for orchestration-level trusted checkpoint failures."""


class TrustedCheckpointService:
    """Facade sealing ledger states into signed, stored checkpoints."""

    def __init__(
        self,
        storage: CheckpointStorage,
        keyring: TrustedKeyRing,
        private_key_path: Path | str,
    ):
        if not isinstance(storage, CheckpointStorage):
            raise TrustedCheckpointServiceError(
                "storage must be a CheckpointStorage instance"
            )
        if not isinstance(keyring, TrustedKeyRing):
            raise TrustedCheckpointServiceError(
                "keyring must be a TrustedKeyRing instance"
            )

        self.storage = storage
        self.keyring = keyring
        self.private_key_path = Path(private_key_path)

    # ------------------------------------------------------------- key mgmt

    def generate_signing_key(self, passphrase: bytes | None = None) -> bytes:
        """Generate a keypair; write the private PEM to the key file path.

        Returns the public PEM (for out-of-band pinning by auditors). The
        private key file is written with owner-only permissions; pass a
        passphrase to encrypt it at rest.
        """

        private_key, public_key = generate_keypair()
        private_pem = serialize_private_key(private_key, passphrase=passphrase)

        try:
            self.private_key_path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_bytes(self.private_key_path, private_pem, mode=0o600)
        except (OSError, TrustedFsError) as exc:
            raise TrustedCheckpointServiceError(
                "Failed to persist signing key file"
            ) from exc

        return serialize_public_key(public_key)

    def register_signing_key(
        self, signing_key_id: str, passphrase: bytes | None = None
    ) -> None:
        """Register the signing key's public half under a stable key ID.

        The private key must match its registered public half before any
        seal is accepted; add_key refuses silent replacement, so rotating a
        key is always an explicit registry decision.
        """

        private_key = self._load_signing_key(passphrase)
        self.keyring.add_key(signing_key_id, private_key.public_key())

    # ----------------------------------------------------------------- seal

    def seal(
        self,
        *,
        ledger_id: str,
        sequence: int,
        last_entry_hash: str,
        signing_key_id: str,
        timestamp_utc: str | None = None,
        passphrase: bytes | None = None,
    ) -> dict[str, Any]:
        """Sign the given ledger tail state and persist it immutably.

        Returns the stored checkpoint metadata. Re-sealing the exact same
        checkpoint (same timestamp, hence same digest) is idempotent; sealing
        a sequence that already exists with different content is refused so
        the store can never become ambiguous.
        """

        private_key = self._load_signing_key(passphrase)

        # The signing key must be exactly the key the registry pins.
        if not self.keyring.has_key(signing_key_id):
            raise TrustedCheckpointServiceError(
                f"Signing key {signing_key_id!r} is not registered in the "
                "trusted key ring"
            )
        registered = self.keyring.get_key(signing_key_id)
        if (
            public_key_fingerprint(registered)
            != public_key_fingerprint(private_key.public_key())
        ):
            raise TrustedCheckpointServiceError(
                f"Signing key file does not match the registered public key "
                f"for {signing_key_id!r}"
            )

        checkpoint = create_checkpoint(
            ledger_id=ledger_id,
            sequence=sequence,
            last_entry_hash=last_entry_hash,
            signing_key_id=signing_key_id,
            timestamp_utc=timestamp_utc,
        )

        digest = checkpoint_digest(checkpoint)
        for entry in self.storage.list_checkpoints(ledger_id):
            if entry["sequence"] != sequence:
                continue
            if entry["digest"] == digest:
                return entry
            raise TrustedCheckpointServiceError(
                f"Sequence {sequence} for ledger {ledger_id!r} is already "
                "sealed with different content; refusing to create an "
                "ambiguous checkpoint"
            )

        envelope = sign_checkpoint(checkpoint, private_key)
        stored_path = self.storage.save(envelope, self.keyring.trusted_keys())

        return {
            "ledger_id": ledger_id,
            "sequence": sequence,
            "digest": digest,
            "fingerprint": digest[:16],
            "timestamp_utc": checkpoint["timestamp_utc"],
            "signing_key_id": signing_key_id,
            "filename": stored_path.name,
        }

    # ---------------------------------------------------------------- audit

    def stored_checkpoints(self, ledger_id: str | None = None) -> list[dict[str, Any]]:
        """List stored checkpoint metadata, sorted by ledger and sequence."""

        return self.storage.list_checkpoints(ledger_id)

    def chain_report(self, ledger_id: str | None = None) -> dict[str, Any]:
        """Verify every stored checkpoint as one ordered chain.

        All stored envelopes (optionally scoped to one ledger) are loaded and
        verified against the trusted key ring, in claimed append order. A
        stored file that cannot be loaded (corruption or tampering) does not
        abort the audit: it is recorded as a chain error and forces the
        overall result invalid.
        """

        trusted_keys = self.keyring.trusted_keys()

        try:
            entries = self.storage.list_checkpoints(ledger_id)
        except CheckpointStorageError as exc:
            # Build the fallback from the canonical schema so it can never
            # drift from what verify_checkpoint_chain produces.
            report = blank_chain_report()
            report["valid"] = False
            report["ledger_id"] = ledger_id
            report["errors"].append(f"Checkpoint store listing failed: {exc}")
            return report

        envelopes: list[dict[str, Any]] = []
        load_errors: list[str] = []
        for entry in entries:
            try:
                envelopes.append(
                    self.storage.load(entry["ledger_id"], entry["sequence"])
                )
            except CheckpointStorageError as exc:
                load_errors.append(
                    f"Stored checkpoint {entry['filename']} could not be "
                    f"loaded: {exc}"
                )

        report = verify_checkpoint_chain(envelopes, trusted_keys)
        if load_errors:
            report["valid"] = False
            report["errors"].extend(load_errors)
        return report

    # ------------------------------------------------------------ internals

    def _load_signing_key(self, passphrase: bytes | None):
        """Load the private signing key from its owner-only file."""

        if not self.private_key_path.exists():
            raise TrustedCheckpointServiceError(
                "Signing key file does not exist; generate it first"
            )

        try:
            require_owner_only_file(
                self.private_key_path, description="signing key"
            )
        except TrustedFsError as exc:
            raise TrustedCheckpointServiceError(str(exc)) from exc

        try:
            pem_data = self.private_key_path.read_bytes()
        except OSError as exc:
            raise TrustedCheckpointServiceError(
                "Signing key file is unreadable"
            ) from exc

        return load_private_key(pem_data, passphrase=passphrase)
