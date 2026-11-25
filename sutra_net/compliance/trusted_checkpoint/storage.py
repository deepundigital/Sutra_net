"""Atomic, owner-only storage for signed trusted audit checkpoints.

This layer is deliberately independent of the JSONL audit ledger. It only
persists, retrieves and verifies signed checkpoint envelopes; it never reads
or writes ledger data itself. Keeping the two separated is what later allows
recovery and rollback detection to reason about storage in isolation.

Design guarantees:

- Atomic writes: content is written to a temporary file in the target
  directory, flushed and fsynced, then moved into place with an atomic rename.
- Immutable by convention: a stored checkpoint is never silently overwritten.
  Saving an identical checkpoint again is an idempotent no-op; saving
  different content under the same checkpoint identity is an error.
- Strict filenames: only checkpoints whose ledger identifier is filename-safe
  can be stored, and stored filenames carry the sequence number plus a
  fingerprint of the checkpoint payload.
- Owner-only permissions: the store directory and every stored file must be
  readable and writable by the owner alone. Loose or symlinked entries are
  rejected instead of silently accepted.
"""

import json
import os
import re
from pathlib import Path
from typing import Any

from ._fs_utils import (
    TrustedFsError,
    atomic_write_bytes,
    require_owner_only_directory,
    require_owner_only_file,
)
from .checkpoint import checkpoint_digest
from .verifier import validate_envelope, verify_signed_checkpoint

CHECKPOINT_FILE_SUFFIX = ".checkpoint.json"

# Stored filename layout: <ledger_id>-<sequence>-<fingerprint>.checkpoint.json
# The suffix is duplicated as an escaped literal so the pattern stays a
# compile-time constant string.
FILENAME_PATTERN = re.compile(
    r"^(?P<ledger_id>[A-Za-z0-9][A-Za-z0-9._-]{0,127})"
    r"-(?P<sequence>[0-9]{1,16})"
    r"-(?P<fingerprint>[0-9a-f]{16})"
    r"\.checkpoint\.json$"
)

# Identifiers must be usable as single path components without escaping.
SAFE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

FINGERPRINT_LENGTH = 16
SEQUENCE_UPPER_BOUND = 10**16

STORE_DIR_MODE = 0o700
FILE_MODE = 0o600


class CheckpointStorageError(ValueError):
    """Raised when a checkpoint cannot be safely stored, loaded or listed."""


def is_storable_ledger_id(ledger_id: Any) -> bool:
    """Return True when ledger_id is safe to use as a stored filename."""

    return isinstance(ledger_id, str) and bool(SAFE_ID_PATTERN.fullmatch(ledger_id))


def _validate_storable_identity(ledger_id: str, sequence: int) -> None:
    """Reject identifiers that are unsafe to turn into file names."""

    if not is_storable_ledger_id(ledger_id):
        raise CheckpointStorageError(
            "ledger_id must match [A-Za-z0-9][A-Za-z0-9._-]{0,127} to be storable"
        )

    if isinstance(sequence, bool) or not isinstance(sequence, int):
        raise CheckpointStorageError("sequence must be an integer")

    if not 0 <= sequence < SEQUENCE_UPPER_BOUND:
        raise CheckpointStorageError(
            f"sequence must be within [0, {SEQUENCE_UPPER_BOUND}) to be storable"
        )


def _validate_envelope_structure(envelope: Any) -> dict[str, Any]:
    """Delegate structural validation to the shared envelope contract.

    Returns the validated checkpoint payload so callers never re-parse the
    envelope by hand.
    """

    try:
        return validate_envelope(envelope)
    except ValueError as exc:
        raise CheckpointStorageError(str(exc)) from exc


def _canonical_envelope_bytes(envelope: dict[str, Any]) -> bytes:
    """Deterministic on-disk representation of a signed envelope."""

    payload = json.dumps(
        envelope,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return payload.encode("utf-8") + b"\n"


class CheckpointStorage:
    """Filesystem store for signed trusted audit checkpoints."""

    def __init__(self, base_dir: Path | str):
        self.base_dir = Path(base_dir)

        # mode= is filtered by umask, so 0o700 survives common umasks, but an
        # explicitly permissive pre-existing directory must never be widened.
        self.base_dir.mkdir(mode=STORE_DIR_MODE, parents=True, exist_ok=True)
        self._require_private_directory(self.base_dir)

    # ------------------------------------------------------------------ save

    def save(
        self,
        envelope: dict[str, Any],
        trusted_public_keys: dict[str, Any],
    ) -> Path:
        """Verify and atomically persist a signed checkpoint envelope.

        Returns the stored file path. Saving byte-identical content again is
        an idempotent no-op; any conflicting content for the same checkpoint
        identity is rejected without touching the existing file.
        """

        checkpoint = verify_signed_checkpoint(envelope, trusted_public_keys)

        ledger_id = checkpoint["ledger_id"]
        sequence = checkpoint["sequence"]
        _validate_storable_identity(ledger_id, sequence)

        fingerprint = checkpoint_digest(checkpoint)[:FINGERPRINT_LENGTH]
        target = self.base_dir / (
            f"{ledger_id}-{sequence:010d}-{fingerprint}{CHECKPOINT_FILE_SUFFIX}"
        )
        payload = _canonical_envelope_bytes(envelope)

        if os.path.lexists(target):
            self._require_private_file(target)
            existing = target.read_bytes()
            if existing == payload:
                return target
            raise CheckpointStorageError(
                "Refusing to overwrite existing checkpoint with different content: "
                f"{target.name}"
            )

        self._atomic_write(target, payload)
        return target

    # ------------------------------------------------------------------ load

    def load(self, ledger_id: str, sequence: int) -> dict[str, Any]:
        """Load a stored envelope and re-validate it against its filename."""

        _validate_storable_identity(ledger_id, sequence)
        candidates = self._find_files(ledger_id, sequence)

        if not candidates:
            raise CheckpointStorageError(
                f"No stored checkpoint for ledger_id={ledger_id!r}, "
                f"sequence={sequence}"
            )

        if len(candidates) > 1:
            raise CheckpointStorageError(
                f"Ambiguous checkpoint state for ledger_id={ledger_id!r}, "
                f"sequence={sequence}: {len(candidates)} files exist"
            )

        path = candidates[0]
        self._require_private_file(path)

        try:
            raw = path.read_bytes()
            envelope = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CheckpointStorageError(
                f"Stored checkpoint is unreadable: {path.name}"
            ) from exc

        checkpoint = _validate_envelope_structure(envelope)

        # The fingerprint in the filename must describe the stored payload.
        expected_fp = checkpoint_digest(checkpoint)[:FINGERPRINT_LENGTH]
        stored_fp = FILENAME_PATTERN.fullmatch(path.name).group("fingerprint")
        if stored_fp != expected_fp:
            raise CheckpointStorageError(
                f"Stored checkpoint content does not match its filename "
                f"fingerprint: {path.name}"
            )

        return envelope

    def verify_stored(
        self,
        ledger_id: str,
        sequence: int,
        trusted_public_keys: dict[str, Any],
    ) -> dict[str, Any]:
        """Load a stored checkpoint and verify its Ed25519 signature."""

        envelope = self.load(ledger_id, sequence)
        return verify_signed_checkpoint(envelope, trusted_public_keys)

    # ------------------------------------------------------------------ list

    def list_checkpoints(
        self, ledger_id: str | None = None
    ) -> list[dict[str, Any]]:
        """List stored checkpoints as metadata, sorted by ledger and sequence.

        A corrupt or misnamed entry raises instead of being skipped: in an
        immutable evidence store, silent skipping would hide tampering.
        """

        if ledger_id is not None:
            _validate_storable_identity(ledger_id, 0)

        entries: list[dict[str, Any]] = []
        try:
            children = sorted(os.listdir(self.base_dir))
        except OSError as exc:
            raise CheckpointStorageError(
                "Checkpoint store directory is not readable"
            ) from exc

        for name in children:
            match = FILENAME_PATTERN.fullmatch(name)
            if match is None:
                continue

            if ledger_id is not None and match.group("ledger_id") != ledger_id:
                continue

            path = self.base_dir / name
            self._require_private_file(path)

            try:
                envelope = json.loads(path.read_bytes().decode("utf-8"))
                checkpoint = _validate_envelope_structure(envelope)
            except (CheckpointStorageError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise CheckpointStorageError(
                    f"Stored checkpoint is corrupt: {name}"
                ) from exc

            entries.append(
                {
                    "ledger_id": checkpoint["ledger_id"],
                    "sequence": checkpoint["sequence"],
                    "fingerprint": match.group("fingerprint"),
                    "digest": checkpoint_digest(checkpoint),
                    "timestamp_utc": checkpoint["timestamp_utc"],
                    "signing_key_id": checkpoint["signing_key_id"],
                    "filename": name,
                }
            )

        entries.sort(key=lambda item: (item["ledger_id"], item["sequence"]))
        return entries

    # ------------------------------------------------------------- internals

    def _find_files(self, ledger_id: str, sequence: int) -> list[Path]:
        prefix = f"{ledger_id}-{sequence:010d}-"
        candidates: list[Path] = []

        try:
            children = sorted(os.listdir(self.base_dir))
        except OSError as exc:
            raise CheckpointStorageError(
                "Checkpoint store directory is not readable"
            ) from exc

        for name in children:
            if not name.startswith(prefix):
                continue
            if FILENAME_PATTERN.fullmatch(name) is None:
                continue
            candidates.append(self.base_dir / name)

        return candidates

    def _atomic_write(self, target: Path, payload: bytes) -> None:
        """Write payload to target via temp file + fsync + atomic rename."""

        try:
            atomic_write_bytes(
                target,
                payload,
                mode=FILE_MODE,
                temp_prefix=".tmp-checkpoint-",
            )
        except TrustedFsError as exc:
            raise CheckpointStorageError(str(exc)) from exc

    @staticmethod
    def _require_private_directory(directory: Path) -> None:
        """Reject symlinked or group/world-accessible store directories."""

        try:
            require_owner_only_directory(
                directory, description="checkpoint store"
            )
        except TrustedFsError as exc:
            raise CheckpointStorageError(str(exc)) from exc

    @staticmethod
    def _require_private_file(path: Path) -> None:
        """Reject symlinked or group/world-accessible stored files."""

        try:
            require_owner_only_file(path, description="stored checkpoint")
        except TrustedFsError as exc:
            raise CheckpointStorageError(str(exc)) from exc
