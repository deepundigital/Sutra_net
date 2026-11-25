"""Canonical checkpoint creation and validation for trusted audit infrastructure."""

import datetime
import hashlib
import json
import re
from typing import Any


CHECKPOINT_VERSION = 1
SIGNATURE_ALGORITHM = "Ed25519"
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")


def create_checkpoint(
    *,
    ledger_id: str,
    sequence: int,
    last_entry_hash: str,
    signing_key_id: str,
    timestamp_utc: str | None = None,
) -> dict[str, Any]:
    """Create an unsigned checkpoint payload."""

    if not isinstance(ledger_id, str) or not ledger_id.strip():
        raise ValueError("ledger_id must be a non-empty string")

    if len(ledger_id) > 128:
        raise ValueError("ledger_id must not exceed 128 characters")

    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
        raise ValueError("sequence must be a non-negative integer")

    if not isinstance(last_entry_hash, str) or not SHA256_PATTERN.fullmatch(
        last_entry_hash
    ):
        raise ValueError("last_entry_hash must be a lowercase SHA-256 hex digest")

    if not isinstance(signing_key_id, str) or not signing_key_id.strip():
        raise ValueError("signing_key_id must be a non-empty string")

    if len(signing_key_id) > 128:
        raise ValueError("signing_key_id must not exceed 128 characters")

    if timestamp_utc is None:
        timestamp_utc = datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat()

    if not isinstance(timestamp_utc, str):
        raise ValueError("timestamp_utc must be an ISO-8601 string")

    try:
        parsed_timestamp = datetime.datetime.fromisoformat(
            timestamp_utc.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise ValueError("timestamp_utc must be a valid ISO-8601 timestamp") from exc

    if (
        parsed_timestamp.tzinfo is None
        or parsed_timestamp.utcoffset() != datetime.timedelta(0)
    ):
        raise ValueError("timestamp_utc must include a UTC timezone")

    checkpoint = {
        "checkpoint_version": CHECKPOINT_VERSION,
        "ledger_id": ledger_id,
        "sequence": sequence,
        "last_entry_hash": last_entry_hash,
        "timestamp_utc": timestamp_utc,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "signing_key_id": signing_key_id,
    }

    validate_checkpoint(checkpoint)
    return checkpoint


def validate_checkpoint(checkpoint: dict[str, Any]) -> None:
    """Validate the checkpoint schema and field types."""

    if not isinstance(checkpoint, dict):
        raise ValueError("Checkpoint must be a JSON object")

    expected_fields = {
        "checkpoint_version",
        "ledger_id",
        "sequence",
        "last_entry_hash",
        "timestamp_utc",
        "signature_algorithm",
        "signing_key_id",
    }

    if set(checkpoint) != expected_fields:
        raise ValueError("Checkpoint fields do not match the required schema")

    if (
        isinstance(checkpoint["checkpoint_version"], bool)
        or checkpoint["checkpoint_version"] != CHECKPOINT_VERSION
    ):
        raise ValueError("Unsupported checkpoint version")

    if not isinstance(checkpoint["ledger_id"], str) or not (
        1 <= len(checkpoint["ledger_id"].strip()) <= 128
    ):
        raise ValueError("Invalid ledger_id")

    if (
        isinstance(checkpoint["sequence"], bool)
        or not isinstance(checkpoint["sequence"], int)
        or checkpoint["sequence"] < 0
    ):
        raise ValueError("Invalid checkpoint sequence")

    if not isinstance(checkpoint["last_entry_hash"], str) or not (
        SHA256_PATTERN.fullmatch(checkpoint["last_entry_hash"])
    ):
        raise ValueError("Invalid last_entry_hash")

    if checkpoint["signature_algorithm"] != SIGNATURE_ALGORITHM:
        raise ValueError("Unsupported signature algorithm")

    if not isinstance(checkpoint["signing_key_id"], str) or not (
        1 <= len(checkpoint["signing_key_id"].strip()) <= 128
    ):
        raise ValueError("Invalid signing_key_id")

    timestamp = checkpoint["timestamp_utc"]

    if not isinstance(timestamp, str):
        raise ValueError("Invalid checkpoint timestamp")

    try:
        parsed = datetime.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Invalid checkpoint timestamp") from exc

    if parsed.tzinfo is None or parsed.utcoffset() != datetime.timedelta(0):
        raise ValueError("Checkpoint timestamp must use UTC")


def canonical_checkpoint_bytes(checkpoint: dict[str, Any]) -> bytes:
    """Return deterministic bytes used for digital signatures."""

    validate_checkpoint(checkpoint)

    return json.dumps(
        checkpoint,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def checkpoint_digest(checkpoint: dict[str, Any]) -> str:
    """Return the SHA-256 digest of the canonical checkpoint payload."""

    return hashlib.sha256(canonical_checkpoint_bytes(checkpoint)).hexdigest()


def serialize_checkpoint(checkpoint: dict[str, Any]) -> bytes:
    """Serialize a validated checkpoint as canonical JSON."""

    return canonical_checkpoint_bytes(checkpoint) + b"\n"


def deserialize_checkpoint(raw: bytes) -> dict[str, Any]:
    """Parse and validate a serialized checkpoint."""

    try:
        checkpoint = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid checkpoint JSON") from exc

    validate_checkpoint(checkpoint)
    return checkpoint
