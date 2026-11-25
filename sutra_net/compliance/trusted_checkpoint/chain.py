"""Continuity verification for sequences of signed trusted checkpoints.

This module operates purely on checkpoint envelopes in memory. It depends on
neither the audit ledger nor the storage layer, so the same verification can
be applied to a live store, a backup export, or evidence copied from another
site.

An ordered list of envelopes is treated as the claimed append order. The
verification answers four questions:

1. Is every envelope a cryptographically valid, signed checkpoint?
2. Do all checkpoints belong to a single ledger?
3. Does the sequence numbering move strictly forward (a repeated or
   decreasing sequence number is rollback or fork evidence)?
4. Do sealing timestamps move monotonically forward (allowing equal
   timestamps for same-second seals)?

Sequence gaps are reported as informational findings, because sealing
intervals are an operational policy choice, not an integrity violation.

Report semantics: ``first_sequence``/``last_sequence`` refer to the first
and last checkpoints in the *claimed append order*, which on a valid chain
is also the numeric order.
"""

import datetime
from typing import Any

from .checkpoint import checkpoint_digest, validate_checkpoint
from .verifier import verify_signed_checkpoint


class CheckpointChainError(ValueError):
    """Raised when chain verification itself is given unusable input."""


def _parse_utc_timestamp(value: Any) -> datetime.datetime:
    """Parse an ISO-8601 UTC timestamp from a validated checkpoint."""

    if not isinstance(value, str):
        raise CheckpointChainError("Checkpoint timestamp must be a string")

    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CheckpointChainError("Checkpoint timestamp is not valid ISO-8601") from exc

    if parsed.tzinfo is None or parsed.utcoffset() != datetime.timedelta(0):
        raise CheckpointChainError("Checkpoint timestamp must use UTC")

    return parsed


def blank_chain_report() -> dict[str, Any]:
    """Return an empty report with the canonical chain-report schema.

    Single source of truth for the report shape: other modules (such as the
    service facade) build their fallback reports from this so they can never
    drift from what verify_checkpoint_chain produces.
    """

    return {
        "valid": True,
        "count": 0,
        "ledger_id": None,
        "first_sequence": None,
        "last_sequence": None,
        "last_digest": None,
        "errors": [],
        "duplicates": [],
        "sequence_regressions": [],
        "timestamp_regressions": [],
        "gaps": [],
    }


def verify_checkpoint_chain(
    envelopes: list[dict[str, Any]],
    trusted_public_keys: dict[str, Any],
) -> dict[str, Any]:
    """Verify a claimed-append-order chain of signed checkpoint envelopes.

    Returns a report dict; ``valid`` is False when any envelope fails
    verification, ledger identity diverges, sequence numbering repeats or
    regresses, or timestamps regress. Gaps are reported but do not by
    themselves invalidate the chain.
    """

    if not isinstance(envelopes, list):
        raise CheckpointChainError("envelopes must be a list of signed envelopes")

    report = blank_chain_report()
    previous_sequence: int | None = None
    previous_timestamp: datetime.datetime | None = None
    seen_sequences: set[int] = set()
    sequences_in_order: list[int] = []

    for position, envelope in enumerate(envelopes):
        if not isinstance(envelope, dict):
            report["errors"].append(
                f"Envelope at position {position} is not an object"
            )
            report["valid"] = False
            continue

        try:
            checkpoint = verify_signed_checkpoint(envelope, trusted_public_keys)
        except ValueError as exc:
            report["errors"].append(
                f"Envelope at position {position} failed verification: {exc}"
            )
            report["valid"] = False
            continue

        try:
            validate_checkpoint(checkpoint)
        except ValueError as exc:
            report["errors"].append(
                f"Envelope at position {position} has an invalid checkpoint: {exc}"
            )
            report["valid"] = False
            continue

        sequence = checkpoint["sequence"]
        ledger_id = checkpoint["ledger_id"]

        if report["ledger_id"] is None:
            report["ledger_id"] = ledger_id
        elif report["ledger_id"] != ledger_id:
            report["errors"].append(
                f"Envelope at position {position} belongs to ledger "
                f"{ledger_id!r}, expected {report['ledger_id']!r}"
            )
            report["valid"] = False

        if sequence in seen_sequences:
            report["duplicates"].append(sequence)
            report["errors"].append(
                f"Envelope at position {position} repeats sequence {sequence}; "
                "a repeated sequence is fork or replay evidence"
            )
            report["valid"] = False
        seen_sequences.add(sequence)
        sequences_in_order.append(sequence)

        if previous_sequence is not None and sequence < previous_sequence:
            report["sequence_regressions"].append([previous_sequence, sequence])
            report["errors"].append(
                f"Envelope at position {position} regresses from sequence "
                f"{previous_sequence} to {sequence}; this is rollback evidence"
            )
            report["valid"] = False

        try:
            timestamp = _parse_utc_timestamp(checkpoint["timestamp_utc"])
        except CheckpointChainError as exc:
            report["errors"].append(
                f"Envelope at position {position}: {exc}"
            )
            report["valid"] = False
            timestamp = None

        if (
            timestamp is not None
            and previous_timestamp is not None
            and timestamp < previous_timestamp
        ):
            report["timestamp_regressions"].append(
                [previous_sequence, sequence]
            )
            report["errors"].append(
                f"Envelope at position {position} seals at "
                f"{checkpoint['timestamp_utc']}, before the previous "
                "checkpoint's timestamp"
            )
            report["valid"] = False

        if timestamp is not None:
            previous_timestamp = timestamp
        previous_sequence = sequence
        report["count"] += 1
        report["last_digest"] = checkpoint_digest(checkpoint)

    report["first_sequence"] = sequences_in_order[0] if sequences_in_order else None
    report["last_sequence"] = sequences_in_order[-1] if sequences_in_order else None

    unique_sorted = sorted(set(sequences_in_order))
    for before, after in zip(unique_sorted, unique_sorted[1:]):
        if after != before + 1:
            report["gaps"].append([before, after])

    return report


def analyze_sequence_gaps(sequences: list[int]) -> list[list[int]]:
    """Return [from, to] gaps in a list of checkpoint sequence numbers."""

    if not isinstance(sequences, list) or any(
        isinstance(s, bool) or not isinstance(s, int) for s in sequences
    ):
        raise CheckpointChainError("sequences must be a list of integers")

    unique_sorted = sorted(set(sequences))
    return [
        [before, after]
        for before, after in zip(unique_sorted, unique_sorted[1:])
        if after != before + 1
    ]
