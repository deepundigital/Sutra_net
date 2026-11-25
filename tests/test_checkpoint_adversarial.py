"""Adversarial and edge-case battery for the trusted checkpoint modules.

These tests actively try to break the invariants established in earlier
cycles: identity escapes, filename spoofing, symlink and permission attacks,
filesystem races, and boundary values.
"""

import json
import os
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from sutra_net.compliance.trusted_checkpoint import (
    CheckpointStorage,
    CheckpointStorageError,
    TrustedKeyRing,
    TrustedKeyRingError,
    create_checkpoint,
    generate_keypair,
    sign_checkpoint,
)


@pytest.fixture
def keypair():
    return generate_keypair()


@pytest.fixture
def trusted(keypair):
    return {"adv-key-01": keypair[1]}


@pytest.fixture
def storage(tmp_path):
    return CheckpointStorage(tmp_path / "checkpoints")


def make_checkpoint(ledger_id="case-adv-ledger", sequence=1, signing_key_id="adv-key-01"):
    return create_checkpoint(
        ledger_id=ledger_id,
        sequence=sequence,
        last_entry_hash="a" * 64,
        signing_key_id=signing_key_id,
        timestamp_utc="2026-11-05T06:00:00Z",
    )


# ------------------------------------------------------------ identity edges


def test_unicode_ledger_id_is_rejected_by_storage(storage, keypair, trusted):
    envelope = sign_checkpoint(make_checkpoint(ledger_id="café-ünicode"), keypair[0])

    with pytest.raises(CheckpointStorageError, match="ledger_id"):
        storage.save(envelope, trusted)


def test_newline_in_ledger_id_is_rejected(storage, keypair, trusted):
    envelope = sign_checkpoint(make_checkpoint(ledger_id="line1\nline2"), keypair[0])

    with pytest.raises(CheckpointStorageError, match="ledger_id"):
        storage.save(envelope, trusted)


def test_maximum_length_ledger_id_is_accepted(storage, keypair, trusted):
    long_id = "l" * 128
    envelope = sign_checkpoint(make_checkpoint(ledger_id=long_id), keypair[0])

    path = storage.save(envelope, trusted)

    assert path.name.startswith(long_id + "-")


def test_sequence_boundary_values(storage, keypair, trusted):
    private_key, _ = keypair

    at_bound = sign_checkpoint(make_checkpoint(sequence=10**16 - 1), private_key)
    path = storage.save(at_bound, trusted)
    assert storage.load("case-adv-ledger", 10**16 - 1)["checkpoint"]["sequence"] == 10**16 - 1
    path.unlink()

    over_bound = sign_checkpoint(make_checkpoint(sequence=10**16), private_key)
    with pytest.raises(CheckpointStorageError, match="sequence"):
        storage.save(over_bound, trusted)


# ----------------------------------------------------------- spoofing attacks


def test_cross_ledger_filename_spoofing_detected(storage, keypair, trusted):
    private_key, _ = keypair

    victim = sign_checkpoint(make_checkpoint(ledger_id="case-adv-ledger"), private_key)
    victim_path = storage.save(victim, trusted)

    # Content belongs to ledger A; filename claims ledger B.
    foreign = sign_checkpoint(make_checkpoint(ledger_id="case-other"), private_key)
    spoofed_name = victim_path.name.replace("case-adv-ledger", "case-other")
    spoofed_path = storage.base_dir / spoofed_name
    spoofed_path.write_bytes(
        json.dumps(foreign, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )
    # Owner-only perms so the fingerprint guard is what catches the spoof
    # (a loose file is caught earlier by the permission guard).
    os.chmod(spoofed_path, 0o600)
    victim_path.unlink()

    with pytest.raises(CheckpointStorageError, match="fingerprint"):
        storage.load("case-other", 1)


# ------------------------------------------------- filesystem-level attacks


def test_symlinked_store_directory_rejected(tmp_path, keypair, trusted):
    real = tmp_path / "real-store"
    real.mkdir(mode=0o700)
    link = tmp_path / "linked-store"
    os.symlink(real, link)

    with pytest.raises(CheckpointStorageError, match="symbolic link"):
        CheckpointStorage(link)


def test_registry_replaced_by_directory_is_rejected(tmp_path, keypair):
    ring = TrustedKeyRing(tmp_path / "keys" / "trusted_keys.json")
    ring.add_key("adv-key-01", keypair[1])

    ring.registry_path.unlink()
    ring.registry_path.mkdir()

    with pytest.raises(TrustedKeyRingError, match="not a regular file"):
        ring.trusted_keys()


def test_checkpoint_file_replaced_by_directory_is_detected(storage, keypair, trusted):
    storage.save(sign_checkpoint(make_checkpoint(), keypair[0]), trusted)
    target = next(storage.base_dir.glob("*.checkpoint.json"))
    target.unlink()
    target.mkdir()

    with pytest.raises(CheckpointStorageError, match="not a regular file"):
        storage.load("case-adv-ledger", 1)


def test_directory_entry_planted_beside_store_is_ignored(storage, keypair, trusted):
    """Random non-checkpoint files in the store are invisible to listing."""

    (storage.base_dir / "operator_notes.txt").write_text("not a checkpoint")
    (storage.base_dir / ".tmp-checkpoint-abandoned.json.tmp").write_bytes(b"junk")
    (storage.base_dir / "case-adv-ledger-0000000001-bad!fp.checkpoint.json").write_bytes(
        b"{}"
    )

    storage.save(sign_checkpoint(make_checkpoint(), keypair[0]), trusted)

    assert len(storage.list_checkpoints()) == 1


# ------------------------------------------------------------------- races


def test_concurrent_distinct_saves_all_persist(storage, keypair, trusted):
    private_key, _ = keypair

    def seal(index: int) -> None:
        envelope = sign_checkpoint(make_checkpoint(sequence=index), private_key)
        storage.save(envelope, trusted)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(seal, range(16)))

    entries = storage.list_checkpoints()
    assert len(entries) == 16
    assert [e["sequence"] for e in entries] == list(range(16))


def test_concurrent_identical_saves_stay_idempotent(storage, keypair, trusted):
    private_key, _ = keypair
    envelope = sign_checkpoint(make_checkpoint(), private_key)

    def seal(_: int) -> None:
        storage.save(envelope, trusted)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(seal, range(16)))

    assert len(storage.list_checkpoints()) == 1


def test_concurrent_chain_audit_matches_sequential(storage, keypair, trusted):
    private_key, _ = keypair
    for sequence in range(6):
        storage.save(sign_checkpoint(make_checkpoint(sequence=sequence), private_key), trusted)

    results = {}

    def audit(_: int) -> None:
        envelopes = [
            storage.load("case-adv-ledger", s) for s in range(6)
        ]
        from sutra_net.compliance.trusted_checkpoint import verify_checkpoint_chain

        results[_] = verify_checkpoint_chain(envelopes, trusted)["valid"]

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(audit, range(4)))

    assert all(results.values())


# --------------------------------------------------------- store relocation


def test_store_can_be_copied_and_reverified_offline(tmp_path, keypair, trusted):
    """Evidence copied to another workstation must still audit cleanly."""

    private_key, _ = keypair
    source = CheckpointStorage(tmp_path / "primary")
    for sequence in range(3):
        source.save(
            sign_checkpoint(make_checkpoint(sequence=sequence), private_key), trusted
        )

    replica = CheckpointStorage(tmp_path / "replica")
    for item in source.base_dir.iterdir():
        shutil.copy2(item, replica.base_dir / item.name)

    envelopes = [replica.load("case-adv-ledger", s) for s in range(3)]

    from sutra_net.compliance.trusted_checkpoint import verify_checkpoint_chain

    report = verify_checkpoint_chain(envelopes, trusted)
    assert report["valid"] is True
    assert report["count"] == 3
