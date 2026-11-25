import copy
import json
import os
import stat

import pytest

from sutra_net.compliance.trusted_checkpoint import (
    CheckpointStorage,
    CheckpointStorageError,
    checkpoint_digest,
    create_checkpoint,
    generate_keypair,
    sign_checkpoint,
)


@pytest.fixture
def keypair():
    return generate_keypair()


@pytest.fixture
def trusted_keys(keypair):
    _, public_key = keypair
    return {"store-key-01": public_key}


def make_checkpoint(
    ledger_id="case-store-ledger",
    sequence=7,
    signing_key_id="store-key-01",
):
    return create_checkpoint(
        ledger_id=ledger_id,
        sequence=sequence,
        last_entry_hash="b" * 64,
        signing_key_id=signing_key_id,
        timestamp_utc="2026-11-01T06:00:00Z",
    )


@pytest.fixture
def signed_envelope(keypair):
    private_key, _ = keypair
    return sign_checkpoint(make_checkpoint(), private_key)


@pytest.fixture
def storage(tmp_path):
    return CheckpointStorage(tmp_path / "checkpoints")


# --------------------------------------------------------------------- save


def test_save_returns_expected_filename(storage, signed_envelope, trusted_keys):
    path = storage.save(signed_envelope, trusted_keys)

    assert path.parent == storage.base_dir
    assert path.name.endswith(".checkpoint.json")

    stem = path.name[: -len(".checkpoint.json")]
    ledger_id, sequence_text, fingerprint = stem.rsplit("-", 2)
    assert ledger_id == "case-store-ledger"
    assert sequence_text == "0000000007"
    assert len(fingerprint) == 16
    assert fingerprint == checkpoint_digest(signed_envelope["checkpoint"])[:16]


def test_save_and_load_roundtrip(storage, signed_envelope, trusted_keys):
    storage.save(signed_envelope, trusted_keys)

    loaded = storage.load("case-store-ledger", 7)

    assert loaded == signed_envelope


def test_save_rejects_tampered_signature_and_writes_nothing(
    storage, signed_envelope, trusted_keys
):
    tampered = copy.deepcopy(signed_envelope)
    tampered["signature"] = "A" * len(tampered["signature"])

    with pytest.raises(ValueError):
        storage.save(tampered, trusted_keys)

    assert storage.list_checkpoints() == []


def test_save_is_idempotent_for_identical_checkpoint(
    storage, signed_envelope, trusted_keys
):
    first = storage.save(signed_envelope, trusted_keys)
    second = storage.save(signed_envelope, trusted_keys)

    assert first == second
    assert len(storage.list_checkpoints()) == 1


def test_save_rejects_conflicting_content_for_same_identity(
    storage, signed_envelope, trusted_keys
):
    path = storage.save(signed_envelope, trusted_keys)

    # Same logical envelope, different on-disk bytes (e.g. rewritten by a
    # tampering process or a racing writer): re-saving must refuse instead of
    # silently overwriting or healing the stored file.
    path.write_text(json.dumps(signed_envelope, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(CheckpointStorageError, match="different content"):
        storage.save(signed_envelope, trusted_keys)


def test_save_rejects_unsafe_ledger_id(storage, keypair, trusted_keys):
    private_key, _ = keypair

    # Note: an empty ledger_id never reaches storage.save because
    # create_checkpoint already rejects it upstream; the load-path guard
    # test below covers it at the storage boundary.
    unsafe_ids = ["../escape", "with/slash", "with\\slash", ".hidden", "sp ace"]
    for ledger_id in unsafe_ids:
        envelope = sign_checkpoint(make_checkpoint(ledger_id=ledger_id), private_key)
        with pytest.raises(CheckpointStorageError, match="ledger_id"):
            storage.save(envelope, trusted_keys)

    assert storage.list_checkpoints() == []


def test_save_rejects_out_of_range_sequence(storage, keypair, trusted_keys):
    private_key, _ = keypair

    envelope = sign_checkpoint(make_checkpoint(sequence=10**16), private_key)

    with pytest.raises(CheckpointStorageError, match="sequence"):
        storage.save(envelope, trusted_keys)


# --------------------------------------------------------------------- load


def test_load_missing_checkpoint_raises(storage):
    with pytest.raises(CheckpointStorageError, match="No stored checkpoint"):
        storage.load("case-store-ledger", 99)


def test_load_rejects_ambiguous_fingerprints(storage, signed_envelope, trusted_keys):
    storage.save(signed_envelope, trusted_keys)
    real = next(storage.base_dir.glob("case-store-ledger-0000000007-*.checkpoint.json"))

    stem = real.name[: -len(".checkpoint.json")]
    ledger_id, sequence_text, fingerprint = stem.rsplit("-", 2)
    duplicate_name = f"{ledger_id}-{sequence_text}-{'f' * 16}.checkpoint.json"
    (storage.base_dir / duplicate_name).write_bytes(real.read_bytes())

    with pytest.raises(CheckpointStorageError, match="Ambiguous"):
        storage.load("case-store-ledger", 7)


def test_load_rejects_corrupted_json(storage, signed_envelope, trusted_keys):
    path = storage.save(signed_envelope, trusted_keys)
    path.write_bytes(b"{not json at all")

    with pytest.raises(CheckpointStorageError, match="unreadable"):
        storage.load("case-store-ledger", 7)


def test_load_rejects_content_that_does_not_match_filename_fingerprint(
    storage, signed_envelope, trusted_keys
):
    path = storage.save(signed_envelope, trusted_keys)

    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["checkpoint"]["sequence"] = 8
    path.write_text(
        json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(CheckpointStorageError, match="fingerprint"):
        storage.load("case-store-ledger", 7)


def test_load_rejects_invalid_envelope_structure(
    storage, signed_envelope, trusted_keys
):
    path = storage.save(signed_envelope, trusted_keys)

    envelope = json.loads(path.read_text(encoding="utf-8"))
    del envelope["signature"]
    path.write_text(json.dumps(envelope), encoding="utf-8")

    with pytest.raises(CheckpointStorageError, match="schema"):
        storage.load("case-store-ledger", 7)


def test_load_rejects_unsafe_identity_arguments(storage):
    with pytest.raises(CheckpointStorageError):
        storage.load("", 1)
    with pytest.raises(CheckpointStorageError):
        storage.load("../escape", 1)
    with pytest.raises(CheckpointStorageError):
        storage.load("case-store-ledger", -1)


# ------------------------------------------------------------------- verify


def test_verify_stored_returns_checkpoint(storage, signed_envelope, trusted_keys):
    storage.save(signed_envelope, trusted_keys)

    verified = storage.verify_stored("case-store-ledger", 7, trusted_keys)

    assert verified["sequence"] == 7
    assert verified["ledger_id"] == "case-store-ledger"


def test_verify_stored_rejects_untrusted_key(storage, signed_envelope, trusted_keys):
    storage.save(signed_envelope, trusted_keys)

    _, other_public = generate_keypair()

    with pytest.raises(ValueError, match="signature verification failed"):
        storage.verify_stored("case-store-ledger", 7, {"store-key-01": other_public})


# --------------------------------------------------------------------- list


def test_list_checkpoints_sorted_and_filtered(storage, keypair, trusted_keys):
    private_key, _ = keypair

    for ledger, sequence in [("case-b", 2), ("case-a", 10), ("case-a", 2)]:
        storage.save(
            sign_checkpoint(
                make_checkpoint(ledger_id=ledger, sequence=sequence), private_key
            ),
            trusted_keys,
        )

    all_entries = storage.list_checkpoints()
    assert [(e["ledger_id"], e["sequence"]) for e in all_entries] == [
        ("case-a", 2),
        ("case-a", 10),
        ("case-b", 2),
    ]

    filtered = storage.list_checkpoints(ledger_id="case-a")
    assert [e["sequence"] for e in filtered] == [2, 10]


def test_list_checkpoints_raises_on_corrupt_file(
    storage, signed_envelope, trusted_keys
):
    storage.save(signed_envelope, trusted_keys)
    target = next(storage.base_dir.glob("*.checkpoint.json"))
    target.write_bytes(b"garbage")

    with pytest.raises(CheckpointStorageError, match="corrupt"):
        storage.list_checkpoints()


# ---------------------------------------------------------- permissions & fs


def test_store_directory_permissions_are_owner_only(storage):
    mode = stat.S_IMODE(os.lstat(storage.base_dir).st_mode)
    assert mode == 0o700


def test_existing_loose_store_directory_is_rejected(tmp_path):
    loose = tmp_path / "loose"
    loose.mkdir()
    os.chmod(loose, 0o755)

    with pytest.raises(CheckpointStorageError, match="too open"):
        CheckpointStorage(loose)


def test_saved_file_permissions_are_owner_only(storage, signed_envelope, trusted_keys):
    path = storage.save(signed_envelope, trusted_keys)

    mode = stat.S_IMODE(os.lstat(path).st_mode)
    assert mode == 0o600


def test_load_rejects_loose_file_permissions(storage, signed_envelope, trusted_keys):
    path = storage.save(signed_envelope, trusted_keys)
    os.chmod(path, 0o644)

    with pytest.raises(CheckpointStorageError, match="too open"):
        storage.load("case-store-ledger", 7)


def test_load_rejects_symlink_at_checkpoint_path(
    storage, signed_envelope, trusted_keys, tmp_path
):
    path = storage.save(signed_envelope, trusted_keys)

    outside = tmp_path / "outside.json"
    outside.write_bytes(path.read_bytes())
    path.unlink()
    os.symlink(outside, path)

    with pytest.raises(CheckpointStorageError, match="symbolic link"):
        storage.load("case-store-ledger", 7)


def test_no_temp_files_left_behind(storage, signed_envelope, trusted_keys):
    storage.save(signed_envelope, trusted_keys)

    leftovers = [p for p in storage.base_dir.iterdir() if p.name.startswith(".tmp-")]
    assert leftovers == []
