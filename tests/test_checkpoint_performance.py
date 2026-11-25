"""Generous performance smoke test: correctness at scale, not speed racing."""

import time

from sutra_net.compliance.trusted_checkpoint import (
    CheckpointStorage,
    TrustedCheckpointService,
    TrustedKeyRing,
    verify_checkpoint_chain,
)

SCALE = 100
CEILING_SECONDS = 20.0


def test_hundred_checkpoint_lifecycle_completes_quickly(tmp_path):
    service = TrustedCheckpointService(
        storage=CheckpointStorage(tmp_path / "store"),
        keyring=TrustedKeyRing(tmp_path / "keys" / "registry.json"),
        private_key_path=tmp_path / "keys" / "signing_key.pem",
    )
    service.generate_signing_key()
    service.register_signing_key("perf-key-01")

    started = time.perf_counter()
    for sequence in range(SCALE):
        service.seal(
            ledger_id="perf-ledger",
            sequence=sequence,
            last_entry_hash="a" * 64,
            signing_key_id="perf-key-01",
            timestamp_utc=f"2026-01-01T00:{sequence // 60:02d}:{sequence % 60:02d}Z",
        )
    entries = service.stored_checkpoints("perf-ledger")
    envelopes = [
        service.storage.load("perf-ledger", entry["sequence"])
        for entry in entries
    ]
    report = verify_checkpoint_chain(envelopes, service.keyring.trusted_keys())
    elapsed = time.perf_counter() - started

    assert report["valid"] is True
    assert report["count"] == SCALE
    assert elapsed < CEILING_SECONDS, (
        f"{SCALE}-checkpoint lifecycle took {elapsed:.1f}s "
        f"(ceiling {CEILING_SECONDS}s)"
    )
