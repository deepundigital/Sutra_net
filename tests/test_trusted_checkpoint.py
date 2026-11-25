import unittest

from sutra_net.compliance.trusted_checkpoint import (
    canonical_checkpoint_bytes,
    checkpoint_digest,
    create_checkpoint,
    deserialize_checkpoint,
    serialize_checkpoint,
    validate_checkpoint,
)


class TestTrustedCheckpoint(unittest.TestCase):

    def setUp(self):
        self.checkpoint = create_checkpoint(
            ledger_id="pramana-test-ledger",
            sequence=10,
            last_entry_hash="a" * 64,
            signing_key_id="test-key-001",
            timestamp_utc="2026-10-31T06:00:00+00:00",
        )

    def test_checkpoint_creation(self):
        self.assertEqual(self.checkpoint["checkpoint_version"], 1)
        self.assertEqual(self.checkpoint["sequence"], 10)
        self.assertEqual(self.checkpoint["signature_algorithm"], "Ed25519")

    def test_canonical_serialization_is_deterministic(self):
        first = canonical_checkpoint_bytes(self.checkpoint)
        second = canonical_checkpoint_bytes(dict(reversed(list(self.checkpoint.items()))))
        self.assertEqual(first, second)

    def test_checkpoint_round_trip(self):
        raw = serialize_checkpoint(self.checkpoint)
        restored = deserialize_checkpoint(raw)
        self.assertEqual(restored, self.checkpoint)

    def test_checkpoint_digest_is_deterministic(self):
        self.assertEqual(
            checkpoint_digest(self.checkpoint),
            checkpoint_digest(self.checkpoint),
        )

    def test_rejects_invalid_hash(self):
        with self.assertRaises(ValueError):
            create_checkpoint(
                ledger_id="test-ledger",
                sequence=1,
                last_entry_hash="invalid",
                signing_key_id="test-key",
            )

    def test_rejects_negative_sequence(self):
        with self.assertRaises(ValueError):
            create_checkpoint(
                ledger_id="test-ledger",
                sequence=-1,
                last_entry_hash="a" * 64,
                signing_key_id="test-key",
            )

    def test_rejects_boolean_sequence(self):
        with self.assertRaises(ValueError):
            create_checkpoint(
                ledger_id="test-ledger",
                sequence=True,
                last_entry_hash="a" * 64,
                signing_key_id="test-key",
            )

    def test_rejects_modified_schema(self):
        modified = dict(self.checkpoint)
        modified["unexpected"] = "value"

        with self.assertRaises(ValueError):
            validate_checkpoint(modified)

    def test_rejects_non_utc_timestamp(self):
        with self.assertRaises(ValueError):
            create_checkpoint(
                ledger_id="test-ledger",
                sequence=1,
                last_entry_hash="a" * 64,
                signing_key_id="test-key",
                timestamp_utc="2026-10-31T12:00:00+05:30",
            )


if __name__ == "__main__":
    unittest.main()
