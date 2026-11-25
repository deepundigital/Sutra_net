import base64
import json
import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from sutra_net.api import server as server_module
from sutra_net.api.server import app
from sutra_net.compliance.audit_ledger import ForensicAuditLedger
from sutra_net.compliance.trusted_checkpoint import (
    CheckpointStorage,
    TrustedCheckpointService,
    TrustedKeyRing,
)


TEST_USERNAME = "checkpoint-test"
TEST_PASSWORD = "test-only-password"

AUTH_HEADERS = {
    "Authorization": "Basic " + base64.b64encode(
        f"{TEST_USERNAME}:{TEST_PASSWORD}".encode()
    ).decode()
}

TEST_ENV = {
    "SUTRA_AUTH_USERNAME": TEST_USERNAME,
    "SUTRA_AUTH_PASSWORD": TEST_PASSWORD,
}


class TestCheckpointAPI(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)

        self.storage = CheckpointStorage(base / "checkpoints")
        self.keyring = TrustedKeyRing(base / "keys" / "trusted_keys.json")
        self.key_path = base / "keys" / "signing_key.pem"
        self.service = TrustedCheckpointService(
            self.storage, self.keyring, self.key_path
        )
        self.service.generate_signing_key()
        self.service.register_signing_key("api-key-01")

        self.ledger = ForensicAuditLedger(base / "audit_ledger.jsonl")

    def tearDown(self):
        self._tmp.cleanup()

    @contextmanager
    def client(self):
        with patch.dict(os.environ, TEST_ENV):
            with patch.object(server_module, "checkpoint_service", self.service):
                with patch.object(server_module, "audit_ledger", self.ledger):
                    with TestClient(app) as test_client:
                        yield test_client

    def seed_ledger(self):
        self.ledger.record_action(
            action_type="TEST_SEED",
            user_name="test operator",
            details={"note": "seed record for checkpoint tests"},
        )

    # ------------------------------------------------------------------ auth

    def test_checkpoint_routes_require_authentication(self):
        with patch.dict(os.environ, TEST_ENV):
            with TestClient(app) as client:
                sealed = client.post(
                    "/api/compliance/checkpoint", json={}
                )
                listed = client.get("/api/compliance/checkpoints")
                verified = client.get("/api/compliance/checkpoints/verify")

        self.assertEqual(sealed.status_code, 401)
        self.assertEqual(listed.status_code, 401)
        self.assertEqual(verified.status_code, 401)

    def test_signing_key_path_env_override(self):
        """SUTRA_SIGNING_KEY_PATH overrides the default signing key location."""

        with patch.dict(
            os.environ, {"SUTRA_SIGNING_KEY_PATH": "/tmp/anywhere/key.pem"}
        ):
            self.assertEqual(
                server_module.resolve_signing_key_path(),
                Path("/tmp/anywhere/key.pem"),
            )

        self.assertEqual(
            server_module.resolve_signing_key_path(),
            server_module.TRUSTED_KEYS_DIR / "signing_key.pem",
        )

    # ------------------------------------------------------------------ seal

    def test_seal_refused_on_empty_ledger(self):
        with self.client() as client:
            response = client.post(
                "/api/compliance/checkpoint",
                headers=AUTH_HEADERS,
                json={
                    "ledger_id": "case-api-ledger",
                    "sequence": 1,
                    "signing_key_id": "api-key-01",
                },
            )

        self.assertEqual(response.status_code, 409)
        self.assertIn("no hash-chained records", response.json()["detail"])

    def test_seal_success_returns_metadata(self):
        self.seed_ledger()

        with self.client() as client:
            response = client.post(
                "/api/compliance/checkpoint",
                headers=AUTH_HEADERS,
                json={
                    "ledger_id": "case-api-ledger",
                    "sequence": 1,
                    "signing_key_id": "api-key-01",
                },
            )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "success")
        checkpoint = body["checkpoint"]
        self.assertEqual(checkpoint["ledger_id"], "case-api-ledger")
        self.assertEqual(checkpoint["sequence"], 1)
        self.assertEqual(checkpoint["signing_key_id"], "api-key-01")
        self.assertNotIn("path", checkpoint)
        self.assertNotIn("/", checkpoint["filename"])

    def test_seal_rejects_invalid_body(self):
        self.seed_ledger()

        with self.client() as client:
            extra_field = client.post(
                "/api/compliance/checkpoint",
                headers=AUTH_HEADERS,
                json={
                    "ledger_id": "case-api-ledger",
                    "sequence": 1,
                    "signing_key_id": "api-key-01",
                    "evil": True,
                },
            )
            bad_ledger = client.post(
                "/api/compliance/checkpoint",
                headers=AUTH_HEADERS,
                json={
                    "ledger_id": "../escape",
                    "sequence": 1,
                    "signing_key_id": "api-key-01",
                },
            )
            negative_sequence = client.post(
                "/api/compliance/checkpoint",
                headers=AUTH_HEADERS,
                json={
                    "ledger_id": "case-api-ledger",
                    "sequence": -1,
                    "signing_key_id": "api-key-01",
                },
            )

        self.assertEqual(extra_field.status_code, 422)
        self.assertEqual(bad_ledger.status_code, 422)
        self.assertEqual(negative_sequence.status_code, 422)

    def test_seal_refuses_unregistered_signing_key(self):
        self.seed_ledger()

        with self.client() as client:
            response = client.post(
                "/api/compliance/checkpoint",
                headers=AUTH_HEADERS,
                json={
                    "ledger_id": "case-api-ledger",
                    "sequence": 1,
                    "signing_key_id": "ghost-key",
                },
            )

        self.assertEqual(response.status_code, 409)
        self.assertIn("not registered", response.json()["detail"])

    # ------------------------------------------------------------------ list

    def test_list_checkpoints_empty_and_populated(self):
        with self.client() as client:
            empty = client.get(
                "/api/compliance/checkpoints", headers=AUTH_HEADERS
            )

            self.seed_ledger()
            client.post(
                "/api/compliance/checkpoint",
                headers=AUTH_HEADERS,
                json={
                    "ledger_id": "case-api-ledger",
                    "sequence": 1,
                    "signing_key_id": "api-key-01",
                },
            )
            populated = client.get(
                "/api/compliance/checkpoints", headers=AUTH_HEADERS
            )

        self.assertEqual(empty.status_code, 200)
        self.assertEqual(empty.json()["count"], 0)

        self.assertEqual(populated.status_code, 200)
        self.assertEqual(populated.json()["count"], 1)

    def test_list_rejects_unsafe_ledger_filter(self):
        with self.client() as client:
            response = client.get(
                "/api/compliance/checkpoints",
                headers=AUTH_HEADERS,
                params={"ledger_id": "../escape"},
            )

        self.assertEqual(response.status_code, 400)

    def test_verify_rejects_unsafe_ledger_filter(self):
        with self.client() as client:
            response = client.get(
                "/api/compliance/checkpoints/verify",
                headers=AUTH_HEADERS,
                params={"ledger_id": "../escape"},
            )

        self.assertEqual(response.status_code, 400)

    def test_list_reports_corrupt_store_as_server_error(self):
        self.seed_ledger()

        with self.client() as client:
            client.post(
                "/api/compliance/checkpoint",
                headers=AUTH_HEADERS,
                json={
                    "ledger_id": "case-api-ledger",
                    "sequence": 1,
                    "signing_key_id": "api-key-01",
                },
            )
            target = next(self.storage.base_dir.glob("*.checkpoint.json"))
            target.write_bytes(b"garbage")

            response = client.get(
                "/api/compliance/checkpoints", headers=AUTH_HEADERS
            )

        # A corrupt store is a server-side integrity condition, not a bad
        # request: 500 with a detail that leaks no internals.
        self.assertEqual(response.status_code, 500)
        self.assertIn("corrupt", response.json()["detail"])
        self.assertNotIn(str(self.storage.base_dir), response.json()["detail"])

    # ---------------------------------------------------------------- verify

    def test_verify_reports_valid_chain_after_seal(self):
        self.seed_ledger()

        with self.client() as client:
            client.post(
                "/api/compliance/checkpoint",
                headers=AUTH_HEADERS,
                json={
                    "ledger_id": "case-api-ledger",
                    "sequence": 1,
                    "signing_key_id": "api-key-01",
                },
            )
            response = client.get(
                "/api/compliance/checkpoints/verify", headers=AUTH_HEADERS
            )

        self.assertEqual(response.status_code, 200)
        report = response.json()["report"]
        self.assertTrue(report["valid"])
        self.assertEqual(report["count"], 1)

    def test_verify_detects_tampered_store(self):
        self.seed_ledger()

        with self.client() as client:
            client.post(
                "/api/compliance/checkpoint",
                headers=AUTH_HEADERS,
                json={
                    "ledger_id": "case-api-ledger",
                    "sequence": 1,
                    "signing_key_id": "api-key-01",
                },
            )
            target = next(self.storage.base_dir.glob("*.checkpoint.json"))
            envelope = json.loads(target.read_text(encoding="utf-8"))
            envelope["checkpoint"]["last_entry_hash"] = "0" * 64
            target.write_text(json.dumps(envelope), encoding="utf-8")

            response = client.get(
                "/api/compliance/checkpoints/verify", headers=AUTH_HEADERS
            )

        self.assertEqual(response.status_code, 200)
        report = response.json()["report"]
        self.assertFalse(report["valid"])
        self.assertTrue(report["errors"])


if __name__ == "__main__":
    unittest.main()
