import json
import os
import stat
from pathlib import Path

import pytest

from sutra_net.compliance.trusted_checkpoint.cli import main

PASSPHRASE_ENV = {"SUTRA_SIGNING_PASSPHRASE": "cli-secret"}


@pytest.fixture
def paths(tmp_path):
    return {
        "store_dir": tmp_path / "store",
        "registry": tmp_path / "keys" / "trusted_keys.json",
        "key_file": tmp_path / "keys" / "signing_key.pem",
        "ledger_path": tmp_path / "audit_ledger.jsonl",
    }


def base_args(paths):
    return [
        "--store-dir", str(paths["store_dir"]),
        "--registry", str(paths["registry"]),
        "--key-file", str(paths["key_file"]),
    ]


def run(capsys, argv):
    code = main(argv)
    captured = capsys.readouterr()
    out = captured.out.strip()
    payload = json.loads(out) if out else {}
    return code, payload, captured


def test_keygen_registers_and_writes_owner_only_key(capsys, paths, monkeypatch):
    monkeypatch.delenv("SUTRA_SIGNING_PASSPHRASE", raising=False)
    code, payload, _ = run(capsys, base_args(paths) + ["keygen", "--key-id", "cli-key-01"])

    assert code == 0
    assert payload["status"] == "success"
    assert "BEGIN PUBLIC KEY" in payload["public_key"]
    mode = stat.S_IMODE(os.lstat(paths["key_file"]).st_mode)
    assert mode == 0o600


def test_seal_with_explicit_last_hash_then_list_and_verify(capsys, paths, monkeypatch):
    monkeypatch.delenv("SUTRA_SIGNING_PASSPHRASE", raising=False)
    run(capsys, base_args(paths) + ["keygen", "--key-id", "cli-key-01"])

    code, payload, _ = run(
        capsys,
        base_args(paths)
        + ["seal", "--ledger-id", "case-cli-ledger", "--sequence", "1",
           "--key-id", "cli-key-01", "--last-hash", "a" * 64],
    )
    assert code == 0
    assert payload["checkpoint"]["sequence"] == 1

    code, payload, _ = run(capsys, base_args(paths) + ["list"])
    assert code == 0
    assert payload["count"] == 1

    code, payload, _ = run(
        capsys, base_args(paths) + ["verify", "--ledger-id", "case-cli-ledger"]
    )
    assert code == 0
    assert payload["valid"] is True


def test_seal_idempotent_then_conflicting_sequence_fails(capsys, paths, monkeypatch):
    monkeypatch.delenv("SUTRA_SIGNING_PASSPHRASE", raising=False)
    run(capsys, base_args(paths) + ["keygen", "--key-id", "cli-key-01"])

    seal_args = (
        base_args(paths)
        + ["seal", "--ledger-id", "case-cli-ledger", "--sequence", "4",
           "--key-id", "cli-key-01", "--last-hash", "b" * 64,
           "--timestamp-utc", "2026-11-05T06:00:00Z"]
    )
    code_first, _, _ = run(capsys, seal_args)
    code_again, _, _ = run(capsys, seal_args)
    assert code_first == 0
    assert code_again == 0

    conflicting = (
        base_args(paths)
        + ["seal", "--ledger-id", "case-cli-ledger", "--sequence", "4",
           "--key-id", "cli-key-01", "--last-hash", "b" * 64,
           "--timestamp-utc", "2026-11-05T07:00:00Z"]
    )
    code_conflict, payload, _ = run(capsys, conflicting)
    assert code_conflict == 1
    assert payload["status"] == "error"


def test_seal_reads_last_hash_from_real_ledger(capsys, paths, monkeypatch):
    from sutra_net.compliance.audit_ledger import ForensicAuditLedger

    monkeypatch.delenv("SUTRA_SIGNING_PASSPHRASE", raising=False)
    run(capsys, base_args(paths) + ["keygen", "--key-id", "cli-key-01"])
    ForensicAuditLedger(paths["ledger_path"]).record_action(
        action_type="CLI_SEED", user_name="test operator", details={}
    )

    code, payload, _ = run(
        capsys,
        base_args(paths)
        + ["seal", "--ledger-id", "case-cli-ledger", "--sequence", "1",
           "--key-id", "cli-key-01", "--ledger-path", str(paths["ledger_path"])],
    )
    assert code == 0
    assert len(payload["checkpoint"]["digest"]) == 64


def test_verify_exits_nonzero_on_tampered_store(capsys, paths, monkeypatch):
    monkeypatch.delenv("SUTRA_SIGNING_PASSPHRASE", raising=False)
    run(capsys, base_args(paths) + ["keygen", "--key-id", "cli-key-01"])
    run(
        capsys,
        base_args(paths)
        + ["seal", "--ledger-id", "case-cli-ledger", "--sequence", "1",
           "--key-id", "cli-key-01", "--last-hash", "c" * 64],
    )

    target = next(paths["store_dir"].glob("*.checkpoint.json"))
    envelope = json.loads(target.read_text(encoding="utf-8"))
    envelope["checkpoint"]["last_entry_hash"] = "9" * 64
    target.write_text(json.dumps(envelope), encoding="utf-8")

    code, payload, _ = run(
        capsys, base_args(paths) + ["verify", "--ledger-id", "case-cli-ledger"]
    )
    assert code == 1
    assert payload["report"]["valid"] is False


def test_passphrase_protected_key_end_to_end(capsys, paths, monkeypatch):
    monkeypatch.setenv("SUTRA_SIGNING_PASSPHRASE", "cli-secret")
    run(capsys, base_args(paths) + ["keygen", "--key-id", "cli-key-01"])

    key_pem = paths["key_file"].read_bytes()
    assert b"ENCRYPTED" in key_pem

    code, payload, _ = run(
        capsys,
        base_args(paths)
        + ["seal", "--ledger-id", "case-cli-ledger", "--sequence", "1",
           "--key-id", "cli-key-01", "--last-hash", "d" * 64],
    )
    assert code == 0


def test_seal_without_any_hash_source_fails_cleanly(capsys, paths, monkeypatch):
    monkeypatch.delenv("SUTRA_SIGNING_PASSPHRASE", raising=False)
    run(capsys, base_args(paths) + ["keygen", "--key-id", "cli-key-01"])

    code, payload, _ = run(
        capsys,
        base_args(paths)
        + ["seal", "--ledger-id", "case-cli-ledger", "--sequence", "1",
           "--key-id", "cli-key-01",
           "--ledger-path", str(paths["ledger_path"])],
    )
    assert code == 1
    assert "no hash-chained records" in payload["error"]


def test_module_entry_point_exposes_cli():
    from sutra_net.compliance.trusted_checkpoint.__main__ import main as entry_main

    assert entry_main is main


def test_flags_accepted_after_subcommand(capsys, paths, monkeypatch):
    """Operators naturally type global flags after the subcommand (the deck's
    recovery drill does); both positions must work identically."""

    monkeypatch.delenv("SUTRA_SIGNING_PASSPHRASE", raising=False)
    code, payload, _ = run(
        capsys,
        ["keygen", "--key-id", "cli-key-01"]
        + ["--store-dir", str(paths["store_dir"]),
           "--registry", str(paths["registry"]),
           "--key-file", str(paths["key_file"])],
    )

    assert code == 0
    assert paths["key_file"].is_file()


def test_deck_recovery_drill_command_shape_works(capsys, paths, monkeypatch):
    """End-to-end replay of the scenario_demo.md drill: seal, tamper, then
    audit with flags placed after the subcommand -> exit 1, invalid chain."""

    monkeypatch.delenv("SUTRA_SIGNING_PASSPHRASE", raising=False)
    run(capsys, base_args(paths) + ["keygen", "--key-id", "cli-key-01"])
    run(
        capsys,
        base_args(paths)
        + ["seal", "--ledger-id", "case-cli-ledger", "--sequence", "1",
           "--key-id", "cli-key-01", "--last-hash", "e" * 64],
    )

    target = next(paths["store_dir"].glob("*.checkpoint.json"))
    envelope = json.loads(target.read_text(encoding="utf-8"))
    envelope["checkpoint"]["last_entry_hash"] = "0" * 64
    target.write_text(json.dumps(envelope), encoding="utf-8")
    os.chmod(target, 0o600)

    code, payload, _ = run(
        capsys,
        ["verify",
         "--store-dir", str(paths["store_dir"]),
         "--registry", str(paths["registry"]),
         "--key-file", str(paths["key_file"]),
         "--ledger-id", "case-cli-ledger"],
    )

    assert code == 1
    assert payload["report"]["valid"] is False
    assert payload["report"]["errors"]


def test_after_position_overrides_before_position(capsys, paths, monkeypatch):
    """When both positions give a flag, the last occurrence wins."""

    monkeypatch.delenv("SUTRA_SIGNING_PASSPHRASE", raising=False)
    other_store = paths["store_dir"].parent / "other-store"

    code, payload, _ = run(
        capsys,
        ["--store-dir", "/nonexistent-before-position",
         "keygen", "--key-id", "cli-key-01",
         "--store-dir", str(other_store),
         "--registry", str(paths["registry"]),
         "--key-file", str(paths["key_file"])],
    )

    assert code == 0
    assert other_store.parent.is_dir()
