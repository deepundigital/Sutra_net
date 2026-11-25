"""Command-line interface for the trusted checkpoint infrastructure.

Thin operator shell over the service facade:

    keygen   generate a signing key, register its public half
    seal     sign the audit ledger's verified tail into an immutable checkpoint
    verify   audit every stored checkpoint as one ordered signed chain
    list     show stored checkpoint metadata

All subcommands print JSON and use explicit exit codes: 0 success, 1
operation/verification failure, 2 usage error. Every path can be overridden
on the command line so the tool is self-contained and testable without
touching the server's data directory.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Sequence

from sutra_net.compliance.audit_ledger import ForensicAuditLedger
from sutra_net.config import (
    AUDIT_LEDGER_PATH,
    TRUSTED_CHECKPOINT_DIR,
    TRUSTED_KEYS_DIR,
)

from .service import TrustedCheckpointService
from .storage import CheckpointStorage
from .keyring import TrustedKeyRing

DEFAULT_KEY_FILE = TRUSTED_KEYS_DIR / "signing_key.pem"
DEFAULT_REGISTRY = TRUSTED_KEYS_DIR / "trusted_keys.json"
PASSPHRASE_ENV_VAR = "SUTRA_SIGNING_PASSPHRASE"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trusted_checkpoint",
        description="Signed, immutable chain-of-custody checkpoints",
    )
    parser.add_argument(
        "--store-dir",
        type=Path,
        default=TRUSTED_CHECKPOINT_DIR,
        help="Checkpoint store directory",
    )
    parser.add_argument(
        "--registry",
        type=Path,
        default=DEFAULT_REGISTRY,
        help="Trusted key registry file",
    )
    parser.add_argument(
        "--key-file",
        type=Path,
        default=DEFAULT_KEY_FILE,
        help="Ed25519 signing key file (PKCS8 PEM)",
    )

    # The same path flags are also accepted after the subcommand: operators
    # naturally type them there (as the deck's recovery drill does). SUPPRESS
    # defaults mean an absent after-position flag never clobbers a
    # before-position value; when both are given, the last one wins.
    sub_common = argparse.ArgumentParser(add_help=False)
    sub_common.add_argument(
        "--store-dir", type=Path, default=argparse.SUPPRESS, help=argparse.SUPPRESS
    )
    sub_common.add_argument(
        "--registry", type=Path, default=argparse.SUPPRESS, help=argparse.SUPPRESS
    )
    sub_common.add_argument(
        "--key-file", type=Path, default=argparse.SUPPRESS, help=argparse.SUPPRESS
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    keygen = subparsers.add_parser(
        "keygen",
        parents=[sub_common],
        help="Generate a signing key and register its public half",
    )
    keygen.add_argument("--key-id", required=True)

    seal = subparsers.add_parser(
        "seal",
        parents=[sub_common],
        help="Seal the ledger's verified tail into a checkpoint",
    )
    seal.add_argument("--ledger-id", required=True)
    seal.add_argument("--sequence", type=int, required=True)
    seal.add_argument("--key-id", required=True)
    seal.add_argument(
        "--last-hash",
        default=None,
        help="Ledger tail hash to seal; when omitted, taken from the ledger",
    )
    seal.add_argument("--ledger-path", type=Path, default=AUDIT_LEDGER_PATH)
    seal.add_argument("--timestamp-utc", default=None)

    verify = subparsers.add_parser(
        "verify",
        parents=[sub_common],
        help="Audit all stored checkpoints as one signed chain",
    )
    verify.add_argument("--ledger-id", default=None)

    listing = subparsers.add_parser(
        "list",
        parents=[sub_common],
        help="List stored checkpoint metadata",
    )
    listing.add_argument("--ledger-id", default=None)

    return parser


def _emit(payload: dict) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))


def _passphrase_from_env() -> bytes | None:
    value = os.environ.get(PASSPHRASE_ENV_VAR)
    return value.encode("utf-8") if value else None


def _build_service(args: argparse.Namespace) -> TrustedCheckpointService:
    return TrustedCheckpointService(
        storage=CheckpointStorage(args.store_dir),
        keyring=TrustedKeyRing(args.registry),
        private_key_path=args.key_file,
    )


def cmd_keygen(args: argparse.Namespace) -> int:
    service = _build_service(args)
    public_pem = service.generate_signing_key(
        passphrase=_passphrase_from_env()
    )
    service.register_signing_key(args.key_id, passphrase=_passphrase_from_env())

    _emit(
        {
            "status": "success",
            "key_id": args.key_id,
            "key_file": str(args.key_file),
            "public_key": public_pem.decode("ascii"),
        }
    )
    return 0


def _resolve_last_hash(args: argparse.Namespace) -> str:
    if args.last_hash:
        return args.last_hash

    integrity = ForensicAuditLedger(args.ledger_path).verify_integrity()
    if not integrity.get("valid"):
        raise ValueError("Audit ledger integrity check failed; refusing to seal.")
    last_hash = integrity.get("last_hash")
    if not last_hash:
        raise ValueError("Audit ledger has no hash-chained records to seal.")
    return last_hash


def cmd_seal(args: argparse.Namespace) -> int:
    service = _build_service(args)
    last_hash = _resolve_last_hash(args)

    metadata = service.seal(
        ledger_id=args.ledger_id,
        sequence=args.sequence,
        last_entry_hash=last_hash,
        signing_key_id=args.key_id,
        timestamp_utc=args.timestamp_utc,
        passphrase=_passphrase_from_env(),
    )
    _emit({"status": "success", "checkpoint": metadata})
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    service = _build_service(args)
    report = service.chain_report(args.ledger_id)
    _emit({"status": "success", "valid": report["valid"], "report": report})
    return 0 if report["valid"] else 1


def cmd_list(args: argparse.Namespace) -> int:
    service = _build_service(args)
    entries = service.stored_checkpoints(args.ledger_id)
    _emit({"status": "success", "count": len(entries), "checkpoints": entries})
    return 0


_HANDLERS = {
    "keygen": cmd_keygen,
    "seal": cmd_seal,
    "verify": cmd_verify,
    "list": cmd_list,
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return _HANDLERS[args.command](args)
    except ValueError as exc:
        _emit({"status": "error", "error": str(exc)})
        return 1
    except OSError as exc:
        _emit({"status": "error", "error": f"Filesystem error: {exc}"})
        return 1


if __name__ == "__main__":
    sys.exit(main())
