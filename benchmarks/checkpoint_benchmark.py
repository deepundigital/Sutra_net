"""Performance micro-benchmarks for the trusted checkpoint infrastructure.

Measures the full seal/audit lifecycle at a realistic scale:

    python3 benchmarks/checkpoint_benchmark.py [--count 200]

All work happens inside a temporary directory; nothing touches data/.
"""

import argparse
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

# Allow direct execution (python3 benchmarks/checkpoint_benchmark.py) by
# putting the project root on the import path.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sutra_net.compliance.trusted_checkpoint import (
    CheckpointStorage,
    TrustedCheckpointService,
    TrustedKeyRing,
    verify_checkpoint_chain,
)


def run_benchmark(count: int) -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="checkpoint-bench-"))
    try:
        service = TrustedCheckpointService(
            storage=CheckpointStorage(tmp / "store"),
            keyring=TrustedKeyRing(tmp / "keys" / "registry.json"),
            private_key_path=tmp / "keys" / "signing_key.pem",
        )
        service.generate_signing_key()
        service.register_signing_key("bench-key-01")

        started = time.perf_counter()
        for sequence in range(count):
            service.seal(
                ledger_id="bench-ledger",
                sequence=sequence,
                last_entry_hash="a" * 64,
                signing_key_id="bench-key-01",
                timestamp_utc=f"2026-01-01T00:{sequence // 60:02d}:{sequence % 60:02d}Z",
            )
        seal_seconds = time.perf_counter() - started

        started = time.perf_counter()
        entries = service.stored_checkpoints("bench-ledger")
        list_seconds = time.perf_counter() - started

        started = time.perf_counter()
        envelopes = [
            service.storage.load("bench-ledger", entry["sequence"])
            for entry in entries
        ]
        load_seconds = time.perf_counter() - started

        trusted = service.keyring.trusted_keys()
        started = time.perf_counter()
        report = verify_checkpoint_chain(envelopes, trusted)
        verify_seconds = time.perf_counter() - started

        assert report["valid"], "benchmark chain must be valid"

        return {
            "checkpoints": count,
            "seal_total_seconds": round(seal_seconds, 3),
            "seal_per_checkpoint_ms": round(seal_seconds * 1000 / count, 2),
            "seal_throughput_per_second": round(count / seal_seconds, 1),
            "list_seconds": round(list_seconds, 4),
            "load_all_seconds": round(load_seconds, 4),
            "verify_chain_seconds": round(verify_seconds, 4),
            "verify_per_checkpoint_ms": round(verify_seconds * 1000 / count, 2),
            "chain_valid": report["valid"],
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=200)
    args = parser.parse_args()

    results = run_benchmark(args.count)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
