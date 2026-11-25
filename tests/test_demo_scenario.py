"""Smoke tests for the executable Round-2 scenario demo."""

import datetime
import json
from pathlib import Path

import pytest

from demo.run_scenario import main as run_demo_main


@pytest.fixture
def workdir(tmp_path) -> Path:
    return tmp_path / "demo"


def test_demo_completes_all_stages(workdir):
    exit_code = run_demo_main(["--workdir", str(workdir)])

    assert exit_code == 0

    report = json.loads((workdir / "case_report.json").read_text(encoding="utf-8"))
    assert report["all_stages_ok"] is True

    stages = [entry["stage"] for entry in report["timeline"]]
    assert stages == [
        "ACQUISITION",
        "NETWORK_TRIAGE",
        "MOBILE_TRIAGE",
        "CORRELATION",
        "CHAIN_OF_CUSTODY",
        "CERTIFICATION",
    ]


def test_demo_acquires_and_hashes_evidence(workdir):
    run_demo_main(["--workdir", str(workdir)])

    report = json.loads((workdir / "case_report.json").read_text(encoding="utf-8"))
    acquisition = report["timeline"][0]

    assert len(acquisition["artifacts"]) == 2
    for artifact in acquisition["artifacts"]:
        assert len(artifact["sha256"]) == 64
        assert len(artifact["sha3_256"]) == 64


def test_demo_seals_and_verifies_checkpoint_chain(workdir):
    run_demo_main(["--workdir", str(workdir)])

    report = json.loads((workdir / "case_report.json").read_text(encoding="utf-8"))
    custody = next(
        entry
        for entry in report["timeline"]
        if entry["stage"] == "CHAIN_OF_CUSTODY"
    )

    assert custody["chain_valid"] is True
    assert custody["chain_count"] == 1
    assert custody["sealed"]["sequence"] == 1
    assert custody["sealed"]["ledger_id"] == "CASE-2026-SUTRAM-DEMO"


def test_demo_produces_certificate_files(workdir):
    run_demo_main(["--workdir", str(workdir)])

    report = json.loads((workdir / "case_report.json").read_text(encoding="utf-8"))
    certification = report["timeline"][-1]

    assert certification["certificate_pdf"].endswith(".pdf")
    assert certification["certificate_json"].endswith(".json")
    assert (workdir / "certificates" / certification["certificate_pdf"]).is_file()
    assert (workdir / "certificates" / certification["certificate_json"]).is_file()


def test_demo_is_idempotent_across_runs(workdir):
    assert run_demo_main(["--workdir", str(workdir)]) == 0
    assert run_demo_main(["--workdir", str(workdir)]) == 0

    report = json.loads((workdir / "case_report.json").read_text(encoding="utf-8"))
    custody = next(
        entry
        for entry in report["timeline"]
        if entry["stage"] == "CHAIN_OF_CUSTODY"
    )

    # Second run seals sequence 2 onto the same unbroken chain.
    assert custody["chain_count"] == 2
    assert custody["sealed"]["sequence"] == 2
    assert custody["chain_valid"] is True


def test_certificate_manifest_carries_real_acquisition_facts(workdir):
    """The Sec-63 certificate must embed the real acquisition facts, never
    placeholders: a legal-grade document cannot contain fabricated sizes."""

    assert run_demo_main(["--workdir", str(workdir)]) == 0

    report = json.loads((workdir / "case_report.json").read_text(encoding="utf-8"))
    acquisition = report["timeline"][0]["artifacts"][0]
    certification = report["timeline"][-1]

    cert_data = json.loads(
        (workdir / "certificates" / certification["certificate_json"]).read_text(
            encoding="utf-8"
        )
    )
    evidence = cert_data["evidence"]

    assert evidence["filename"] == acquisition["filename"]
    assert evidence["file_size_bytes"] == acquisition["file_size_bytes"]
    assert evidence["file_size_bytes"] > 0
    assert evidence["hashes"]["sha256"] == acquisition["sha256"]
    assert evidence["hashes"]["sha3_256"] == acquisition["sha3_256"]

    # The acquisition timestamp must be a real ISO-8601 UTC instant.
    parsed = datetime.datetime.fromisoformat(
        evidence["acquired_utc"].replace("Z", "+00:00")
    )
    assert parsed.tzinfo is not None
