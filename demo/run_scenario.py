"""End-to-end cybercrime scenario demo for SUTRAM 2026 Round 2.

Scenario: a seized laptop yields an encrypted-traffic capture and an Android
chat database. The pipeline acquires and hashes the evidence, triages
encrypted C2 beaconing, extracts a Hinglish extortion ring with its UPI mule
accounts, correlates everything on a knowledge graph, seals the audit
ledger's verified tail into a signed checkpoint, verifies the chain, and
issues a BSA Section 63 certificate.

Every artifact stays inside --workdir (default: <project>/data/demo).
Run non-interactively:

    python3 demo/run_scenario.py [--workdir DIR]

Exit code 0 only if every stage, including checkpoint verification,
succeeds.
"""

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from sutra_net.ai.chitra_nlp import ChitraNLP
from sutra_net.ai.graph_builder import ForensicKnowledgeGraph
from sutra_net.ai.correlation import EvidenceCorrelationEngine
from sutra_net.ai.spatial import SpatialCorrelationEngine
from sutra_net.ai.reconstruction import CrimeReconstructionEngine
from sutra_net.ai.netspectra_ml import NetSpectraML
from sutra_net.compliance.audit_ledger import ForensicAuditLedger
from sutra_net.compliance.bsa_section63 import BSASection63Certificate
from sutra_net.compliance.trusted_checkpoint import (
    CheckpointStorage,
    TrustedCheckpointService,
    TrustedKeyRing,
)
from sutra_net.ingest.hasher import AcquisitionHasher
from sutra_net.ingest.mobile_parser import MobileParser
from sutra_net.ingest.pcap_parser import PcapParser
from sutra_net.ingest.evtx_parser import LogParser
from sutra_net.evidence import (
    evidence_locations_to_records,
    linux_syslog_records_to_events,
    mobile_messages_to_events,
    pcap_flows_to_events,
    windows_event_records_to_events,
)
from sutra_net.storage.parquet_engine import ParquetEngine

CASE_ID = "CASE-2026-SUTRAM-DEMO"
SIGNING_KEY_ID = "demo-key-01"


def stage_acquire(workdir: Path) -> dict:
    """Hash and register the seized artifacts in the audit ledger."""

    ledger = ForensicAuditLedger(workdir / "audit_ledger.jsonl")
    samples_dir = PROJECT_ROOT / "sample_data"
    acquired = []

    for filename, notes in [
        ("sample_network.pcap", "Network capture seized from suspect workstation"),
        ("sample_msgstore.db", "Android chat database extracted from seized handset"),
    ]:
        artifact = samples_dir / filename
        if not artifact.is_file():
            continue
        record = AcquisitionHasher.register_artifact(
            artifact,
            case_id=CASE_ID,
            examiner_name="demo operator",
            notes=notes,
            ledger_path=ledger.ledger_path,
        )
        acquired.append(record)

    supporting = []
    for filename, notes in [
        ("sample_syslog.log", "Linux authentication and audit syslog"),
        ("sample_windows_events.jsonl", "Structured Windows Event Log export"),
    ]:
        artifact = samples_dir / filename
        if not artifact.is_file():
            continue
        record = AcquisitionHasher.register_artifact(
            artifact,
            case_id=CASE_ID,
            examiner_name="demo operator",
            notes=notes,
            ledger_path=ledger.ledger_path,
        )
        supporting.append(record)

    if not acquired:
        raise RuntimeError("Bundled sample evidence is missing; cannot run scenario")

    return {
        "stage": "ACQUISITION",
        "artifacts": [
            {
                "filename": record["filename"],
                "acquisition_record_id": record["record_id"],
                "file_size_bytes": record["file_size_bytes"],
                "sha256": record["hashes"]["sha256"],
                "sha3_256": record["hashes"]["sha3_256"],
                "acquired_utc": record["acquired_utc"],
            }
            for record in acquired
        ],
        "supporting_artifacts": [
            {
                "filename": record["filename"],
                "acquisition_record_id": record["record_id"],
                "file_size_bytes": record["file_size_bytes"],
                "sha256": record["hashes"]["sha256"],
                "sha3_256": record["hashes"]["sha3_256"],
                "acquired_utc": record["acquired_utc"],
            }
            for record in supporting
        ],
        "ledger_record_ids": [record["record_id"] for record in (*acquired, *supporting)],
    }


def _artifact_provenance(acquisition: dict | None, filename: str) -> dict:
    if not acquisition:
        return {"artifact_path": str((PROJECT_ROOT / "sample_data" / filename).resolve())}
    artifact = next(
        (item for item in [
            *acquisition.get("artifacts", []),
            *acquisition.get("supporting_artifacts", []),
        ] if item.get("filename") == filename),
        None,
    )
    if not artifact:
        return {"artifact_path": str((PROJECT_ROOT / "sample_data" / filename).resolve())}
    return {
        "artifact_path": str((PROJECT_ROOT / "sample_data" / filename).resolve()),
        "artifact_sha256": artifact.get("sha256"),
        "acquisition_record_id": artifact.get("acquisition_record_id"),
    }


def stage_network_triage(workdir: Path, acquisition: dict | None = None) -> dict:
    """Triage the capture and stage host logs for shared evidence normalization."""

    parser = PcapParser(PROJECT_ROOT / "sample_data" / "sample_network.pcap")
    parsed = parser.parse()

    ParquetEngine(base_dir=workdir / "parquet_store").write_records(
        parsed["flows"], "flows", case_id=CASE_ID
    )

    triaged = NetSpectraML().triage_flows(parsed["flows"])
    malicious = [flow for flow in triaged if flow["is_malicious"]]
    provenance = _artifact_provenance(acquisition, "sample_network.pcap")
    syslog_path = PROJECT_ROOT / "sample_data" / "sample_syslog.log"
    syslog_records = LogParser.parse_syslog(syslog_path) if syslog_path.is_file() else []
    syslog_provenance = _artifact_provenance(acquisition, "sample_syslog.log")
    if syslog_records:
        ParquetEngine(base_dir=workdir / "parquet_store").write_records(
            syslog_records, "linux_syslog", case_id=CASE_ID
        )
    windows_path = PROJECT_ROOT / "sample_data" / "sample_windows_events.jsonl"
    windows_records = LogParser.parse_windows_events(windows_path) if windows_path.is_file() else []
    windows_provenance = _artifact_provenance(acquisition, "sample_windows_events.jsonl")
    if windows_records:
        ParquetEngine(base_dir=workdir / "parquet_store").write_records(
            windows_records, "windows_events", case_id=CASE_ID
        )

    return {
        "stage": "NETWORK_TRIAGE",
        "total_flows": len(triaged),
        "malicious_flows": len(malicious),
        "ja3_alerts": sorted(
            {
                flow["ja3_hash"]
                for flow in malicious
                if flow.get("ja3_hash")
            }
        )[:5],
        "evidence_provenance": provenance,
        "linux_syslog_record_count": len(syslog_records),
        "windows_event_record_count": len(windows_records),
        "linux_syslog_records": syslog_records,
        "linux_syslog_provenance": syslog_provenance,
        "windows_event_records": windows_records,
        "windows_events_provenance": windows_provenance,
        "flows": triaged,
    }


def stage_mobile_triage(workdir: Path, acquisition: dict | None = None) -> dict:
    """Triage Hinglish chat artifacts and extract fraud entities."""

    parser = MobileParser(PROJECT_ROOT / "sample_data" / "sample_msgstore.db")
    messages = parser.parse_whatsapp()

    parquet_messages = [
        {key: value for key, value in message.items() if key != "location"}
        for message in messages
    ]
    ParquetEngine(base_dir=workdir / "parquet_store").write_records(
        parquet_messages, "messages", case_id=CASE_ID
    )

    triaged = ChitraNLP().triage_messages(messages)
    flagged = [message for message in triaged if message["is_flagged"]]
    provenance = _artifact_provenance(acquisition, "sample_msgstore.db")
    mobile_events = mobile_messages_to_events(
        triaged, case_id=CASE_ID, **provenance
    )
    location_records = evidence_locations_to_records(mobile_events)
    location_parquet_file = None
    if location_records:
        location_parquet_file = ParquetEngine(base_dir=workdir / "parquet_store").write_records(
            location_records, "locations", case_id=CASE_ID
        )

    return {
        "stage": "MOBILE_TRIAGE",
        "total_messages": len(triaged),
        "flagged_messages": len(flagged),
        "categories": sorted(
            {category for message in flagged for category in message.get("scam_categories", [])}
        ),
        "evidence_provenance": provenance,
        "location_records": len(location_records),
        "location_parquet_file": location_parquet_file.name if location_parquet_file else None,
        "messages": triaged,
    }


def stage_correlate(network: dict, mobile: dict) -> dict:
    """Correlate C2 infrastructure and fraud entities on one graph."""

    graph = ForensicKnowledgeGraph()
    network_provenance = network.get("evidence_provenance", {})
    mobile_provenance = mobile.get("evidence_provenance", {})
    network_events = pcap_flows_to_events(
        network["flows"], case_id=CASE_ID, **network_provenance
    )
    mobile_events = mobile_messages_to_events(
        mobile["messages"], case_id=CASE_ID, **mobile_provenance
    )
    syslog_events = linux_syslog_records_to_events(
        network.get("linux_syslog_records", []),
        case_id=CASE_ID,
        **network.get("linux_syslog_provenance", {}),
    )
    windows_events = windows_event_records_to_events(
        network.get("windows_event_records", []),
        case_id=CASE_ID,
        **network.get("windows_events_provenance", {}),
    )
    graph.ingest_events([*network_events, *mobile_events, *syslog_events, *windows_events])

    mules = graph.find_mule_accounts()
    correlation_engine = EvidenceCorrelationEngine()
    all_events = [*network_events, *mobile_events, *syslog_events, *windows_events]
    timeline = correlation_engine.build_timeline(all_events, case_id=CASE_ID)
    temporal_correlations = correlation_engine.correlate(
        all_events, case_id=CASE_ID, window_seconds=900, cross_source_only=True
    )
    spatial_correlations = SpatialCorrelationEngine().correlate(
        all_events,
        case_id=CASE_ID,
        radius_meters=1000,
        time_window_seconds=3600,
        cross_source_only=False,
    )
    entity_correlations = correlation_engine.correlate_shared_entities(
        all_events, case_id=CASE_ID, cross_source_only=True
    )
    reconstruction = CrimeReconstructionEngine().reconstruct(
        all_events,
        case_id=CASE_ID,
        temporal_result=temporal_correlations,
        spatial_result=spatial_correlations,
        entity_result=entity_correlations,
    )
    graph.ingest_event_correlations([
        *temporal_correlations["correlations"],
        *spatial_correlations["spatial_correlations"],
        *entity_correlations["entity_correlations"],
    ])
    event_nodes = [
        data.get("metadata", {}).get("event", {})
        for _node, data in graph.graph.nodes(data=True)
        if data.get("entity_type") == "evidence_event"
    ]
    source_event_counts = {
        source: sum(1 for event in event_nodes if event.get("source_type") == source)
        for source in ("pcap", "mobile", "linux_syslog", "windows_event")
    }
    entity_count = sum(
        1 for _node, data in graph.graph.nodes(data=True)
        if data.get("entity_type") != "evidence_event"
    )

    return {
        "stage": "CORRELATION",
        "nodes": graph.graph.number_of_nodes(),
        "entities": entity_count,
        "relationships": graph.graph.number_of_edges(),
        "evidence_events": len(event_nodes),
        "source_event_counts": source_event_counts,
        "event_sequence": [
            {
                "event_id": event.get("event_id"),
                "timestamp_utc": event.get("timestamp_utc"),
                "source_type": event.get("source_type"),
                "source_record_id": event.get("source_record_id"),
                "summary": event.get("summary"),
            }
            for event in timeline["events"]
        ],
        "temporal_correlations": temporal_correlations["correlations"],
        "temporal_correlation_count": temporal_correlations["total_correlations"],
        "spatial_correlations": spatial_correlations["spatial_correlations"],
        "spatial_correlation_count": spatial_correlations["total_spatial_correlations"],
        "entity_correlations": entity_correlations["entity_correlations"],
        "entity_correlation_count": entity_correlations["total_entity_correlations"],
        "reconstruction": reconstruction,
        "mule_accounts": mules,
    }


def stage_seal_and_verify(workdir: Path) -> dict:
    """Seal the ledger's verified tail and audit the checkpoint chain."""

    ledger = ForensicAuditLedger(workdir / "audit_ledger.jsonl")
    integrity = ledger.verify_integrity()
    if not integrity["valid"] or not integrity.get("last_hash"):
        raise RuntimeError(
            "Audit ledger failed integrity verification; scenario aborted"
        )

    keys_dir = workdir / "trusted_keys"
    key_path = keys_dir / "signing_key.pem"
    service = TrustedCheckpointService(
        storage=CheckpointStorage(workdir / "trusted_checkpoints"),
        keyring=TrustedKeyRing(keys_dir / "trusted_keys.json"),
        private_key_path=key_path,
    )
    if not key_path.exists():
        service.generate_signing_key()
    if not service.keyring.has_key(SIGNING_KEY_ID):
        service.register_signing_key(SIGNING_KEY_ID)

    # Sequences are per-demo-run; use the next free ordinal.
    existing = service.stored_checkpoints(CASE_ID)
    sequence = (existing[-1]["sequence"] + 1) if existing else 1

    metadata = service.seal(
        ledger_id=CASE_ID,
        sequence=sequence,
        last_entry_hash=integrity["last_hash"],
        signing_key_id=SIGNING_KEY_ID,
    )
    report = service.chain_report(CASE_ID)
    if not report["valid"]:
        raise RuntimeError("Checkpoint chain verification failed")

    return {
        "stage": "CHAIN_OF_CUSTODY",
        "sealed": metadata,
        "chain_valid": report["valid"],
        "chain_count": report["count"],
        "ledger_last_hash": integrity["last_hash"],
    }


def stage_certify(workdir: Path, acquisition: dict, correlation: dict) -> dict:
    """Issue the BSA Section 63 certificate for the verified evidence."""

    certificate = BSASection63Certificate(output_dir=workdir / "certificates")
    artifact = acquisition["artifacts"][0]

    findings = [
        f"{correlation['relationships']} correlated relationships across "
        f"{correlation['entities']} entities",
        f"{len(correlation['mule_accounts'])} high-degree UPI mule accounts identified",
    ]

    paths = certificate.generate_certificate(
        case_id=CASE_ID,
        evidence_manifest={
            "filename": artifact["filename"],
            "file_size_bytes": artifact["file_size_bytes"],
            "hashes": {
                "sha256": artifact["sha256"],
                "sha3_256": artifact["sha3_256"],
            },
            "acquired_utc": artifact["acquired_utc"],
        },
        examiner_name="demo operator",
        agency_name="Cyber Crime Investigation Unit / FSL",
        key_findings=findings,
    )

    return {
        "stage": "CERTIFICATION",
        "certificate_pdf": Path(paths["pdf_path"]).name,
        "certificate_json": Path(paths["json_path"]).name,
    }


def run_scenario(workdir: Path) -> dict:
    """Execute every stage in order and return the case timeline."""

    workdir.mkdir(parents=True, exist_ok=True)
    timeline: list[dict] = []

    acquisition = stage_acquire(workdir)
    timeline.append({k: v for k, v in acquisition.items() if k != "ledger_record_ids"})

    network = stage_network_triage(workdir, acquisition)
    timeline.append({
        k: v for k, v in network.items()
        if k not in {"flows", "linux_syslog_records", "windows_event_records"}
    })

    mobile = stage_mobile_triage(workdir, acquisition)
    timeline.append({k: v for k, v in mobile.items() if k != "messages"})

    correlation = stage_correlate(network, mobile)
    timeline.append(correlation)

    custody = stage_seal_and_verify(workdir)
    timeline.append(custody)

    certification = stage_certify(workdir, acquisition, correlation)
    timeline.append(certification)

    return {
        "case_id": CASE_ID,
        "scenario": "Encrypted C2 + Hinglish extortion ring with UPI mule network",
        "timeline": timeline,
        "all_stages_ok": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workdir",
        type=Path,
        default=PROJECT_ROOT / "data" / "demo",
        help="Directory for all demo artifacts (default: data/demo)",
    )
    args = parser.parse_args(argv)

    try:
        report = run_scenario(args.workdir)
    except Exception as exc:  # demo must fail with a clear operator message
        print(json.dumps({"status": "error", "error": str(exc)}, indent=2))
        return 1

    report_path = args.workdir / "case_report.json"
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
    print(f"Case report written to: {report_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
