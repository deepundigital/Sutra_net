"""
Sutra-Net API Server: FastAPI service powering the Sakshya-UI dashboard,
interactive forensic triage, zero-copy Parquet analytics, and BSA Section 63 certificate generation.
"""

import base64
import binascii
import hmac
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Literal
from fastapi import FastAPI, HTTPException, Query
from fastapi.encoders import jsonable_encoder
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from sutra_net.config import (
    PROJECT_ROOT,
    SAMPLE_DATA_DIR,
    CERTIFICATES_DIR,
    TRUSTED_CHECKPOINT_DIR,
    TRUSTED_KEYS_DIR,
)
from sutra_net.ingest.hasher import AcquisitionHasher
from sutra_net.ingest.pcap_parser import PcapParser
from sutra_net.ingest.mobile_parser import MobileParser
from sutra_net.ingest.evtx_parser import LogParser
from sutra_net.storage.parquet_engine import ParquetEngine
from sutra_net.storage.query_engine import ForensicQueryEngine
from sutra_net.storage.inverted_index import InvertedIndex
from sutra_net.ai.netspectra_ml import NetSpectraML
from sutra_net.ai.chitra_nlp import ChitraNLP
from sutra_net.ai.graph_builder import ForensicKnowledgeGraph
from sutra_net.ai.correlation import EvidenceCorrelationEngine
from sutra_net.ai.spatial import SpatialCorrelationEngine
from sutra_net.ai.reconstruction import CrimeReconstructionEngine
from sutra_net.evidence import (
    evidence_locations_to_records,
    linux_syslog_records_to_events,
    mobile_messages_to_events,
    pcap_flows_to_events,
    windows_event_records_to_events,
)
from sutra_net.compliance.bsa_section63 import BSASection63Certificate
from sutra_net.compliance.audit_ledger import ForensicAuditLedger
from sutra_net.compliance.trusted_checkpoint import (
    CheckpointStorage,
    CheckpointStorageError,
    TrustedCheckpointService,
    TrustedCheckpointServiceError,
    TrustedKeyRing,
    TrustedKeyRingError,
    is_storable_ledger_id,
)

app = FastAPI(
    title="Sutra-Net Forensics Engine",
    description="AI-Powered Cyber Investigation & Digital Forensics Platform (SUTRAM 2026)",
    version="1.0.0"
)

_AUTH_REALM = "Sutra-Net Forensics"


@app.middleware("http")
async def require_authentication(request, call_next):
    """Require environment-configured HTTP Basic Authentication on every route."""

    expected_username = os.environ.get("SUTRA_AUTH_USERNAME")
    expected_password = os.environ.get("SUTRA_AUTH_PASSWORD")

    # Fail closed: never silently run without configured credentials.
    if not expected_username or not expected_password:
        return JSONResponse(
            status_code=503,
            content={"detail": "Server authentication is not configured."},
        )

    # Static assets contain no evidence or credentials.
    # Keep all API endpoints protected by authentication.
    if request.url.path.startswith("/static/"):
        return await call_next(request)

    def unauthorized():
        return JSONResponse(
            status_code=401,
            content={"detail": "Authentication required."},
            headers={
                "WWW-Authenticate":
                    f'Basic realm="{_AUTH_REALM}", charset="UTF-8"'
            },
        )

    header = request.headers.get("authorization", "")
    scheme, separator, encoded = header.partition(" ")

    if scheme.lower() != "basic" or not separator or not encoded:
        return unauthorized()

    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return unauthorized()

    if ":" not in decoded:
        return unauthorized()

    supplied_username, supplied_password = decoded.split(":", 1)
    username_matches = hmac.compare_digest(
        supplied_username, expected_username
    )
    password_matches = hmac.compare_digest(
        supplied_password, expected_password
    )

    if not (username_matches and password_matches):
        return unauthorized()

    return await call_next(request)


# Core Service Instances
parquet_engine = ParquetEngine()
query_engine = ForensicQueryEngine()
inverted_index = InvertedIndex()
ml_triage = NetSpectraML()
nlp_triage = ChitraNLP()
knowledge_graph = ForensicKnowledgeGraph()
correlation_engine = EvidenceCorrelationEngine()
spatial_correlation_engine = SpatialCorrelationEngine()
reconstruction_engine = CrimeReconstructionEngine()
cert_generator = BSASection63Certificate()
audit_ledger = ForensicAuditLedger()

# Serve static dashboard files
STATIC_DIR = PROJECT_ROOT / "sutra_net" / "api" / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class SQLQueryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query_id: str = Field(min_length=1, max_length=64)
    limit: int = Field(default=20, ge=1, le=100)


class CertificateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    case_id: str = Field(
        default="CASE-2026-SUTRAM-DEMO",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
    )
    examiner_name: str = Field(min_length=1, max_length=120)
    agency_name: str = Field(min_length=1, max_length=160)
    artifact_name: Literal[
        "sample_network.pcap",
        "sample_msgstore.db",
        "sample_syslog.log",
        "sample_windows_events.jsonl",
    ] = "sample_network.pcap"


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serves the primary forensic investigation dashboard."""
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return HTMLResponse("<h1>Sutra-Net Forensics API Online</h1><p>Visit /docs for Swagger API</p>")


@app.get("/deck", response_class=HTMLResponse)
async def serve_pitch_deck():
    """Serves the 12-slide SUTRAM 2026 Pitch Deck."""
    deck_path = PROJECT_ROOT / "deck" / "index.html"
    if deck_path.exists():
        return FileResponse(deck_path)
    raise HTTPException(status_code=404, detail="Pitch deck not found.")


@app.post("/api/ingest/sample")
async def ingest_sample_evidence():
    """
    Ingests all bundled synthetic samples (PCAP, WhatsApp DB, Syslog),
    computes SHA-256 hashes, stores them in columnar Parquet, and populates the knowledge graph.
    """
    results = {}
    case_id = "CASE-2026-SUTRAM-DEMO"
    all_evidence_events = []

    # 1. Ingest PCAP
    pcap_path = SAMPLE_DATA_DIR / "sample_network.pcap"
    if pcap_path.exists():
        hash_record = AcquisitionHasher.register_artifact(pcap_path, case_id=case_id, notes="Network Packet Capture")
        parser = PcapParser(pcap_path)
        parsed = parser.parse()

        # Write flows to Parquet
        parquet_file = parquet_engine.write_records(parsed["flows"], "flows", case_id=case_id)

        # Index and Triage
        triaged_flows = ml_triage.triage_flows(parsed["flows"])
        network_events = pcap_flows_to_events(
            triaged_flows,
            case_id=case_id,
            artifact_path=pcap_path,
            artifact_sha256=hash_record["hashes"]["sha256"],
            acquisition_record_id=hash_record["record_id"],
        )
        knowledge_graph.ingest_events(network_events)
        all_evidence_events.extend(network_events)

        results["pcap"] = {
            "hashes": hash_record["hashes"],
            "total_packets": parsed["total_packets"],
            "total_flows": parsed["total_flows"],
            "parquet_file": str(parquet_file.name),
            "threats_detected": sum(1 for f in triaged_flows if f["is_malicious"]),
            "evidence_events": len(network_events),
        }

    # 2. Ingest WhatsApp DB
    db_path = SAMPLE_DATA_DIR / "sample_msgstore.db"
    if db_path.exists():
        hash_record = AcquisitionHasher.register_artifact(db_path, case_id=case_id, notes="Android WhatsApp SQLite Evidence")
        parser = MobileParser(db_path)
        messages = parser.parse_whatsapp()

        if messages:
            parquet_messages = [
                {key: value for key, value in message.items() if key != "location"}
                for message in messages
            ]
            parquet_file = parquet_engine.write_records(parquet_messages, "messages", case_id=case_id)
            triaged_msgs = nlp_triage.triage_messages(messages)
            mobile_events = mobile_messages_to_events(
                triaged_msgs,
                case_id=case_id,
                artifact_path=db_path,
                artifact_sha256=hash_record["hashes"]["sha256"],
                acquisition_record_id=hash_record["record_id"],
            )
            knowledge_graph.ingest_events(mobile_events)
            all_evidence_events.extend(mobile_events)
            location_records = evidence_locations_to_records(mobile_events)
            location_parquet_file = None
            if location_records:
                location_parquet_file = parquet_engine.write_records(
                    location_records, "locations", case_id=case_id
                )

            results["mobile"] = {
                "hashes": hash_record["hashes"],
                "total_messages": len(messages),
                "parquet_file": str(parquet_file.name),
                "fraudulent_messages": sum(1 for m in triaged_msgs if m["is_flagged"]),
                "evidence_events": len(mobile_events),
                "location_records": len(location_records),
                "location_parquet_file": str(location_parquet_file.name) if location_parquet_file else None,
            }

    # 3. Ingest Linux syslog without inventing a year or timezone for RFC3164 rows.
    syslog_path = SAMPLE_DATA_DIR / "sample_syslog.log"
    if syslog_path.exists():
        hash_record = AcquisitionHasher.register_artifact(
            syslog_path, case_id=case_id, notes="Linux authentication and audit syslog"
        )
        syslog_records = LogParser.parse_syslog(syslog_path)
        parquet_file = None
        if syslog_records:
            parquet_file = parquet_engine.write_records(syslog_records, "linux_syslog", case_id=case_id)
        syslog_events = linux_syslog_records_to_events(
            syslog_records,
            case_id=case_id,
            artifact_path=syslog_path,
            artifact_sha256=hash_record["hashes"]["sha256"],
            acquisition_record_id=hash_record["record_id"],
        )
        knowledge_graph.ingest_events(syslog_events)
        all_evidence_events.extend(syslog_events)
        results["linux_syslog"] = {
            "hashes": hash_record["hashes"],
            "parsed_records": len(syslog_records),
            "evidence_events": len(syslog_events),
            "timestamped_events": sum(event.timestamp_utc is not None for event in syslog_events),
            "parquet_file": str(parquet_file.name) if parquet_file else None,
        }

    # Optional structured Windows export; the adapter is also available to callers
    # that supply their own JSONL extraction.
    windows_path = SAMPLE_DATA_DIR / "sample_windows_events.jsonl"
    if windows_path.exists():
        hash_record = AcquisitionHasher.register_artifact(
            windows_path, case_id=case_id, notes="Structured Windows Event Log export"
        )
        windows_records = LogParser.parse_windows_events(windows_path)
        parquet_file = None
        if windows_records:
            parquet_file = parquet_engine.write_records(windows_records, "windows_events", case_id=case_id)
        windows_events = windows_event_records_to_events(
            windows_records,
            case_id=case_id,
            artifact_path=windows_path,
            artifact_sha256=hash_record["hashes"]["sha256"],
            acquisition_record_id=hash_record["record_id"],
        )
        knowledge_graph.ingest_events(windows_events)
        all_evidence_events.extend(windows_events)
        results["windows_events"] = {
            "hashes": hash_record["hashes"],
            "parsed_records": len(windows_records),
            "evidence_events": len(windows_events),
            "timestamped_events": sum(event.timestamp_utc is not None for event in windows_events),
            "parquet_file": str(parquet_file.name) if parquet_file else None,
        }

    temporal_result = correlation_engine.correlate(
        all_evidence_events,
        case_id=case_id,
        window_seconds=900,
        cross_source_only=True,
    )
    spatial_result = spatial_correlation_engine.correlate(
        all_evidence_events,
        case_id=case_id,
        radius_meters=1000,
        time_window_seconds=3600,
        cross_source_only=False,
    )
    entity_result = correlation_engine.correlate_shared_entities(
        all_evidence_events,
        case_id=case_id,
        cross_source_only=True,
    )
    knowledge_graph.ingest_event_correlations([
        *temporal_result["correlations"],
        *spatial_result["spatial_correlations"],
        *entity_result["entity_correlations"],
    ])
    results["correlation"] = {
        "temporal_associations": temporal_result["total_correlations"],
        "spatial_associations": spatial_result["total_spatial_correlations"],
        "shared_entity_associations": entity_result["total_entity_correlations"],
    }

    # Record action in audit ledger
    audit_ledger.record_action(
        action_type="EVIDENCE_INGESTION_BATCH",
        user_name="System Examiner",
        details=results,
        case_id=case_id
    )

    return {"status": "success", "ingested": results}


@app.get("/api/triage/network")
async def get_network_triage():
    """
    Returns AI network flow scoring, C2 beacon alerts, and JA3 fingerprints.
    """
    pcap_path = SAMPLE_DATA_DIR / "sample_network.pcap"
    if not pcap_path.exists():
        raise HTTPException(status_code=404, detail="Sample PCAP not found.")

    parser = PcapParser(pcap_path)
    parsed = parser.parse()
    triaged = ml_triage.triage_flows(parsed["flows"])

    return {
        "total_flows": len(triaged),
        "malicious_count": sum(1 for f in triaged if f["is_malicious"]),
        "flows": triaged
    }


@app.get("/api/triage/mobile")
async def get_mobile_triage():
    """
    Returns Hinglish scam intent categorization and extracted UPI mule accounts.
    """
    db_path = SAMPLE_DATA_DIR / "sample_msgstore.db"
    if not db_path.exists():
        raise HTTPException(status_code=404, detail="Sample WhatsApp DB not found.")

    parser = MobileParser(db_path)
    messages = parser.parse_whatsapp()
    triaged = nlp_triage.triage_messages(messages)
    mule_accounts = knowledge_graph.find_mule_accounts()

    return {
        "total_messages": len(triaged),
        "flagged_count": sum(1 for m in triaged if m["is_flagged"]),
        "mule_accounts": mule_accounts,
        "messages": triaged
    }


@app.get("/api/graph")
async def get_knowledge_graph():
    """
    Returns the complete Cytoscape.js knowledge graph.
    """
    return knowledge_graph.to_cytoscape_json()


@app.get("/api/timeline")
async def get_evidence_timeline(
    case_id: Optional[str] = None,
    source_type: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    limit: int = Query(default=500, ge=1, le=5000),
):
    """Return normalized case events in chronological order."""
    try:
        return correlation_engine.build_timeline(
            knowledge_graph.get_evidence_events(case_id),
            case_id=case_id,
            source_type=source_type,
            start=start,
            end=end,
            limit=limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/correlations")
async def get_evidence_correlations(
    case_id: Optional[str] = None,
    window_seconds: int = Query(default=900, ge=1, le=604800),
    cross_source_only: bool = True,
    limit: int = Query(default=500, ge=1, le=5000),
):
    """Find explainable same-case event associations within a time window."""
    return correlation_engine.correlate(
        knowledge_graph.get_evidence_events(case_id),
        case_id=case_id,
        window_seconds=window_seconds,
        cross_source_only=cross_source_only,
        limit=limit,
    )


@app.get("/api/spatial-correlations")
async def get_spatial_correlations(
    case_id: Optional[str] = None,
    radius_meters: float = Query(default=1000, gt=0, le=100000),
    time_window_seconds: Optional[int] = Query(default=None, ge=1, le=604800),
    cross_source_only: bool = False,
    limit: int = Query(default=500, ge=1, le=5000),
):
    """Find same-case location observations within a geographic radius."""
    return spatial_correlation_engine.correlate(
        knowledge_graph.get_evidence_events(case_id),
        case_id=case_id,
        radius_meters=radius_meters,
        time_window_seconds=time_window_seconds,
        cross_source_only=cross_source_only,
        limit=limit,
    )


@app.get("/api/entity-correlations")
async def get_entity_correlations(
    case_id: Optional[str] = None,
    cross_source_only: bool = True,
    limit: int = Query(default=500, ge=1, le=5000),
):
    """Find same-case event links by shared normalized identifiers, including untimed rows."""
    return correlation_engine.correlate_shared_entities(
        knowledge_graph.get_evidence_events(case_id),
        case_id=case_id,
        cross_source_only=cross_source_only,
        limit=limit,
    )


@app.get("/api/reconstruction")
async def get_case_reconstruction(
    case_id: Optional[str] = None,
    temporal_window_seconds: int = Query(default=900, ge=1, le=604800),
    spatial_radius_meters: float = Query(default=1000, gt=0, le=100000),
    spatial_time_window_seconds: Optional[int] = Query(default=3600, ge=1, le=604800),
    limit: int = Query(default=2000, ge=1, le=5000),
):
    """Build a provenance-linked chronology grouped into reviewable episodes."""
    return reconstruction_engine.reconstruct(
        knowledge_graph.get_evidence_events(case_id),
        case_id=case_id,
        temporal_window_seconds=temporal_window_seconds,
        spatial_radius_meters=spatial_radius_meters,
        spatial_time_window_seconds=spatial_time_window_seconds,
        limit=limit,
    )


@app.get("/api/case-report")
async def export_case_report(
    case_id: str = Query(
        default="CASE-2026-SUTRAM-DEMO",
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
    ),
    temporal_window_seconds: int = Query(default=900, ge=1, le=604800),
    spatial_radius_meters: float = Query(default=1000, gt=0, le=100000),
    spatial_time_window_seconds: Optional[int] = Query(default=3600, ge=1, le=604800),
    limit: int = Query(default=2000, ge=1, le=5000),
):
    """Download one evidence-linked working report with analysis and audit context."""
    all_events = knowledge_graph.get_evidence_events(case_id)
    timeline = correlation_engine.build_timeline(
        all_events, case_id=case_id, limit=limit
    )
    report_events = timeline["events"]
    association_limit = max(500, min(limit * 10, 5000))
    temporal_result = correlation_engine.correlate(
        report_events,
        case_id=case_id,
        window_seconds=temporal_window_seconds,
        cross_source_only=True,
        limit=association_limit,
    )
    spatial_result = spatial_correlation_engine.correlate(
        report_events,
        case_id=case_id,
        radius_meters=spatial_radius_meters,
        time_window_seconds=spatial_time_window_seconds,
        cross_source_only=False,
        limit=association_limit,
    )
    entity_result = correlation_engine.correlate_shared_entities(
        report_events,
        case_id=case_id,
        cross_source_only=True,
        limit=association_limit,
    )
    reconstruction = reconstruction_engine.reconstruct(
        report_events,
        case_id=case_id,
        temporal_window_seconds=temporal_window_seconds,
        spatial_radius_meters=spatial_radius_meters,
        spatial_time_window_seconds=spatial_time_window_seconds,
        temporal_result=temporal_result,
        spatial_result=spatial_result,
        entity_result=entity_result,
        limit=limit,
    )

    audit_integrity = audit_ledger.verify_integrity()
    try:
        audit_history = audit_ledger.get_case_history(case_id)
        audit_history_error = None
    except ValueError:
        audit_history = []
        audit_history_error = "Case audit history is unavailable because ledger integrity verification failed."
    acquisition_records = [
        record for record in audit_history
        if record.get("filename") and record.get("hashes")
    ]
    artifact_manifest = {}
    for event in report_events:
        path = event.get("artifact_path")
        sha256 = event.get("artifact_sha256")
        if not path and not sha256:
            continue
        key = str(sha256 or path)
        item = artifact_manifest.setdefault(key, {
            "artifact_path": path,
            "artifact_sha256": sha256,
            "source_types": set(),
            "event_count": 0,
        })
        item["source_types"].add(str(event.get("source_type") or "unknown"))
        item["event_count"] += 1
        if not item.get("artifact_path"):
            item["artifact_path"] = path
        if not item.get("artifact_sha256"):
            item["artifact_sha256"] = sha256

    source_counts = {}
    for event in report_events:
        source = str(event.get("source_type") or "unknown")
        source_counts[source] = source_counts.get(source, 0) + 1
    missing_timestamp_count = sum(not event.get("timestamp_utc") for event in report_events)
    report = {
        "schema_version": 1,
        "report_type": "investigative_working_report",
        "case_id": case_id,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_case_events": len(all_events),
            "included_event_count": len(report_events),
            "truncated_events": timeline["truncated"],
            "events_without_usable_utc_timestamp": missing_timestamp_count,
            "source_event_counts": source_counts,
            "temporal_association_count": temporal_result["total_correlations"],
            "spatial_association_count": spatial_result["total_spatial_correlations"],
            "shared_identifier_association_count": entity_result["total_entity_correlations"],
            "episode_count": reconstruction["episode_count"],
        },
        "analysis_parameters": {
            "temporal_window_seconds": temporal_window_seconds,
            "spatial_radius_meters": spatial_radius_meters,
            "spatial_time_window_seconds": spatial_time_window_seconds,
            "event_limit": limit,
        },
        "artifact_manifest": [
            {
                **item,
                "source_types": sorted(item["source_types"]),
            }
            for _key, item in sorted(artifact_manifest.items())
        ],
        "acquisition_records": acquisition_records,
        "audit_integrity": {
            **audit_integrity,
            "case_history_available": audit_history_error is None,
            "case_history_error": audit_history_error,
        },
        "audit_history": audit_history,
        "events": report_events,
        "temporal_correlations": temporal_result,
        "spatial_correlations": spatial_result,
        "shared_identifier_correlations": entity_result,
        "reconstruction": reconstruction,
        "limitations": [
            "Rule-based associations are investigative leads and do not prove causation, identity, intent, or guilt.",
            "Events without reliable UTC timestamps are retained and can link by identifiers, but are not temporally ordered.",
            "This working report is an analysis export; it does not replace examiner review or an applicable evidence certificate.",
        ],
    }
    headers = {
        "Content-Disposition": f'attachment; filename="{case_id}-case-report.json"'
    }
    return JSONResponse(content=jsonable_encoder(report), headers=headers)


@app.post("/api/query/sql")
async def execute_sql_query(req: SQLQueryRequest):
    """Runs an approved, bounded forensic query."""
    return query_engine.run_saved_query(req.query_id, req.limit)


@app.post("/api/compliance/certificate")
async def generate_certificate(req: CertificateRequest):
    """Generate a certificate draft from a recorded, verified acquisition."""

    sample_root = SAMPLE_DATA_DIR.resolve()
    artifact_path = (sample_root / req.artifact_name).resolve()

    # Only the explicitly supported sample evidence files are accepted.
    if artifact_path.parent != sample_root or not artifact_path.is_file():
        raise HTTPException(status_code=404, detail="Evidence artifact not found.")

    # Require a prior acquisition record for this exact case and artifact.
    records = audit_ledger.get_case_history(req.case_id)
    acquisition = None

    for record in records:
        if record.get("filename") != req.artifact_name:
            continue
        if not record.get("file_path") or not record.get("hashes"):
            continue
        try:
            recorded_path = Path(record["file_path"]).resolve()
        except (OSError, TypeError, ValueError):
            continue

        if recorded_path == artifact_path and record.get("acquired_utc"):
            acquisition = record
            break

    if acquisition is None:
        raise HTTPException(
            status_code=409,
            detail=(
                "No matching acquisition record exists for this case and artifact. "
                "Ingest the evidence first and use the corresponding case ID."
            ),
        )

    try:
        current_hashes = AcquisitionHasher.hash_file(artifact_path)
    except OSError:
        raise HTTPException(status_code=500, detail="Could not verify evidence integrity.")

    recorded_hashes = acquisition["hashes"]
    algorithms = ("sha256", "sha3_256")

    if any(
        not recorded_hashes.get(name)
        or current_hashes.get(name) != recorded_hashes.get(name)
        for name in algorithms
    ):
        raise HTTPException(
            status_code=409,
            detail="Evidence hash mismatch. Certificate generation was refused.",
        )

    evidence_manifest = {
        "filename": artifact_path.name,
        "file_size_bytes": artifact_path.stat().st_size,
        "hashes": recorded_hashes,
        "acquired_utc": acquisition["acquired_utc"],
        "integrity_verified_at_generation": True,
        "integrity_verified_hashes": current_hashes,
        "acquisition_examiner": acquisition.get("examiner_name"),
    }

    # Do not insert fabricated findings into a forensic certificate.
    cert_paths = cert_generator.generate_certificate(
        case_id=req.case_id,
        evidence_manifest=evidence_manifest,
        examiner_name=req.examiner_name,
        agency_name=req.agency_name,
        key_findings=[],
    )

    return {
        "status": "success",
        "pdf_download_url": (
            f"/api/compliance/download_pdf?path="
            f"{Path(cert_paths['pdf_path']).name}"
        ),
        # Return names, not internal filesystem paths.
        "paths": {
            "pdf_path": Path(cert_paths["pdf_path"]).name,
            "json_path": Path(cert_paths["json_path"]).name,
        },
    }


@app.get("/api/compliance/download_pdf")
async def download_certificate_pdf(path: str):
    """Download a PDF located directly in the certificate directory."""

    base_dir = CERTIFICATES_DIR.resolve()

    # Reject directory components, absolute paths and traversal attempts.
    if not path or Path(path).name != path or path in {".", ".."}:
        raise HTTPException(status_code=404, detail="Certificate file not found.")

    full_path = (base_dir / path).resolve()

    # Resolve symlinks before checking containment.
    if (
        full_path.parent != base_dir
        or full_path.suffix.lower() != ".pdf"
        or not full_path.is_file()
    ):
        raise HTTPException(status_code=404, detail="Certificate file not found.")

    return FileResponse(
        full_path,
        media_type="application/pdf",
        filename=full_path.name,
    )


# ---------------------------------------------------------------------------
# Trusted checkpoint infrastructure: signed chain-of-custody seals over the
# audit ledger. Every route below inherits the global authentication
# middleware; none of them exposes internal filesystem paths.
# ---------------------------------------------------------------------------

checkpoint_storage = CheckpointStorage(TRUSTED_CHECKPOINT_DIR)
trusted_keyring = TrustedKeyRing(TRUSTED_KEYS_DIR / "trusted_keys.json")


def resolve_signing_key_path() -> Path:
    """Signing key file location: SUTRA_SIGNING_KEY_PATH override or default."""

    return Path(
        os.environ.get(
            "SUTRA_SIGNING_KEY_PATH",
            str(TRUSTED_KEYS_DIR / "signing_key.pem"),
        )
    )


checkpoint_service = TrustedCheckpointService(
    checkpoint_storage,
    trusted_keyring,
    resolve_signing_key_path(),
)


class CheckpointSealRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    ledger_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    sequence: int = Field(ge=0, le=10**15)
    signing_key_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    timestamp_utc: Optional[str] = None


def _checkpoint_http_error(exc: Exception) -> HTTPException:
    """Map trusted-checkpoint failures onto safe HTTP status codes."""

    text = str(exc)
    if "does not exist" in text or "not configured" in text:
        return HTTPException(
            status_code=503,
            detail="Trusted checkpoint signing is not configured on this server.",
        )
    if isinstance(
        exc, (TrustedCheckpointServiceError, CheckpointStorageError)
    ):
        return HTTPException(status_code=409, detail=text)
    return HTTPException(status_code=400, detail="Invalid checkpoint request.")


@app.post("/api/compliance/checkpoint")
async def create_trusted_checkpoint(req: CheckpointSealRequest):
    """Seal the verified tail of the audit ledger into a signed checkpoint.

    The ledger's integrity report supplies the tail hash; sealing is refused
    outright when the ledger itself fails verification.
    """

    integrity = audit_ledger.verify_integrity()
    if not integrity.get("valid"):
        raise HTTPException(
            status_code=409,
            detail="Audit ledger integrity check failed; refusing to seal.",
        )

    last_hash = integrity.get("last_hash")
    if not last_hash:
        raise HTTPException(
            status_code=409,
            detail="Audit ledger has no hash-chained records to seal.",
        )

    passphrase_env = os.environ.get("SUTRA_SIGNING_PASSPHRASE")
    passphrase_bytes = (
        passphrase_env.encode("utf-8") if passphrase_env else None
    )

    try:
        metadata = checkpoint_service.seal(
            ledger_id=req.ledger_id,
            sequence=req.sequence,
            last_entry_hash=last_hash,
            signing_key_id=req.signing_key_id,
            timestamp_utc=req.timestamp_utc,
            passphrase=passphrase_bytes,
        )
    except (TrustedCheckpointServiceError, CheckpointStorageError) as exc:
        raise _checkpoint_http_error(exc)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid checkpoint request.")

    return {"status": "success", "checkpoint": metadata}


def _require_storable_ledger_id(ledger_id: Optional[str]) -> None:
    """Reject unsafe ledger identifiers before they reach the store layer."""

    if ledger_id is not None and not is_storable_ledger_id(ledger_id):
        raise HTTPException(status_code=400, detail="Invalid ledger identifier.")


@app.get("/api/compliance/checkpoints")
async def list_trusted_checkpoints(ledger_id: Optional[str] = None):
    """List stored checkpoint metadata, sorted by ledger and sequence."""

    _require_storable_ledger_id(ledger_id)

    try:
        entries = checkpoint_service.stored_checkpoints(ledger_id)
    except CheckpointStorageError:
        # A corrupt store is a server-side integrity condition, not a bad
        # request; respond without leaking internal detail.
        raise HTTPException(
            status_code=500,
            detail="Checkpoint store is in a corrupt state; operator audit required.",
        )

    return {"status": "success", "count": len(entries), "checkpoints": entries}


@app.get("/api/compliance/checkpoints/verify")
async def verify_trusted_checkpoints(ledger_id: Optional[str] = None):
    """Verify every stored checkpoint as one ordered, signed chain.

    The verification report is returned even when invalid: a failed audit is
    evidence, and must be inspectable rather than hidden behind an error.
    Corrupt or tampered stored files surface inside the report rather than
    as transport errors.
    """

    _require_storable_ledger_id(ledger_id)

    try:
        report = checkpoint_service.chain_report(ledger_id)
    except TrustedKeyRingError:
        raise HTTPException(
            status_code=503,
            detail="Trusted key registry is not available on this server.",
        )
    except CheckpointStorageError:
        # Defensive: chain_report degrades storage failures into the report
        # itself, so this only fires for unexpected store-layer conditions.
        raise HTTPException(
            status_code=500,
            detail="Checkpoint store is in a corrupt state; operator audit required.",
        )

    return {"status": "success", "report": report}
