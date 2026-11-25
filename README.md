# Sutra-Net Forensics

Sutra-Net is a Python prototype for ingesting and correlating synthetic digital-forensics evidence. It combines network-flow triage, mobile-message analysis, system-log normalization, provenance-aware event links, reconstruction, and audit/checkpoint tooling.

It is a development and demonstration project. Its automated classifications and correlations are investigative leads; they are not validated findings of identity, causation, intent, or guilt. The repository does not establish courtroom admissibility or production readiness.

## Current capabilities

- **Acquisition and integrity:** computes SHA-256 and SHA3-256 hashes and appends acquisition/action records to a JSONL audit ledger.
- **Network:** parses PCAP/PCAPNG through Scapy into packets and aggregated flows, then scores flows with a static fingerprint list, heuristics, and an Isolation Forest initialized from synthetic baseline data.
- **Mobile:** reads supported WhatsApp SQLite schemas and has an SMS parser. The demo API currently ingests the bundled WhatsApp database.
- **System logs:** parses Linux syslog text. It can parse line-delimited JSON Windows event exports; it does **not** read native `.evtx` files.
- **Shared evidence model:** normalizes network, mobile, and log records into events with source-record and artifact provenance.
- **Correlation and reconstruction:** exposes temporal, spatial, and shared-identifier associations, then groups connected events into reviewable episodes. These are rule-based links, not causal conclusions.
- **Storage and queries:** writes supported parser outputs to compressed Parquet files and runs a bounded set of read-only DuckDB queries.
- **Reporting:** provides a JSON case-report export and a separate Section 63 certificate PDF/JSON template.
- **Audit checkpoints:** includes an Ed25519-signed checkpoint chain and offline verification tooling.

## Evidence support and limitations

| Source | Current support | Important limit |
| --- | --- | --- |
| PCAP / PCAPNG | Scapy parsing, packet/flow records, flow triage | The parser reads the capture into memory; large-capture streaming has not been implemented. TLS fingerprinting is rudimentary and is not a complete JA3/JA4 implementation. |
| WhatsApp SQLite | Supported message-table variants, message triage, entity/location extraction | The dashboard uses the bundled sample database; device acquisition and broad schema coverage are outside this prototype. |
| SMS SQLite | Parser method for SMS records | Not currently included in the sample-ingestion API workflow. |
| Linux syslog | Text parser and shared event adapter | RFC3164 timestamps have no year/timezone, so they remain raw and are not assigned a fabricated UTC time. |
| Windows events | Line-delimited JSON export parser and optional `sample_windows_events.jsonl` ingestion | No native `.evtx` parser or bundled Windows event fixture is included. |

The dashboard's Cytoscape graph and web fonts are loaded from external CDNs. The current browser UI therefore is **not fully offline/air-gap ready** without locally hosting those assets. API authentication uses HTTP Basic credentials supplied through environment variables; role-based access control is not implemented.

## Correlation API

All API routes are protected by the server authentication middleware. Configure both `SUTRA_AUTH_USERNAME` and `SUTRA_AUTH_PASSWORD`; the API returns HTTP 503 if either is missing.

- `POST /api/ingest/sample` hashes and ingests the bundled PCAP, WhatsApp database, and syslog. If `sample_windows_events.jsonl` is present in `sample_data/`, it is also ingested.
- `GET /api/timeline?case_id=CASE-2026-SUTRAM-DEMO&limit=500` returns case events. Timestamped events are UTC ordered; events without reliable timestamps are retained after them.
- `GET /api/correlations?case_id=CASE-2026-SUTRAM-DEMO&window_seconds=900` finds temporal cross-source pairs. Use `cross_source_only=false` to include same-source pairs.
- `GET /api/spatial-correlations?case_id=CASE-2026-SUTRAM-DEMO&radius_meters=1000&time_window_seconds=3600` compares coordinate-bearing events.
- `GET /api/entity-correlations?case_id=CASE-2026-SUTRAM-DEMO` links events by normalized identifiers, including events without usable timestamps.
- `GET /api/reconstruction?case_id=CASE-2026-SUTRAM-DEMO` returns episodes, unlinked events, associations, and per-event provenance.
- `GET /api/case-report?case_id=CASE-2026-SUTRAM-DEMO` downloads a working JSON report with the included events, artifact manifest, acquisition/audit context, associations, and reconstruction. The report is generated from the API process's in-memory graph; that graph is not rehydrated from Parquet after a restart.
- `POST /api/query/sql` accepts only saved query IDs: `top_flows`, `recent_flows`, `recent_locations`, and `recent_syslog`. Arbitrary SQL is disabled.
- `POST /api/compliance/certificate` generates a PDF and JSON certificate template for a previously acquired supported sample artifact.
- `POST /api/compliance/checkpoint`, `GET /api/compliance/checkpoints`, and `GET /api/compliance/checkpoints/verify` manage and verify signed audit checkpoints.

### Timestamp and interpretation rules

The event model preserves raw timestamps and source-record IDs. Yearless RFC3164 syslog times are not converted into UTC. Log timestamps without an explicit UTC field or timezone offset are not used for temporal correlation. Shared-identifier matches can still connect untimed records, but do not imply temporal order. Spatial matches include the reported coordinate accuracy when available.

## Install and run

Use Python 3.10 or newer and install the project dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Configure local credentials before starting the API. Replace the example values; do not commit real credentials:

```bash
export SUTRA_AUTH_USERNAME="examiner"
export SUTRA_AUTH_PASSWORD="replace-with-a-local-secret"
python -m uvicorn sutra_net.api.server:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/` and authenticate with those credentials. Click **Ingest Demo Evidence** before using the timeline, correlation, reconstruction, or case-report views. The dashboard's graph and font assets currently require network access unless you host those assets locally.

The sample API uses these files from `sample_data/` when present:

- `sample_network.pcap`
- `sample_msgstore.db`
- `sample_syslog.log`
- `sample_windows_events.jsonl` (optional JSONL export)

## Demo scenario

The scripted scenario writes its outputs under the selected work directory (default: `data/demo`):

```bash
python demo/run_scenario.py --workdir /tmp/sutram-demo
```

It records sample acquisition, triage, correlation/reconstruction, audit-chain sealing and verification, and certificate-template generation. It is a synthetic demonstration, not a validation on real case evidence.

## Tests and benchmark

The test directory contains both `unittest` and `pytest` tests. Install `pytest` if it is not already available, then run:

```bash
python -m pip install pytest
python -m pytest tests/ -q
```

The performance script compares JSON scanning, SQLite, and Parquet/DuckDB over a generated **150,000-record synthetic dataset**:

```bash
python benchmarks/speed_benchmark.py
```

Its timings depend on the local machine and dataset state. They are not a 10 GB benchmark, production SLA, or guarantee of ingestion performance.

## Integrity, certificates, and operational notes

- The audit ledger is append-only and hash-chained. The trusted-checkpoint package signs checkpoint metadata with Ed25519 and verifies checkpoint chains independently.
- The Section 63 PDF/JSON generator includes artifact hashes and a blank officer-signature block. It does not digitally sign the PDF; treat the generated files as templates that require the responsible examiner's review and signature process.
- The sample dashboard is pinned to `CASE-2026-SUTRAM-DEMO`. The backend has case-filtered read endpoints, but a full case-creation and case-selection workflow is not implemented.
- Evidence-event graph state is held in memory. Parquet and audit files are persisted, but the service does not currently rebuild the graph from them on startup.
- Triage logic uses prototype heuristics and synthetic baseline data. Validate it against labeled, representative data before relying on its alerts.
- The bundled messages do not include location coordinates, so the sample spatial-association table is empty unless location-bearing evidence is supplied.

## Project layout

```text
sutra_net/
  ai/              triage, graph, temporal/spatial correlation, reconstruction
  api/             FastAPI service and static HTML/CSS/JavaScript dashboard
  compliance/      audit ledger, certificate template, signed checkpoint tooling
  evidence/        common event model and source adapters
  ingest/          PCAP, mobile, syslog/Windows-export parsers and hasher
  storage/         Parquet writer, bounded DuckDB queries, inverted index
sample_data/       synthetic PCAP, mobile database, syslog, and generator
benchmarks/        query and checkpoint benchmarks
demo/              scripted end-to-end synthetic scenario
 tests/            unit, API, security, and scenario tests
```
