"""Adapters that normalize current PCAP and mobile parser records."""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import math
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from sutra_net.evidence.events import EvidenceEntity, EvidenceEvent, stable_event_id


def _artifact_path(value: str | Path | None) -> str | None:
    if value is None:
        return None
    return str(Path(value).expanduser().resolve())


def _timestamp_utc(value: Any, *, numeric_unit: str = "seconds") -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        seconds = float(value)
        if numeric_unit == "milliseconds" or seconds > 100_000_000_000:
            seconds /= 1000.0
        try:
            return dt.datetime.fromtimestamp(seconds, tz=dt.timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            return _timestamp_utc(float(text), numeric_unit=numeric_unit)
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc).isoformat()


def _system_log_timestamp_utc(record: Mapping[str, Any]) -> str | None:
    """Parse log times only when their UTC meaning is explicit or an offset exists."""
    timestamp_key = next((
        key for key in (
            "timestamp_utc", "timestamp", "event_time", "eventTime", "time_created",
            "TimeCreated", "system_time", "@timestamp",
        )
        if record.get(key) is not None
    ), None)
    if timestamp_key is None:
        return None
    value = record[timestamp_key]
    if isinstance(value, Mapping):
        value = next((
            value.get(key)
            for key in ("SystemTime", "system_time", "timestamp", "value")
            if value.get(key) is not None
        ), None)
    if timestamp_key == "timestamp_utc" or isinstance(value, (int, float)):
        return _timestamp_utc(value)
    if isinstance(value, str):
        try:
            parsed = dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return None
    return _timestamp_utc(value)


def _fallback_record_id(record: Mapping[str, Any], index: int) -> str:
    raw = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    return f"record-{index}-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]}"


def _log_entities(record: Mapping[str, Any]) -> tuple[EvidenceEntity, ...]:
    entities = {}

    def add(entity_type: str, value: Any, role: str, attributes: Mapping[str, Any] | None = None):
        if value is None:
            return
        normalized = str(value).strip()
        if not normalized or normalized.casefold() in {"unknown", "n/a", "none"}:
            return
        entity = EvidenceEntity(entity_type, normalized, role, dict(attributes or {}))
        entities[entity.entity_id] = entity

    for field, role in (
        ("hostname", "event_host"),
        ("computer", "event_host"),
        ("Computer", "event_host"),
        ("computer_name", "event_host"),
        ("machine_name", "event_host"),
    ):
        add("host_name", record.get(field), role)

    for field, role in (
        ("process", "event_process"),
        ("process_name", "event_process"),
        ("image", "event_process"),
        ("Image", "event_process"),
        ("command", "event_command"),
        ("CommandLine", "event_command"),
    ):
        add("process_name" if role == "event_process" else "command_line", record.get(field), role)

    for field, role in (
        ("username", "event_account"),
        ("user", "event_account"),
        ("subject_user_name", "subject_account"),
        ("SubjectUserName", "subject_account"),
        ("target_user_name", "target_account"),
        ("TargetUserName", "target_account"),
        ("account_name", "event_account"),
    ):
        add("account_name", record.get(field), role)

    text_values = [
        record.get("message"),
        record.get("Message"),
        record.get("raw_text"),
        record.get("raw_line"),
        record.get("description"),
        record.get("command_line"),
    ]
    for field in ("extracted_ip", "source_ip", "src_ip", "client_address", "ip_address", "IpAddress"):
        value = record.get(field)
        if value:
            text_values.append(str(value))
    for text_value in text_values:
        if not isinstance(text_value, str):
            continue
        for candidate in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", text_value):
            try:
                normalized_ip = ipaddress.ip_address(candidate).compressed
            except ValueError:
                continue
            role = "remote_ip" if candidate == record.get("extracted_ip") or "from " in text_value.lower() else "referenced_ip"
            add("ip_address", normalized_ip, role)

    for field in ("process_id", "ProcessId", "pid"):
        add("process_id", record.get(field), "event_process_id")

    message = " ".join(str(value) for value in text_values if isinstance(value, str))
    user_match = re.search(
        r"(?:failed|accepted)\s+password\s+for\s+(?:invalid\s+user\s+)?([A-Za-z0-9_.@-]+)",
        message,
        re.IGNORECASE,
    )
    if not user_match:
        user_match = re.search(r"sudo:\s*([A-Za-z0-9_.@-]+)\s+:", message, re.IGNORECASE)
    if user_match:
        add("account_name", user_match.group(1), "message_account")

    return tuple(entities.values())


def _system_log_events(
    records: Sequence[Mapping[str, Any]],
    *,
    source_type: str,
    case_id: str,
    artifact_path: str | Path | None,
    artifact_sha256: str | None,
    acquisition_record_id: str | None,
) -> list[EvidenceEvent]:
    path = _artifact_path(artifact_path)
    events = []
    for index, record in enumerate(records):
        raw_timestamp = next((
            record.get(key)
            for key in (
                "timestamp_utc", "timestamp", "event_time", "eventTime", "time_created",
                "TimeCreated", "system_time", "@timestamp",
            )
            if record.get(key) is not None
        ), None)
        timestamp_utc = _system_log_timestamp_utc(record)
        source_record = next((
            record.get(key)
            for key in ("record_id", "event_record_id", "record_number", "event_index")
            if record.get(key) is not None
        ), None)
        if source_record is None:
            source_record_id = _fallback_record_id(record, index)
        elif "event_index" in record and source_record == record.get("event_index"):
            try:
                source_record_id = f"line:{int(source_record) + 1}"
            except (TypeError, ValueError):
                source_record_id = f"line:{source_record}"
        else:
            source_record_id = str(source_record)

        message = str(
            record.get("message") or record.get("Message") or record.get("raw_text")
            or record.get("raw_line") or ""
        )
        if source_type == "linux_syslog":
            lowered = message.casefold()
            if "audit log cleared" in lowered or "audit log cleared" in str(record.get("raw_line", "")).casefold():
                event_type = "audit_log_cleared"
            elif "failed password" in lowered or "invalid user" in lowered:
                event_type = "authentication_failure"
            elif "accepted password" in lowered:
                event_type = "authentication_success"
            elif "sudo:" in lowered or "command=" in lowered:
                event_type = "privileged_command"
            else:
                event_type = "linux_syslog_event"
        else:
            event_number = record.get("event_id", record.get("EventID"))
            event_type = f"windows_event_{event_number}" if event_number is not None else "windows_log_record"
            if record.get("artifact_type") == "raw_event":
                event_type = "windows_raw_event"

        details = dict(record)
        details["timestamp_raw"] = record.get("timestamp_raw") or (str(raw_timestamp) if raw_timestamp is not None else None)
        if timestamp_utc is None and details.get("timestamp_raw"):
            details["timestamp_precision"] = "yearless_or_unzoned"
        event_id = stable_event_id(
            case_id=case_id,
            source_type=source_type,
            artifact_sha256=artifact_sha256,
            artifact_path=path,
            source_record_id=source_record_id,
        )
        events.append(EvidenceEvent(
            event_id=event_id,
            case_id=case_id,
            source_type=source_type,
            event_type=event_type,
            timestamp_utc=timestamp_utc,
            artifact_path=path,
            artifact_sha256=artifact_sha256,
            acquisition_record_id=acquisition_record_id,
            source_record_id=source_record_id,
            entities=_log_entities(record),
            details=details,
        ))
    return events


def linux_syslog_records_to_events(
    records: Sequence[Mapping[str, Any]],
    *,
    case_id: str = "UNASSIGNED",
    artifact_path: str | Path | None = None,
    artifact_sha256: str | None = None,
    acquisition_record_id: str | None = None,
) -> list[EvidenceEvent]:
    """Normalize parsed Linux syslog lines; yearless timestamps remain unassigned."""
    return _system_log_events(
        records,
        source_type="linux_syslog",
        case_id=case_id,
        artifact_path=artifact_path,
        artifact_sha256=artifact_sha256,
        acquisition_record_id=acquisition_record_id,
    )


def windows_event_records_to_events(
    records: Sequence[Mapping[str, Any]],
    *,
    case_id: str = "UNASSIGNED",
    artifact_path: str | Path | None = None,
    artifact_sha256: str | None = None,
    acquisition_record_id: str | None = None,
) -> list[EvidenceEvent]:
    """Normalize Windows JSONL event records, retaining raw timestamps and IDs."""
    return _system_log_events(
        records,
        source_type="windows_event",
        case_id=case_id,
        artifact_path=artifact_path,
        artifact_sha256=artifact_sha256,
        acquisition_record_id=acquisition_record_id,
    )


def _location_entity(value: Any) -> EvidenceEntity | None:
    if isinstance(value, Mapping):
        latitude = value.get("latitude")
        if latitude is None:
            latitude = value.get("lat")
        longitude = value.get("longitude")
        if longitude is None:
            longitude = value.get("lon")
        if longitude is None:
            longitude = value.get("lng")
        accuracy = value.get("accuracy_m")
        method = value.get("method") or value.get("source") or "structured_location"
    elif isinstance(value, str) and "," in value:
        latitude, longitude = value.split(",", 1)
        accuracy = None
        method = "coordinates_in_record"
    else:
        return None

    try:
        latitude_value = float(latitude)
        longitude_value = float(longitude)
    except (TypeError, ValueError):
        return None
    if not (-90 <= latitude_value <= 90 and -180 <= longitude_value <= 180):
        return None
    try:
        accuracy_value = float(accuracy) if accuracy is not None else None
    except (TypeError, ValueError):
        accuracy_value = None
    if accuracy_value is not None and (not math.isfinite(accuracy_value) or accuracy_value < 0):
        accuracy_value = None
    normalized_value = f"{latitude_value:.6f},{longitude_value:.6f}"
    return EvidenceEntity(
        "location",
        normalized_value,
        "observed_location",
        {
            "latitude": latitude_value,
            "longitude": longitude_value,
            "accuracy_m": accuracy_value,
            "method": str(method),
        },
    )


def pcap_flows_to_events(
    flows: Sequence[Mapping[str, Any]],
    *,
    case_id: str = "UNASSIGNED",
    artifact_path: str | Path | None = None,
    artifact_sha256: str | None = None,
    acquisition_record_id: str | None = None,
) -> list[EvidenceEvent]:
    """Normalize raw flow rows or NetSpectra triage wrappers into events."""
    path = _artifact_path(artifact_path)
    events: list[EvidenceEvent] = []
    for index, wrapper in enumerate(flows):
        flow = wrapper.get("flow_details")
        if not isinstance(flow, Mapping):
            flow = wrapper
        source_ip = flow.get("src_ip")
        destination_ip = flow.get("dst_ip")
        if not source_ip or not destination_ip:
            continue

        source_record_id = str(flow.get("flow_id") or _fallback_record_id(wrapper, index))
        triage = {
            key: value
            for key, value in wrapper.items()
            if key != "flow_details" and key not in flow
        }
        details = dict(flow)
        if triage:
            details["triage"] = triage
        entities = (
            EvidenceEntity(
                "ip_address", str(source_ip), "source",
                {"port": flow.get("src_port"), "internal": True},
            ),
            EvidenceEntity(
                "ip_address", str(destination_ip), "destination",
                {"port": flow.get("dst_port"), "internal": False},
            ),
        )
        event_id = stable_event_id(
            case_id=case_id,
            source_type="pcap",
            artifact_sha256=artifact_sha256,
            artifact_path=path,
            source_record_id=source_record_id,
        )
        events.append(EvidenceEvent(
            event_id=event_id,
            case_id=case_id,
            source_type="pcap",
            event_type="network_flow",
            timestamp_utc=_timestamp_utc(flow.get("start_time")),
            artifact_path=path,
            artifact_sha256=artifact_sha256,
            acquisition_record_id=acquisition_record_id,
            source_record_id=source_record_id,
            entities=entities,
            details=details,
        ))
    return events


def mobile_messages_to_events(
    messages: Sequence[Mapping[str, Any]],
    *,
    case_id: str = "UNASSIGNED",
    artifact_path: str | Path | None = None,
    artifact_sha256: str | None = None,
    acquisition_record_id: str | None = None,
) -> list[EvidenceEvent]:
    """Normalize raw parser messages or Chitra-NLP analyzed messages."""
    path = _artifact_path(artifact_path)
    events: list[EvidenceEvent] = []
    for index, message in enumerate(messages):
        sender = message.get("sender")
        if not sender:
            continue
        sender_value = str(sender).strip()
        entities = [EvidenceEntity("phone_number", sender_value, "sender")]
        extracted = message.get("entities") or {}
        for field, entity_type, role in (
            ("upi_vpas", "upi_vpa", "recipient_account"),
            ("phone_numbers", "phone_number", "mentioned_contact"),
            ("ifsc_codes", "ifsc_code", "mentioned_bank_branch"),
            ("bank_references", "bank_reference", "mentioned_transaction"),
        ):
            for value in extracted.get(field, []) or []:
                if str(value).strip():
                    entities.append(EvidenceEntity(entity_type, str(value).strip(), role))

        raw_locations = extracted.get("locations") or []
        location_values = list(raw_locations) if isinstance(raw_locations, (list, tuple)) else [raw_locations]
        if message.get("locations"):
            value = message["locations"]
            location_values.extend(value if isinstance(value, list) else [value])
        if message.get("location"):
            location_values.append(message["location"])
        if message.get("latitude") is not None and (
            message.get("longitude") is not None or message.get("lon") is not None
        ):
            location_values.append({
                "latitude": message.get("latitude"),
                "longitude": message.get("longitude") if message.get("longitude") is not None else message.get("lon"),
                "accuracy_m": message.get("accuracy_m"),
                "method": "structured_record",
            })
        seen_locations = set()
        for location_value in location_values:
            entity = _location_entity(location_value)
            if entity and entity.entity_id not in seen_locations:
                entities.append(entity)
                seen_locations.add(entity.entity_id)
        normalized_location = next(
            (
                {
                    "latitude": entity.attributes["latitude"],
                    "longitude": entity.attributes["longitude"],
                    "accuracy_m": entity.attributes.get("accuracy_m"),
                    "method": entity.attributes.get("method"),
                }
                for entity in entities
                if entity.entity_type == "location"
            ),
            None,
        )

        source_record_id = str(message.get("msg_id") or _fallback_record_id(message, index))
        timestamp_value = (
            message.get("datetime_utc")
            or message.get("timestamp")
            or message.get("timestamp_ms")
        )
        details = {
            "source": message.get("source") or "mobile",
            "sender": sender_value,
            "text": message.get("text"),
            "from_me": message.get("from_me"),
            "is_incoming": message.get("is_incoming"),
            "location": normalized_location,
            "entities": extracted,
            "fraud_analysis": message.get("fraud_analysis"),
            "is_flagged": message.get("is_flagged"),
        }
        event_id = stable_event_id(
            case_id=case_id,
            source_type="mobile",
            artifact_sha256=artifact_sha256,
            artifact_path=path,
            source_record_id=source_record_id,
        )
        events.append(EvidenceEvent(
            event_id=event_id,
            case_id=case_id,
            source_type="mobile",
            event_type="mobile_message",
            timestamp_utc=_timestamp_utc(timestamp_value, numeric_unit="milliseconds"),
            artifact_path=path,
            artifact_sha256=artifact_sha256,
            acquisition_record_id=acquisition_record_id,
            source_record_id=source_record_id,
            entities=tuple(entities),
            details=details,
        ))
    return events


def evidence_locations_to_records(
    events: Sequence[EvidenceEvent | Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Flatten event locations into a stable, queryable Parquet row schema."""
    records = []
    for event_value in events:
        event = event_value.to_dict() if isinstance(event_value, EvidenceEvent) else dict(event_value)
        for entity in event.get("entities", []) or []:
            if entity.get("entity_type") not in {"location", "geo_location"}:
                continue
            attributes = entity.get("attributes") or {}
            latitude = attributes.get("latitude")
            longitude = attributes.get("longitude")
            if latitude is None or longitude is None:
                normalized = _location_entity(entity.get("value"))
                if normalized is None:
                    continue
                latitude = normalized.attributes["latitude"]
                longitude = normalized.attributes["longitude"]
                attributes = normalized.attributes
            try:
                latitude_value = float(latitude)
                longitude_value = float(longitude)
            except (TypeError, ValueError):
                continue
            if not (-90 <= latitude_value <= 90 and -180 <= longitude_value <= 180):
                continue
            accuracy = attributes.get("accuracy_m")
            try:
                accuracy_value = float(accuracy) if accuracy is not None else -1.0
            except (TypeError, ValueError):
                accuracy_value = -1.0
            if not math.isfinite(accuracy_value) or accuracy_value < 0:
                accuracy_value = -1.0
            records.append({
                "event_id": str(event.get("event_id") or ""),
                "source_type": str(event.get("source_type") or ""),
                "event_type": str(event.get("event_type") or ""),
                "timestamp_utc": str(event.get("timestamp_utc") or ""),
                "artifact_path": str(event.get("artifact_path") or ""),
                "artifact_sha256": str(event.get("artifact_sha256") or ""),
                "acquisition_record_id": str(event.get("acquisition_record_id") or ""),
                "source_record_id": str(event.get("source_record_id") or ""),
                "latitude": latitude_value,
                "longitude": longitude_value,
                "accuracy_m": accuracy_value,
                "accuracy_available": accuracy_value >= 0,
                "extraction_method": str(attributes.get("method") or "unspecified"),
            })
    return records
