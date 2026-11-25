"""Versioned, source-independent records for evidence correlation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping


def canonical_entity_value(entity_type: str, value: Any) -> str:
    """Return a stable value used to identify an entity across evidence sources."""
    normalized = str(value).strip()
    if entity_type in {"upi_vpa", "email_address", "domain_name", "host_name"}:
        return normalized.casefold()
    if entity_type == "phone_number":
        digits = "".join(char for char in normalized if char.isdigit())
        if digits.startswith("91") and len(digits) == 12:
            digits = digits[2:]
        return digits or normalized
    if entity_type == "ip_address":
        try:
            import ipaddress

            return ipaddress.ip_address(normalized).compressed
        except ValueError:
            return normalized
    if entity_type in {"location", "geo_location"}:
        try:
            latitude, longitude = (float(part.strip()) for part in normalized.split(",", 1))
            latitude = round(latitude, 5)
            longitude = round(longitude, 5)
            if latitude == 0:
                latitude = 0.0
            if longitude == 0:
                longitude = 0.0
            return f"{latitude:.5f},{longitude:.5f}"
        except (ValueError, TypeError):
            return normalized
    if entity_type in {"ifsc_code", "bank_reference"}:
        return normalized.upper()
    return normalized


@dataclass(frozen=True)
class EvidenceEntity:
    """An identified person, device, account, address, or other entity."""

    entity_type: str
    value: str
    role: str
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def entity_id(self) -> str:
        return f"{self.entity_type}:{canonical_entity_value(self.entity_type, self.value)}"

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["entity_id"] = self.entity_id
        return result


@dataclass(frozen=True)
class EvidenceEvent:
    """A normalized observation with source-level forensic provenance."""

    event_id: str
    case_id: str
    source_type: str
    event_type: str
    timestamp_utc: str | None
    artifact_path: str | None
    artifact_sha256: str | None
    acquisition_record_id: str | None
    source_record_id: str
    entities: tuple[EvidenceEntity, ...]
    details: dict[str, Any] = field(default_factory=dict)
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "case_id": self.case_id,
            "source_type": self.source_type,
            "event_type": self.event_type,
            "timestamp_utc": self.timestamp_utc,
            "artifact_path": self.artifact_path,
            "artifact_sha256": self.artifact_sha256,
            "acquisition_record_id": self.acquisition_record_id,
            "source_record_id": self.source_record_id,
            "entities": [entity.to_dict() for entity in self.entities],
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EvidenceEvent":
        entities = tuple(
            EvidenceEntity(
                entity_type=str(entity["entity_type"]),
                value=str(entity["value"]),
                role=str(entity["role"]),
                attributes=dict(entity.get("attributes") or {}),
            )
            for entity in value.get("entities", [])
        )
        return cls(
            event_id=str(value["event_id"]),
            case_id=str(value.get("case_id") or "UNASSIGNED"),
            source_type=str(value["source_type"]),
            event_type=str(value["event_type"]),
            timestamp_utc=value.get("timestamp_utc"),
            artifact_path=value.get("artifact_path"),
            artifact_sha256=value.get("artifact_sha256"),
            acquisition_record_id=value.get("acquisition_record_id"),
            source_record_id=str(value.get("source_record_id") or "unknown"),
            entities=entities,
            details=dict(value.get("details") or {}),
            schema_version=int(value.get("schema_version", 1)),
        )


def stable_event_id(
    *,
    case_id: str,
    source_type: str,
    artifact_sha256: str | None,
    artifact_path: str | None,
    source_record_id: str,
) -> str:
    """Build a deterministic event ID scoped to one artifact and source row."""
    identity = {
        "case_id": case_id,
        "source_type": source_type,
        "artifact_sha256": artifact_sha256,
        "artifact_path": artifact_path,
        "source_record_id": source_record_id,
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
