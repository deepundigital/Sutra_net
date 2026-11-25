"""Build deterministic, provenance-linked event episodes for case review."""

from __future__ import annotations

import datetime as dt
import hashlib
from typing import Any, Iterable, Mapping

from sutra_net.ai.correlation import EvidenceCorrelationEngine, parse_utc_timestamp
from sutra_net.ai.spatial import SpatialCorrelationEngine
from sutra_net.evidence.events import EvidenceEvent


def _as_dict(event: EvidenceEvent | Mapping[str, Any]) -> dict[str, Any]:
    return event.to_dict() if isinstance(event, EvidenceEvent) else dict(event)


def _event_summary(event: Mapping[str, Any]) -> str:
    details = event.get("details") or {}
    if event.get("source_type") == "pcap":
        source = details.get("src_ip", "?")
        destination = details.get("dst_ip", "?")
        protocol = details.get("protocol") or "network"
        return f"Network flow {source} → {destination} ({protocol})"
    if event.get("source_type") == "mobile":
        text = " ".join(str(details.get("text") or "").split())
        return text[:180] + ("…" if len(text) > 180 else "") if text else "Mobile message"
    return str(
        details.get("message") or details.get("raw_text") or details.get("summary")
        or event.get("event_type") or "Evidence event"
    )[:180]


def _event_ref(event: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "event_id": event.get("event_id"),
        "source_type": event.get("source_type"),
        "event_type": event.get("event_type"),
        "timestamp_utc": event.get("timestamp_utc"),
        "source_record_id": event.get("source_record_id"),
        "artifact_path": event.get("artifact_path"),
        "artifact_sha256": event.get("artifact_sha256"),
        "acquisition_record_id": event.get("acquisition_record_id"),
        "summary": _event_summary(event),
        "entities": [
            {
                "entity_type": entity.get("entity_type"),
                "value": entity.get("value"),
                "role": entity.get("role"),
                "attributes": entity.get("attributes") or {},
            }
            for entity in event.get("entities", []) or []
        ],
    }


class CrimeReconstructionEngine:
    """Group associated observations into reviewable, chronological episodes."""

    def __init__(self):
        self.temporal_engine = EvidenceCorrelationEngine()
        self.spatial_engine = SpatialCorrelationEngine()

    @staticmethod
    def _find(parents: dict[str, str], event_id: str) -> str:
        root = event_id
        while parents[root] != root:
            root = parents[root]
        while parents[event_id] != event_id:
            parent = parents[event_id]
            parents[event_id] = root
            event_id = parent
        return root

    @classmethod
    def _union(cls, parents: dict[str, str], left: str, right: str) -> None:
        left_root = cls._find(parents, left)
        right_root = cls._find(parents, right)
        if left_root != right_root:
            parents[max(left_root, right_root)] = min(left_root, right_root)

    @staticmethod
    def _time_key(event: Mapping[str, Any]) -> tuple[bool, dt.datetime, str]:
        timestamp = parse_utc_timestamp(event.get("timestamp_utc"))
        return (
            timestamp is None,
            timestamp or dt.datetime.max.replace(tzinfo=dt.timezone.utc),
            str(event.get("event_id") or ""),
        )

    def reconstruct(
        self,
        events: Iterable[EvidenceEvent | Mapping[str, Any]],
        *,
        case_id: str | None = None,
        temporal_window_seconds: int = 900,
        spatial_radius_meters: float = 1_000,
        spatial_time_window_seconds: int | None = 3_600,
        limit: int = 2_000,
        temporal_result: Mapping[str, Any] | None = None,
        spatial_result: Mapping[str, Any] | None = None,
        entity_result: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Generate episodes from explicit temporal and spatial rule outputs."""
        safe_limit = max(1, min(int(limit), 5_000))
        all_events = []
        for event_value in events:
            event = _as_dict(event_value)
            if not case_id or event.get("case_id") == case_id:
                all_events.append(event)
        all_events.sort(key=self._time_key)
        selected_events = all_events[:safe_limit]
        event_by_id = {
            str(event.get("event_id")): event
            for event in selected_events
            if event.get("event_id")
        }

        temporal = dict(temporal_result or self.temporal_engine.correlate(
            selected_events,
            case_id=case_id,
            window_seconds=temporal_window_seconds,
            cross_source_only=True,
            limit=max(500, min(safe_limit * 10, 10_000)),
        ))
        spatial = dict(spatial_result or self.spatial_engine.correlate(
            selected_events,
            case_id=case_id,
            radius_meters=spatial_radius_meters,
            time_window_seconds=spatial_time_window_seconds,
            cross_source_only=False,
            limit=max(500, min(safe_limit * 10, 10_000)),
        ))
        entity = dict(entity_result or self.temporal_engine.correlate_shared_entities(
            selected_events,
            case_id=case_id,
            cross_source_only=True,
            limit=max(500, min(safe_limit * 10, 10_000)),
        ))
        associations = [
            *temporal.get("correlations", []),
            *spatial.get("spatial_correlations", []),
            *entity.get("entity_correlations", []),
        ]

        parents = {event_id: event_id for event_id in event_by_id}
        linked_ids: set[str] = set()
        valid_associations = []
        for association in associations:
            refs = association.get("events") or []
            if len(refs) != 2:
                continue
            left_id = str(refs[0].get("event_id") or "")
            right_id = str(refs[1].get("event_id") or "")
            if left_id not in parents or right_id not in parents or left_id == right_id:
                continue
            self._union(parents, left_id, right_id)
            linked_ids.update((left_id, right_id))
            valid_associations.append(association)

        components: dict[str, list[str]] = {}
        for event_id in linked_ids:
            components.setdefault(self._find(parents, event_id), []).append(event_id)

        episodes = []
        for event_ids in components.values():
            episode_events = sorted(
                (event_by_id[event_id] for event_id in set(event_ids)),
                key=self._time_key,
            )
            episode_ids = {str(event.get("event_id")) for event in episode_events}
            episode_links = [
                association
                for association in valid_associations
                if all(
                    str(ref.get("event_id")) in episode_ids
                    for ref in (association.get("events") or [])
                )
            ]
            temporal_links = [
                link for link in episode_links
                if link.get("relationship") in {"TEMPORAL_PROXIMITY", "SHARED_ENTITY_AND_TIME"}
            ]
            spatial_links = [
                link for link in episode_links
                if "spatial_proximity" in (link.get("basis") or [])
            ]
            entity_links = [
                link for link in episode_links
                if link.get("relationship") == "SHARED_ENTITY_ONLY"
            ]
            known_times = [
                parse_utc_timestamp(event.get("timestamp_utc"))
                for event in episode_events
            ]
            known_times = [value for value in known_times if value is not None]
            start_time = min(known_times).isoformat() if known_times else None
            end_time = max(known_times).isoformat() if known_times else None
            sources = sorted({str(event.get("source_type") or "unknown") for event in episode_events})
            shared_entities = {}
            for link in episode_links:
                for entity in link.get("shared_entities", []):
                    shared_entities[str(entity.get("entity_id") or entity.get("value"))] = entity
            link_types = sorted({str(link.get("relationship") or "association") for link in episode_links})
            episode_digest = hashlib.sha256(
                "|".join(sorted(episode_ids)).encode("utf-8")
            ).hexdigest()[:20]
            if shared_entities:
                connection_summary = f"{len(shared_entities)} shared identifier(s)"
            elif spatial_links:
                connection_summary = "spatial proximity"
            else:
                connection_summary = "temporal proximity only"
            if known_times and len(known_times) == len(episode_events):
                time_phrase = f"from {start_time} to {end_time}"
            elif known_times:
                time_phrase = (
                    f"with partial timestamp coverage (known observations from {start_time} to {end_time})"
                )
            else:
                time_phrase = "with incomplete timestamp coverage"
            episodes.append({
                "episode_id": f"EP-{episode_digest}",
                "case_id": episode_events[0].get("case_id") if episode_events else case_id,
                "event_count": len(episode_events),
                "start_time_utc": start_time,
                "end_time_utc": end_time,
                "sources": sources,
                "relationship_types": link_types,
                "temporal_association_count": len(temporal_links),
                "spatial_association_count": len(spatial_links),
                "entity_association_count": len(entity_links),
                "shared_entities": sorted(shared_entities.values(), key=lambda item: (
                    str(item.get("entity_type")), str(item.get("value"))
                )),
                "summary": (
                    f"{len(episode_events)} evidence events across {', '.join(sources)} {time_phrase}; "
                    f"grouped by {connection_summary}."
                ),
                "interpretation": (
                    "This is an evidence grouping based on the listed rules. It does not establish causation, "
                    "identity, intent, or guilt. Review the source records and acquisition hashes."
                ),
                "event_sequence": [_event_ref(event) for event in episode_events],
                "associations": episode_links,
            })

        episodes.sort(key=lambda episode: (
            episode["start_time_utc"] is None,
            episode["start_time_utc"] or "",
            episode["episode_id"],
        ))
        unlinked_events = [
            _event_ref(event)
            for event in sorted(
                (event for event_id, event in event_by_id.items() if event_id not in linked_ids),
                key=self._time_key,
            )
        ]
        return {
            "case_id": case_id,
            "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "analysis_parameters": {
                "temporal_window_seconds": temporal_window_seconds,
                "spatial_radius_meters": spatial_radius_meters,
                "spatial_time_window_seconds": spatial_time_window_seconds,
            },
            "input_event_count": len(all_events),
            "considered_event_count": len(selected_events),
            "truncated_events": len(all_events) > len(selected_events),
            "episode_count": len(episodes),
            "linked_event_count": len(linked_ids),
            "unlinked_event_count": len(unlinked_events),
            "temporal_association_count": temporal.get("total_correlations", 0),
            "spatial_association_count": spatial.get("total_spatial_correlations", 0),
            "entity_association_count": entity.get("total_entity_correlations", 0),
            "association_results_truncated": bool(
                temporal.get("truncated") or spatial.get("truncated")
                or entity.get("truncated")
            ),
            "episodes": episodes,
            "unlinked_events": unlinked_events,
            "method": (
                "Connected episodes are formed from explicit temporal-window, geographic-proximity, and shared-identifier "
                "associations. The event order is chronological when timestamps are available; shared-identifier links "
                "can include records without reliable times and remain investigative leads."
            ),
        }
