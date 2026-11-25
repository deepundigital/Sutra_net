"""Timeline ordering and explainable, time-bounded evidence associations."""

from __future__ import annotations

import datetime as dt
from bisect import bisect_left, bisect_right
from typing import Any, Iterable, Mapping

from sutra_net.evidence.events import EvidenceEvent, canonical_entity_value


def parse_utc_timestamp(value: Any) -> dt.datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        seconds = float(value)
        if seconds > 100_000_000_000:
            seconds /= 1000.0
        try:
            return dt.datetime.fromtimestamp(seconds, tz=dt.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            return parse_utc_timestamp(float(text))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _event_entities(event: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    entities: dict[str, dict[str, Any]] = {}
    for entity in event.get("entities", []) or []:
        entity_type = str(entity.get("entity_type") or "unknown")
        value = str(entity.get("value") or "").strip()
        if not value:
            continue
        entity_id = str(entity.get("entity_id") or "").strip()
        if not entity_id:
            entity_id = f"{entity_type}:{canonical_entity_value(entity_type, value)}"
        entities[entity_id] = {
            "entity_id": entity_id,
            "entity_type": entity_type,
            "value": value,
            "role": entity.get("role"),
        }
    return entities


def _event_summary(event: Mapping[str, Any]) -> str:
    details = event.get("details") or {}
    if event.get("source_type") == "pcap":
        source = details.get("src_ip", "?")
        destination = details.get("dst_ip", "?")
        protocol = details.get("protocol") or "network"
        if details.get("src_port") is not None and details.get("dst_port") is not None:
            route = f"{source}:{details['src_port']} → {destination}:{details['dst_port']}"
        else:
            route = f"{source} → {destination}"
        return f"{route} ({protocol})"
    if event.get("source_type") == "mobile":
        text = " ".join(str(details.get("text") or "").split())
        return text[:180] + ("…" if len(text) > 180 else "") if text else "Mobile message"
    return str(details.get("message") or details.get("summary") or event.get("event_type") or "Evidence event")[:180]


class EvidenceCorrelationEngine:
    """Create a case timeline and explain why nearby event pairs were surfaced."""

    @staticmethod
    def _event_key(event: Mapping[str, Any]) -> str:
        return str(event.get("event_id") or event.get("source_record_id") or "")

    @staticmethod
    def _as_dict(event: EvidenceEvent | Mapping[str, Any]) -> dict[str, Any]:
        return event.to_dict() if isinstance(event, EvidenceEvent) else dict(event)

    def build_timeline(
        self,
        events: Iterable[EvidenceEvent | Mapping[str, Any]],
        *,
        case_id: str | None = None,
        source_type: str | None = None,
        start: dt.datetime | None = None,
        end: dt.datetime | None = None,
        limit: int = 500,
    ) -> dict[str, Any]:
        """Return chronological events with a compact, source-aware summary."""
        start_utc = parse_utc_timestamp(start) if start else None
        end_utc = parse_utc_timestamp(end) if end else None
        if start_utc and end_utc and start_utc > end_utc:
            raise ValueError("start must be earlier than or equal to end")

        selected = []
        for event_value in events:
            event = self._as_dict(event_value)
            if case_id and event.get("case_id") != case_id:
                continue
            if source_type and event.get("source_type") != source_type:
                continue
            timestamp = parse_utc_timestamp(event.get("timestamp_utc"))
            if start_utc and (timestamp is None or timestamp < start_utc):
                continue
            if end_utc and (timestamp is None or timestamp > end_utc):
                continue
            event["summary"] = _event_summary(event)
            selected.append((timestamp, event))

        selected.sort(key=lambda item: (
            item[0] is None,
            item[0] or dt.datetime.max.replace(tzinfo=dt.timezone.utc),
            self._event_key(item[1]),
        ))
        ordered = [event for _timestamp, event in selected]
        safe_limit = max(1, int(limit))
        return {
            "case_id": case_id,
            "total_events": len(ordered),
            "returned_events": min(len(ordered), safe_limit),
            "truncated": len(ordered) > safe_limit,
            "events": ordered[:safe_limit],
        }

    def correlate(
        self,
        events: Iterable[EvidenceEvent | Mapping[str, Any]],
        *,
        case_id: str | None = None,
        window_seconds: int = 900,
        cross_source_only: bool = True,
        limit: int = 500,
    ) -> dict[str, Any]:
        """Surface same-case event pairs within a temporal window.

        Results distinguish shared-entity evidence from time proximity alone;
        neither relationship implies causation.
        """
        window = max(1, int(window_seconds))
        safe_limit = max(1, int(limit))
        by_case: dict[str, list[tuple[dt.datetime, dt.datetime, dict[str, Any]]]] = {}
        for event_value in events:
            event = self._as_dict(event_value)
            current_case = str(event.get("case_id") or "UNASSIGNED")
            if case_id and current_case != case_id:
                continue
            starts = parse_utc_timestamp(event.get("timestamp_utc"))
            if starts is None:
                continue
            details = event.get("details") or {}
            ends = parse_utc_timestamp(details.get("end_time")) or starts
            if ends < starts:
                starts, ends = ends, starts
            event["summary"] = _event_summary(event)
            by_case.setdefault(current_case, []).append((starts, ends, event))

        candidates: list[dict[str, Any]] = []
        comparisons = 0
        comparison_cap = max(50_000, safe_limit * 100)
        comparison_truncated = False
        for current_case, case_events in by_case.items():
            case_events.sort(key=lambda item: (item[0], self._event_key(item[2])))
            source_groups: dict[str, list[tuple[int, tuple[dt.datetime, dt.datetime, dict[str, Any]]]]] = {}
            for event_index, event_row in enumerate(case_events):
                source = str(event_row[2].get("source_type") or "unknown")
                source_groups.setdefault(source, []).append((event_index, event_row))
            source_times = {
                source: [row[1][0] for row in rows]
                for source, rows in source_groups.items()
            }

            for left_index, (left_start, left_end, left) in enumerate(case_events):
                left_entities = _event_entities(left)
                for source, rows in source_groups.items():
                    if cross_source_only and source == str(left.get("source_type") or "unknown"):
                        continue
                    times = source_times[source]
                    begin = bisect_left(times, left_start)
                    finish = bisect_right(times, left_end + dt.timedelta(seconds=window))
                    for position in range(begin, finish):
                        right_index, (right_start, right_end, right) = rows[position]
                        if right_index <= left_index:
                            continue
                        comparisons += 1
                        if comparisons > comparison_cap:
                            comparison_truncated = True
                            break

                        overlapping = max(left_start, right_start) <= min(left_end, right_end)
                        if overlapping:
                            gap = 0.0
                        elif left_end < right_start:
                            gap = (right_start - left_end).total_seconds()
                        else:
                            gap = (left_start - right_end).total_seconds()
                        if gap > window:
                            continue

                        right_entities = _event_entities(right)
                        shared_ids = sorted(set(left_entities).intersection(right_entities))
                        shared_entities = [left_entities[entity_id] for entity_id in shared_ids]
                        basis = ["time_window"]
                        if shared_entities:
                            basis.append("shared_entity")
                        candidates.append({
                            "correlation_id": "|".join(sorted((self._event_key(left), self._event_key(right)))),
                            "case_id": current_case,
                            "relationship": "SHARED_ENTITY_AND_TIME" if shared_entities else "TEMPORAL_PROXIMITY",
                            "basis": basis,
                            "shared_entities": shared_entities,
                            "time_gap_seconds": round(gap, 3),
                            "overlapping_time_ranges": overlapping,
                            "window_seconds": window,
                            "interpretation": (
                                "Events share one or more normalized entities and fall within the selected time window."
                                if shared_entities
                                else "Events fall within the selected time window; no shared entity was identified."
                            ),
                            "events": [
                                {
                                    "event_id": left.get("event_id"),
                                    "source_type": left.get("source_type"),
                                    "event_type": left.get("event_type"),
                                    "timestamp_utc": left.get("timestamp_utc"),
                                    "artifact_path": left.get("artifact_path"),
                                    "source_record_id": left.get("source_record_id"),
                                    "acquisition_record_id": left.get("acquisition_record_id"),
                                    "artifact_sha256": left.get("artifact_sha256"),
                                    "summary": left.get("summary"),
                                },
                                {
                                    "event_id": right.get("event_id"),
                                    "source_type": right.get("source_type"),
                                    "event_type": right.get("event_type"),
                                    "timestamp_utc": right.get("timestamp_utc"),
                                    "artifact_path": right.get("artifact_path"),
                                    "source_record_id": right.get("source_record_id"),
                                    "acquisition_record_id": right.get("acquisition_record_id"),
                                    "artifact_sha256": right.get("artifact_sha256"),
                                    "summary": right.get("summary"),
                                },
                            ],
                        })
                    if comparison_truncated:
                        break
                if comparison_truncated:
                    break
            if comparison_truncated:
                break

        candidates.sort(key=lambda item: (
            -len(item["shared_entities"]),
            item["time_gap_seconds"],
            item["correlation_id"],
        ))
        return {
            "case_id": case_id,
            "window_seconds": window,
            "cross_source_only": cross_source_only,
            "total_correlations": len(candidates),
            "returned_correlations": min(len(candidates), safe_limit),
            "truncated": len(candidates) > safe_limit or comparison_truncated,
            "comparison_cap_reached": comparison_truncated,
            "count_is_partial": comparison_truncated,
            "correlations": candidates[:safe_limit],
        }

    def correlate_shared_entities(
        self,
        events: Iterable[EvidenceEvent | Mapping[str, Any]],
        *,
        case_id: str | None = None,
        cross_source_only: bool = True,
        limit: int = 500,
    ) -> dict[str, Any]:
        """Link same-case events by identifiers, including records without usable times."""
        safe_limit = max(1, int(limit))
        comparison_cap = max(50_000, safe_limit * 100)
        event_by_id: dict[str, dict[str, Any]] = {}
        entity_events: dict[tuple[str, str], list[str]] = {}
        entity_values: dict[str, dict[str, Any]] = {}

        for event_value in events:
            event = self._as_dict(event_value)
            current_case = str(event.get("case_id") or "UNASSIGNED")
            if case_id and current_case != case_id:
                continue
            event_id = str(event.get("event_id") or "")
            if not event_id:
                continue
            event_by_id[event_id] = event
            for entity_id, entity in _event_entities(event).items():
                entity_events.setdefault((current_case, entity_id), []).append(event_id)
                entity_values[entity_id] = entity

        pair_entities: dict[tuple[str, str], set[str]] = {}
        comparisons = 0
        comparison_truncated = False
        for (_current_case, entity_id), event_ids in entity_events.items():
            unique_ids = sorted(set(event_ids))
            if cross_source_only:
                source_groups: dict[str, list[str]] = {}
                for event_id in unique_ids:
                    source = str(event_by_id[event_id].get("source_type") or "unknown")
                    source_groups.setdefault(source, []).append(event_id)
                source_names = sorted(source_groups)
                pair_iter = (
                    (left_id, right_id)
                    for index, left_source in enumerate(source_names)
                    for right_source in source_names[index + 1:]
                    for left_id in source_groups[left_source]
                    for right_id in source_groups[right_source]
                )
            else:
                pair_iter = (
                    (unique_ids[left_index], unique_ids[right_index])
                    for left_index in range(len(unique_ids))
                    for right_index in range(left_index + 1, len(unique_ids))
                )
            for first_id, second_id in pair_iter:
                left_id, right_id = sorted((first_id, second_id))
                pair = (left_id, right_id)
                if pair not in pair_entities:
                    comparisons += 1
                    if comparisons > comparison_cap:
                        comparison_truncated = True
                        break
                    pair_entities[pair] = set()
                pair_entities[pair].add(entity_id)
            if comparison_truncated:
                break

        candidates = []
        for (left_id, right_id), shared_ids in pair_entities.items():
            left = event_by_id[left_id]
            right = event_by_id[right_id]
            left["summary"] = _event_summary(left)
            right["summary"] = _event_summary(right)
            candidates.append({
                "correlation_id": "|".join((left_id, right_id)),
                "case_id": left.get("case_id"),
                "relationship": "SHARED_ENTITY_ONLY",
                "basis": ["shared_entity"],
                "shared_entities": [entity_values[key] for key in sorted(shared_ids)],
                "time_gap_seconds": None,
                "overlapping_time_ranges": None,
                "interpretation": (
                    "Events share one or more normalized identifiers. One or both timestamps may be unknown; "
                    "this identifier link does not establish temporal sequence or causation."
                ),
                "events": [
                    {
                        "event_id": event.get("event_id"),
                        "source_type": event.get("source_type"),
                        "event_type": event.get("event_type"),
                        "timestamp_utc": event.get("timestamp_utc"),
                        "artifact_path": event.get("artifact_path"),
                        "source_record_id": event.get("source_record_id"),
                        "acquisition_record_id": event.get("acquisition_record_id"),
                        "artifact_sha256": event.get("artifact_sha256"),
                        "summary": event.get("summary"),
                    }
                    for event in (left, right)
                ],
            })
        candidates.sort(key=lambda item: (
            -len(item["shared_entities"]),
            item["correlation_id"],
        ))
        return {
            "case_id": case_id,
            "cross_source_only": cross_source_only,
            "total_entity_correlations": len(candidates),
            "returned_entity_correlations": min(len(candidates), safe_limit),
            "truncated": len(candidates) > safe_limit or comparison_truncated,
            "comparison_cap_reached": comparison_truncated,
            "count_is_partial": comparison_truncated,
            "entity_correlations": candidates[:safe_limit],
        }
