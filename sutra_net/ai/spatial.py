"""Distance-based correlation for evidence events carrying coordinates."""

from __future__ import annotations

import datetime as dt
import math
from bisect import bisect_left, bisect_right
from typing import Any, Iterable, Mapping

from sutra_net.ai.correlation import parse_utc_timestamp
from sutra_net.evidence.events import EvidenceEvent

EARTH_RADIUS_METERS = 6_371_008.8


def _event_as_dict(event: EvidenceEvent | Mapping[str, Any]) -> dict[str, Any]:
    return event.to_dict() if isinstance(event, EvidenceEvent) else dict(event)


def _locations(event: Mapping[str, Any]) -> list[dict[str, Any]]:
    values = []
    for entity in event.get("entities", []) or []:
        if entity.get("entity_type") not in {"location", "geo_location"}:
            continue
        attributes = entity.get("attributes") or {}
        latitude = attributes.get("latitude")
        if latitude is None:
            latitude = attributes.get("lat")
        longitude = attributes.get("longitude")
        if longitude is None:
            longitude = attributes.get("lon")
        if longitude is None:
            longitude = attributes.get("lng")
        if latitude is None or longitude is None:
            try:
                latitude, longitude = (float(part.strip()) for part in str(entity.get("value", "")).split(",", 1))
            except (TypeError, ValueError):
                continue
        try:
            latitude = float(latitude)
            longitude = float(longitude)
        except (TypeError, ValueError):
            continue
        if not (math.isfinite(latitude) and math.isfinite(longitude)):
            continue
        if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
            continue
        values.append({
            "entity_id": entity.get("entity_id"),
            "latitude": latitude,
            "longitude": longitude,
            "accuracy_m": attributes.get("accuracy_m"),
            "method": attributes.get("method"),
        })

    if values:
        return values

    details = event.get("details") or {}
    raw = details.get("location")
    if isinstance(raw, Mapping):
        latitude = raw.get("latitude")
        if latitude is None:
            latitude = raw.get("lat")
        longitude = raw.get("longitude")
        if longitude is None:
            longitude = raw.get("lon")
        if longitude is None:
            longitude = raw.get("lng")
        try:
            latitude = float(latitude)
            longitude = float(longitude)
        except (TypeError, ValueError):
            return []
        if math.isfinite(latitude) and math.isfinite(longitude) and -90 <= latitude <= 90 and -180 <= longitude <= 180:
            return [{
                "entity_id": None,
                "latitude": latitude,
                "longitude": longitude,
                "accuracy_m": raw.get("accuracy_m"),
                "method": raw.get("method") or "structured_record",
            }]
    return []


def _distance_meters(left: Mapping[str, Any], right: Mapping[str, Any]) -> float:
    lat1, lon1 = math.radians(left["latitude"]), math.radians(left["longitude"])
    lat2, lon2 = math.radians(right["latitude"]), math.radians(right["longitude"])
    delta_lat = lat2 - lat1
    delta_lon = lon2 - lon1
    haversine = (
        math.sin(delta_lat / 2) ** 2
        + math.cos(lat1) * math.cos(lat2) * math.sin(delta_lon / 2) ** 2
    )
    return 2 * EARTH_RADIUS_METERS * math.asin(min(1.0, math.sqrt(haversine)))


def _summary(event: Mapping[str, Any]) -> str:
    details = event.get("details") or {}
    if event.get("source_type") == "pcap":
        source = details.get("src_ip", "?")
        destination = details.get("dst_ip", "?")
        return f"Network flow {source} → {destination}"
    if event.get("source_type") == "mobile":
        text = " ".join(str(details.get("text") or "").split())
        return text[:180] + ("…" if len(text) > 180 else "") if text else "Mobile message"
    return str(details.get("summary") or event.get("event_type") or "Evidence event")[:180]


def _time_gap(
    left_start: dt.datetime | None,
    left_end: dt.datetime | None,
    right_start: dt.datetime | None,
    right_end: dt.datetime | None,
) -> tuple[float | None, bool]:
    if None in (left_start, left_end, right_start, right_end):
        return None, False
    assert left_start is not None and left_end is not None
    assert right_start is not None and right_end is not None
    overlapping = max(left_start, right_start) <= min(left_end, right_end)
    if overlapping:
        return 0.0, True
    if left_end < right_start:
        return (right_start - left_end).total_seconds(), False
    return (left_start - right_end).total_seconds(), False


def _spatial_pair(
    case_id: str,
    left_item: Mapping[str, Any],
    right_item: Mapping[str, Any],
    radius: float,
    window: int | None,
) -> dict[str, Any] | None:
    left = left_item["event"]
    right = right_item["event"]
    gap, overlapping = _time_gap(
        left_item["start"], left_item["end"],
        right_item["start"], right_item["end"],
    )
    if window is not None and (gap is None or gap > window):
        return None

    location_matches = []
    for left_location in left_item["locations"]:
        for right_location in right_item["locations"]:
            distance = _distance_meters(left_location, right_location)
            if distance <= radius:
                location_matches.append({
                    "distance_meters": round(distance, 2),
                    "left_location": left_location,
                    "right_location": right_location,
                })
    if not location_matches:
        return None

    location_matches.sort(key=lambda item: item["distance_meters"])
    closest = location_matches[0]
    relationship = "SPATIOTEMPORAL_ASSOCIATION" if window is not None else "SPATIAL_PROXIMITY"
    return {
        "correlation_id": "|".join(sorted((
            str(left.get("event_id") or left.get("source_record_id") or ""),
            str(right.get("event_id") or right.get("source_record_id") or ""),
        ))),
        "case_id": case_id,
        "relationship": relationship,
        "basis": ["spatial_proximity"] + (["time_window"] if window is not None else []),
        "radius_meters": radius,
        "distance_meters": closest["distance_meters"],
        "location_match_count": len(location_matches),
        "matched_locations": location_matches,
        "time_gap_seconds": round(gap, 3) if gap is not None else None,
        "overlapping_time_ranges": overlapping,
        "time_window_seconds": window,
        "interpretation": (
            f"Location observations are within {radius:g} m"
            + (f" and within {window} seconds." if window is not None else "; no temporal limit was applied.")
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
    }


class SpatialCorrelationEngine:
    """Find same-case evidence events observed near each other geographically."""

    def correlate(
        self,
        events: Iterable[EvidenceEvent | Mapping[str, Any]],
        *,
        case_id: str | None = None,
        radius_meters: float = 1_000,
        time_window_seconds: int | None = 3_600,
        cross_source_only: bool = True,
        limit: int = 500,
    ) -> dict[str, Any]:
        radius = max(0.0, float(radius_meters))
        window = max(0, int(time_window_seconds)) if time_window_seconds is not None else None
        safe_limit = max(1, int(limit))
        by_case: dict[str, list[dict[str, Any]]] = {}
        for event_value in events:
            event = _event_as_dict(event_value)
            current_case = str(event.get("case_id") or "UNASSIGNED")
            if case_id and current_case != case_id:
                continue
            locations = _locations(event)
            if not locations:
                continue
            start = parse_utc_timestamp(event.get("timestamp_utc"))
            details = event.get("details") or {}
            end = parse_utc_timestamp(details.get("end_time")) or start
            if start and end and end < start:
                start, end = end, start
            if window is not None and (start is None or end is None):
                continue
            event["summary"] = _summary(event)
            by_case.setdefault(current_case, []).append({
                "event": event,
                "locations": locations,
                "start": start,
                "end": end,
            })

        candidates: list[dict[str, Any]] = []
        comparisons = 0
        comparison_cap = max(50_000, safe_limit * 100)
        comparison_truncated = False
        for current_case, case_events in by_case.items():
            case_events.sort(key=lambda item: (
                item["start"] is None,
                item["start"] or dt.datetime.max.replace(tzinfo=dt.timezone.utc),
                str(item["event"].get("event_id") or ""),
            ))
            source_groups: dict[str, list[tuple[int, dict[str, Any]]]] = {}
            for event_index, event_item in enumerate(case_events):
                source = str(event_item["event"].get("source_type") or "unknown")
                source_groups.setdefault(source, []).append((event_index, event_item))
            if cross_source_only and len(source_groups) < 2:
                continue
            source_times = {
                source: [item[1]["start"] for item in items]
                for source, items in source_groups.items()
            }

            for left_index, left_item in enumerate(case_events):
                left = left_item["event"]
                if window is not None and (left_item["start"] is None or left_item["end"] is None):
                    continue
                left_source = str(left.get("source_type") or "unknown")
                for source, rows in source_groups.items():
                    if cross_source_only and source == left_source:
                        continue
                    times = source_times[source]
                    if window is not None:
                        begin = bisect_left(times, left_item["start"])
                        finish = bisect_right(
                            times,
                            left_item["end"] + dt.timedelta(seconds=window),
                        )
                    else:
                        begin, finish = 0, len(rows)
                    for position in range(begin, finish):
                        right_index, right_item = rows[position]
                        if right_index <= left_index:
                            continue
                        comparisons += 1
                        if comparisons > comparison_cap:
                            comparison_truncated = True
                            break
                        candidate = _spatial_pair(
                            current_case, left_item, right_item, radius, window
                        )
                        if candidate:
                            candidates.append(candidate)
                    if comparison_truncated:
                        break
                if comparison_truncated:
                    break
            if comparison_truncated:
                break

        candidates.sort(key=lambda item: (
            item["distance_meters"],
            item["time_gap_seconds"] if item["time_gap_seconds"] is not None else float("inf"),
            item["correlation_id"],
        ))
        return {
            "case_id": case_id,
            "radius_meters": radius,
            "time_window_seconds": window,
            "cross_source_only": cross_source_only,
            "total_spatial_correlations": len(candidates),
            "returned_spatial_correlations": min(len(candidates), safe_limit),
            "truncated": len(candidates) > safe_limit or comparison_truncated,
            "comparison_cap_reached": comparison_truncated,
            "count_is_partial": comparison_truncated,
            "spatial_correlations": candidates[:safe_limit],
        }
