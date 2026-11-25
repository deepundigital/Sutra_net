"""
Forensic Knowledge Graph: Builds temporal multi-entity correlation graphs
from normalized evidence events while preserving source-record provenance.
"""

import hashlib
from typing import Any, Dict, Iterable, List, Optional

import networkx as nx

from sutra_net.evidence import EvidenceEvent, mobile_messages_to_events, pcap_flows_to_events
from sutra_net.evidence.events import canonical_entity_value


class ForensicKnowledgeGraph:
    """Constructs and queries a heterogeneous, provenance-aware evidence graph."""

    def __init__(self):
        # Parallel edges retain separate evidence records linking the same entities.
        self.graph = nx.MultiDiGraph()

    def add_entity(
        self,
        entity_id: str,
        entity_type: str,
        label: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Adds or enriches a graph node without discarding prior metadata."""
        if not entity_id:
            return
        node_id = str(entity_id).strip()
        if not node_id:
            return
        existing = self.graph.nodes[node_id] if self.graph.has_node(node_id) else {}
        merged_metadata = dict(existing.get("metadata") or {})
        merged_metadata.update(metadata or {})
        existing_type = existing.get("entity_type")
        # Keep a useful known type if a later source only has an unknown label.
        resolved_type = entity_type if entity_type != "unknown" or not existing_type else existing_type
        self.graph.add_node(
            node_id,
            entity_type=resolved_type,
            label=label or existing.get("label") or node_id,
            metadata=merged_metadata,
        )

    def add_relationship(
        self,
        source_id: str,
        target_id: str,
        relationship: str,
        timestamp: Optional[str] = None,
        weight: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
        edge_key: Optional[str] = None,
    ):
        """Adds a directed relationship; an explicit key makes ingestion idempotent."""
        if not source_id or not target_id:
            return
        s_id = str(source_id).strip()
        t_id = str(target_id).strip()
        if not self.graph.has_node(s_id):
            self.add_entity(s_id, "unknown", s_id)
        if not self.graph.has_node(t_id):
            self.add_entity(t_id, "unknown", t_id)

        self.graph.add_edge(
            s_id,
            t_id,
            key=edge_key,
            relationship=relationship,
            timestamp=timestamp,
            weight=weight,
            metadata=metadata or {},
        )

    @staticmethod
    def _event_dict(event: EvidenceEvent | Dict[str, Any]) -> Dict[str, Any]:
        return event.to_dict() if isinstance(event, EvidenceEvent) else dict(event)

    @staticmethod
    def _event_provenance(event: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "event_id": event.get("event_id"),
            "case_id": event.get("case_id"),
            "source_type": event.get("source_type"),
            "event_type": event.get("event_type"),
            "artifact_path": event.get("artifact_path"),
            "artifact_sha256": event.get("artifact_sha256"),
            "acquisition_record_id": event.get("acquisition_record_id"),
            "source_record_id": event.get("source_record_id"),
        }

    def ingest_events(self, events: Iterable[EvidenceEvent | Dict[str, Any]]) -> int:
        """Add normalized observations, source-record nodes, and semantic links."""
        ingested = 0
        for event_value in events:
            event = self._event_dict(event_value)
            event_id = str(event.get("event_id") or "").strip()
            if not event_id:
                continue
            case_id = str(event.get("case_id") or "UNASSIGNED")
            event_node = f"evidence_event:{event_id}"
            timestamp = event.get("timestamp_utc")
            provenance = self._event_provenance(event)
            self.add_entity(
                event_node,
                "evidence_event",
                label=f"{event.get('event_type', 'event')}: {event.get('source_record_id', event_id)}",
                metadata={"event": event, "provenance": provenance},
            )

            entities_by_role: Dict[str, List[tuple[str, str, Dict[str, Any]]]] = {}
            for entity in event.get("entities", []) or []:
                entity_type = str(entity.get("entity_type") or "unknown")
                value = str(entity.get("value") or "").strip()
                if not value:
                    continue
                canonical_id = str(entity.get("entity_id") or "")
                if not canonical_id:
                    canonical_id = f"{entity_type}:{canonical_entity_value(entity_type, value)}"
                role = str(entity.get("role") or "related")
                attributes = dict(entity.get("attributes") or {})

                display_type = entity_type
                if entity_type == "ip_address":
                    if role == "source":
                        display_type = "internal_host"
                    elif role == "destination":
                        threat = (event.get("details") or {}).get("triage", {})
                        display_type = "c2_server" if threat.get("is_malicious") else "external_ip"
                self.add_entity(
                    canonical_id,
                    display_type,
                    label=f"{display_type.replace('_', ' ').title()}: {value}",
                    metadata={
                        "value": value,
                        "canonical_id": canonical_id,
                        "attributes": attributes,
                        "case_id": case_id,
                    },
                )
                self.add_relationship(
                    event_node,
                    canonical_id,
                    relationship="INVOLVES",
                    timestamp=timestamp,
                    metadata={**provenance, "role": role, "entity_attributes": attributes},
                    edge_key=f"{event_id}:involves:{role}:{canonical_id}",
                )
                entities_by_role.setdefault(role, []).append((canonical_id, entity_type, attributes))

            details = event.get("details") or {}
            source_type = event.get("source_type")
            if source_type == "pcap":
                source = next((item[0] for item in entities_by_role.get("source", [])), None)
                destination = next((item[0] for item in entities_by_role.get("destination", [])), None)
                if source and destination:
                    triage = details.get("triage") or {}
                    is_malicious = bool(triage.get("is_malicious"))
                    self.add_relationship(
                        source,
                        destination,
                        relationship="C2_BEACON" if is_malicious else "NETWORK_FLOW",
                        timestamp=timestamp,
                        weight=3.0 if is_malicious else 1.0,
                        metadata={
                            **provenance,
                            "bytes": details.get("total_bytes"),
                            "protocol": details.get("protocol"),
                            "src_port": details.get("src_port"),
                            "dst_port": details.get("dst_port"),
                            "threat_type": triage.get("threat_type", "BENIGN"),
                            "is_malicious": is_malicious,
                        },
                        edge_key=f"{event_id}:network-flow",
                    )
            elif source_type == "mobile":
                sender = next((item[0] for item in entities_by_role.get("sender", [])), None)
                if sender:
                    for target, entity_type, _attributes in entities_by_role.get("recipient_account", []):
                        self.add_relationship(
                            sender,
                            target,
                            relationship="ASSOCIATED_UPI",
                            timestamp=timestamp,
                            weight=2.0,
                            metadata=provenance,
                            edge_key=f"{event_id}:upi:{target}",
                        )
                    for target, entity_type, _attributes in entities_by_role.get("mentioned_contact", []):
                        if entity_type == "phone_number" and target != sender:
                            self.add_relationship(
                                sender,
                                target,
                                relationship="CONTACTED",
                                timestamp=timestamp,
                                metadata=provenance,
                                edge_key=f"{event_id}:contact:{target}",
                            )
            ingested += 1
        return ingested

    def get_evidence_events(self, case_id: str | None = None) -> List[Dict[str, Any]]:
        """Return stored normalized events, optionally scoped to one case."""
        events = []
        for _node, data in self.graph.nodes(data=True):
            if data.get("entity_type") != "evidence_event":
                continue
            event = data.get("metadata", {}).get("event")
            if not isinstance(event, dict):
                continue
            if case_id and event.get("case_id") != case_id:
                continue
            events.append(event)
        return events

    def ingest_event_correlations(self, correlations: Iterable[Dict[str, Any]]) -> int:
        """Add derived event-to-event links while retaining the rule and source refs."""
        added = 0
        for correlation in correlations:
            event_refs = correlation.get("events") or []
            if len(event_refs) != 2:
                continue
            left_id = str(event_refs[0].get("event_id") or "").strip()
            right_id = str(event_refs[1].get("event_id") or "").strip()
            if not left_id or not right_id:
                continue
            source_node = f"evidence_event:{left_id}"
            target_node = f"evidence_event:{right_id}"
            if not self.graph.has_node(source_node) or not self.graph.has_node(target_node):
                continue
            relation = str(correlation.get("relationship") or "CORRELATED_WITH")
            rule_key = "|".join((
                str(correlation.get("correlation_id") or f"{left_id}:{right_id}"),
                relation,
                str(correlation.get("window_seconds", correlation.get("time_window_seconds", ""))),
                str(correlation.get("radius_meters", "")),
            ))
            edge_key = "derived:" + hashlib.sha256(rule_key.encode("utf-8")).hexdigest()
            self.add_relationship(
                source_node,
                target_node,
                relationship=relation,
                timestamp=event_refs[0].get("timestamp_utc"),
                metadata={
                    "derived": True,
                    "directionality": "chronological_display_only",
                    "correlation": correlation,
                },
                edge_key=edge_key,
            )
            added += 1
        return added

    def ingest_mobile_entities(
        self,
        analyzed_messages: List[Dict[str, Any]],
        *,
        case_id: str = "UNASSIGNED",
        artifact_path: str | None = None,
        artifact_sha256: str | None = None,
        acquisition_record_id: str | None = None,
    ):
        """Compatibility adapter for existing Chitra-NLP mobile output."""
        events = mobile_messages_to_events(
            analyzed_messages,
            case_id=case_id,
            artifact_path=artifact_path,
            artifact_sha256=artifact_sha256,
            acquisition_record_id=acquisition_record_id,
        )
        return self.ingest_events(events)

    def ingest_network_flows(
        self,
        flows: List[Dict[str, Any]],
        *,
        case_id: str = "UNASSIGNED",
        artifact_path: str | None = None,
        artifact_sha256: str | None = None,
        acquisition_record_id: str | None = None,
    ):
        """Compatibility adapter for raw or NetSpectra-triaged flow output."""
        events = pcap_flows_to_events(
            flows,
            case_id=case_id,
            artifact_path=artifact_path,
            artifact_sha256=artifact_sha256,
            acquisition_record_id=acquisition_record_id,
        )
        return self.ingest_events(events)

    def find_mule_accounts(self) -> List[Dict[str, Any]]:
        """Identify UPI accounts contacted by multiple distinct phone entities."""
        mules = []
        for node, node_data in self.graph.nodes(data=True):
            if node_data.get("entity_type") != "upi_vpa":
                continue
            senders = set()
            for source, _target, _key, edge_data in self.graph.in_edges(node, keys=True, data=True):
                if edge_data.get("relationship") == "ASSOCIATED_UPI":
                    if self.graph.nodes[source].get("entity_type") == "phone_number":
                        senders.add(source)
            sender_values = sorted(
                str(self.graph.nodes[sender].get("metadata", {}).get("value") or sender)
                for sender in senders
            )
            inbound_connections = len(senders)
            value = str(node_data.get("metadata", {}).get("value") or node)
            mules.append({
                "upi_vpa": value,
                "inbound_connections": inbound_connections,
                "connected_senders": sender_values,
                "risk_level": "CRITICAL_MULE" if inbound_connections >= 2 else "SUSPECT",
            })
        mules.sort(key=lambda item: item["inbound_connections"], reverse=True)
        return mules

    def to_cytoscape_json(self) -> Dict[str, Any]:
        """Convert the multigraph into Cytoscape.js elements with unique edge IDs."""
        elements = {"nodes": [], "edges": []}
        for node, data in self.graph.nodes(data=True):
            elements["nodes"].append({
                "data": {
                    "id": node,
                    "label": data.get("label", node),
                    "type": data.get("entity_type", "default"),
                    "metadata": data.get("metadata", {}),
                }
            })

        for source, target, key, data in self.graph.edges(keys=True, data=True):
            elements["edges"].append({
                "data": {
                    "id": f"{source}->{target}:{key}",
                    "source": source,
                    "target": target,
                    "label": data.get("relationship", ""),
                    "timestamp": data.get("timestamp"),
                    "weight": data.get("weight", 1.0),
                    "metadata": data.get("metadata", {}),
                }
            })

        return {
            "node_count": len(elements["nodes"]),
            "edge_count": len(elements["edges"]),
            "elements": elements,
        }
