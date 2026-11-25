document.addEventListener("DOMContentLoaded", () => {
  const DEMO_CASE_ID = "CASE-2026-SUTRAM-DEMO";

  // Tab Switching
  const navItems = document.querySelectorAll(".nav-item[data-tab]");
  const tabPanes = document.querySelectorAll(".tab-pane");

  navItems.forEach(item => {
    item.addEventListener("click", () => {
      const targetTab = item.getAttribute("data-tab");
      navItems.forEach(i => i.classList.remove("active"));
      tabPanes.forEach(p => p.classList.remove("active"));

      item.classList.add("active");
      const targetPane = document.getElementById(`tab-${targetTab}`);
      if (targetPane) targetPane.classList.add("active");

      if (targetTab === "network") loadNetworkTriage();
      if (targetTab === "mobile") loadMobileTriage();
      if (targetTab === "graph") {
        loadKnowledgeGraph();
        loadEvidenceTimeline();
        loadEvidenceCorrelations();
        loadSpatialCorrelations();
        loadEntityCorrelations();
        loadReconstruction();
      }
    });
  });

  // 1. Ingest Demo Evidence
  const btnIngest = document.getElementById("btn-ingest-samples");
  btnIngest.addEventListener("click", async () => {
    btnIngest.innerText = "⏳ Ingesting...";
    try {
      const res = await fetch("/api/ingest/sample", { method: "POST" });
      const data = await res.json();
      btnIngest.innerText = "✅ Evidence Ingested";
      setTimeout(() => btnIngest.innerText = "🚀 Ingest Demo Evidence", 3000);
      loadNetworkTriage();
      loadMobileTriage();
      loadKnowledgeGraph();
      loadEvidenceTimeline();
      loadEvidenceCorrelations();
      loadSpatialCorrelations();
      loadEntityCorrelations();
      loadReconstruction();
    } catch (err) {
      alert("Ingestion error: " + err);
      btnIngest.innerText = "🚀 Ingest Demo Evidence";
    }
  });

  // 2. Load Network Triage
  async function loadNetworkTriage() {
    const tbody = document.getElementById("flows-table-body");
    tbody.innerHTML = "<tr><td colspan='7'>Loading flow analysis...</td></tr>";
    try {
      const res = await fetch("/api/triage/network");
      const data = await res.json();
      tbody.innerHTML = "";

      document.getElementById("stat-malicious-count").innerText = `${data.malicious_count} C2 Beacon(s)`;

      data.flows.forEach(flow => {
        const isMal = flow.is_malicious;
        const badgeClass = isMal ? "badge-amber" : "badge";
        const tr = document.createElement("tr");
        if (isMal) tr.style.backgroundColor = "rgba(239, 68, 68, 0.08)";

        tr.innerHTML = `
          <td><code>${flow.flow_id}</code></td>
          <td>${flow.flow_details.packet_count}</td>
          <td>${flow.flow_details.mean_delta_sec}s</td>
          <td><code>${flow.flow_details.jitter_sec}s</code></td>
          <td><strong style="color: ${isMal ? '#EF4444' : '#10B981'}">${(flow.anomaly_score * 100).toFixed(1)}%</strong></td>
          <td><span class="badge ${badgeClass}">${flow.threat_type}</span></td>
          <td><small>${flow.mitre_technique || "None"}</small></td>
        `;
        tbody.appendChild(tr);
      });
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan='7'>Error loading flows: ${err}</td></tr>`;
    }
  }

  // 3. Load Mobile Triage
  async function loadMobileTriage() {
    const tbody = document.getElementById("mobile-table-body");
    tbody.innerHTML = "<tr><td colspan='6'>Loading mobile triage...</td></tr>";
    try {
      const res = await fetch("/api/triage/mobile");
      const data = await res.json();
      tbody.innerHTML = "";

      document.getElementById("stat-mobile-flagged").innerText = `${data.flagged_count} Extortions`;

      data.messages.forEach(msg => {
        const isFlagged = msg.is_flagged;
        const tr = document.createElement("tr");
        if (isFlagged) tr.style.backgroundColor = "rgba(245, 158, 11, 0.08)";

        const upis = msg.entities.upi_vpas.length ? msg.entities.upi_vpas.join("<br/>") : "None";
        tr.innerHTML = `
          <td><code>${msg.sender}</code></td>
          <td><small>${msg.timestamp || 'N/A'}</small></td>
          <td>${msg.text}</td>
          <td><code style="color: #F59E0B">${upis}</code></td>
          <td><span class="badge ${isFlagged ? 'badge-amber' : 'badge'}">${msg.fraud_analysis.primary_category}</span></td>
          <td><strong style="color: ${isFlagged ? '#EF4444' : '#10B981'}">${(msg.fraud_analysis.fraud_score * 100).toFixed(0)}%</strong></td>
        `;
        tbody.appendChild(tr);
      });
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan='6'>Error loading messages: ${err}</td></tr>`;
    }
  }

  // 4. Render Knowledge Graph with Cytoscape
  let cy = null;
  async function loadKnowledgeGraph() {
    try {
      const res = await fetch("/api/graph");
      const graphData = await res.json();

      const elements = [];
      graphData.elements.nodes.forEach(n => {
        let nodeColor = "#38BDF8";
        if (n.data.type === "c2_server") nodeColor = "#EF4444";
        if (n.data.type === "upi_vpa") nodeColor = "#F59E0B";
        if (n.data.type === "phone_number") nodeColor = "#10B981";
        if (n.data.type === "location") nodeColor = "#A78BFA";

        elements.push({
          data: { ...n.data, color: nodeColor }
        });
      });

      graphData.elements.edges.forEach(e => {
        elements.push({ data: e.data });
      });

      if (!cy) {
        cy = cytoscape({
          container: document.getElementById("cy-container"),
          elements: elements,
          style: [
            {
              selector: "node",
              style: {
                "background-color": "data(color)",
                "label": "data(label)",
                "color": "#F8FAFC",
                "font-size": "11px",
                "text-valign": "bottom",
                "text-margin-y": "6px",
                "width": 34,
                "height": 34
              }
            },
            {
              selector: "edge",
              style: {
                "width": 2,
                "line-color": "#475569",
                "target-arrow-color": "#475569",
                "target-arrow-shape": "triangle",
                "curve-style": "bezier",
                "label": "data(label)",
                "font-size": "9px",
                "color": "#94A3B8"
              }
            }
          ],
          layout: {
            name: "cose",
            animate: false,
            padding: 30
          }
        });
      } else {
        cy.json({ elements: elements });
        cy.layout({ name: "cose", animate: false }).run();
      }
    } catch (err) {
      console.error("Error loading graph:", err);
    }
  }

  function addTextCell(row, value) {
    const cell = document.createElement("td");
    cell.textContent = value == null || value === "" ? "—" : String(value);
    row.appendChild(cell);
  }

  function showTableMessage(tbody, columns, message) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = columns;
    cell.textContent = message;
    row.appendChild(cell);
    tbody.replaceChildren(row);
  }

  async function loadEvidenceTimeline() {
    const tbody = document.getElementById("timeline-table-body");
    const status = document.getElementById("timeline-status");
    if (!tbody || !status) return;
    status.textContent = "Loading evidence timeline…";
    try {
      const query = new URLSearchParams({ case_id: DEMO_CASE_ID, limit: "500" });
      const response = await fetch(`/api/timeline?${query}`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Timeline request failed");

      tbody.replaceChildren();
      if (!data.events.length) {
        showTableMessage(tbody, 4, "No evidence events yet. Ingest sample evidence first.");
      } else {
        data.events.forEach(event => {
          const row = document.createElement("tr");
          addTextCell(row, event.timestamp_utc || "Unknown (year/timezone unavailable)");
          addTextCell(row, event.source_type);
          addTextCell(row, event.source_record_id);
          addTextCell(row, event.summary);
          tbody.appendChild(row);
        });
      }
      status.textContent = `${data.returned_events} of ${data.total_events} evidence events. Timestamped rows are UTC ordered; records without reliable times follow them${data.truncated ? " (showing first 500)" : ""}.`;
    } catch (error) {
      showTableMessage(tbody, 4, `Could not load timeline: ${error.message}`);
      status.textContent = "Timeline unavailable.";
    }
  }

  async function loadEvidenceCorrelations() {
    const tbody = document.getElementById("correlation-table-body");
    const status = document.getElementById("correlation-status");
    if (!tbody || !status) return;
    status.textContent = "Finding cross-source events within 15 minutes…";
    try {
      const query = new URLSearchParams({
        case_id: DEMO_CASE_ID,
        window_seconds: "900",
        cross_source_only: "true",
        limit: "500"
      });
      const response = await fetch(`/api/correlations?${query}`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Correlation request failed");

      tbody.replaceChildren();
      if (!data.correlations.length) {
        showTableMessage(tbody, 5, "No cross-source event pairs fell within the selected time window.");
      } else {
        data.correlations.forEach(item => {
          const row = document.createElement("tr");
          addTextCell(row, item.relationship);
          addTextCell(row, item.overlapping_time_ranges ? "Overlapping" : `${item.time_gap_seconds}s`);
          addTextCell(row, item.shared_entities.map(entity => `${entity.entity_type}: ${entity.value}`).join(", ") || "None identified");
          addTextCell(row, item.events.map(event => `${event.source_type} / ${event.source_record_id}`).join(" ↔ "));
          addTextCell(row, item.interpretation);
          tbody.appendChild(row);
        });
      }
      status.textContent = `${data.returned_correlations} temporal association(s)${data.truncated ? " (results truncated)" : ""}. Time proximity is an investigative lead, not proof of causation.`;
    } catch (error) {
      showTableMessage(tbody, 5, `Could not load correlations: ${error.message}`);
      status.textContent = "Correlation analysis unavailable.";
    }
  }

  async function loadSpatialCorrelations() {
    const tbody = document.getElementById("spatial-table-body");
    const status = document.getElementById("spatial-status");
    if (!tbody || !status) return;
    status.textContent = "Finding location observations within 1 km and 1 hour…";
    try {
      const query = new URLSearchParams({
        case_id: DEMO_CASE_ID,
        radius_meters: "1000",
        time_window_seconds: "3600",
        cross_source_only: "false",
        limit: "500"
      });
      const response = await fetch(`/api/spatial-correlations?${query}`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Spatial correlation request failed");

      tbody.replaceChildren();
      if (!data.spatial_correlations.length) {
        showTableMessage(tbody, 6, "No location-bearing event pairs meet the selected distance and time limits.");
      } else {
        data.spatial_correlations.forEach(item => {
          const row = document.createElement("tr");
          const match = item.matched_locations[0];
          const left = match.left_location;
          const right = match.right_location;
          const coordinates = `${left.latitude.toFixed(5)}, ${left.longitude.toFixed(5)} ↔ ${right.latitude.toFixed(5)}, ${right.longitude.toFixed(5)}`;
          const accuracy = [left.accuracy_m, right.accuracy_m]
            .map(value => value == null ? "not supplied" : `${value} m`)
            .join(" / ");
          addTextCell(row, item.relationship);
          addTextCell(row, `${item.distance_meters} m`);
          addTextCell(row, item.overlapping_time_ranges ? "Overlapping" : `${item.time_gap_seconds}s`);
          addTextCell(row, coordinates);
          addTextCell(row, accuracy);
          addTextCell(row, item.events.map(event => `${event.source_type} / ${event.source_record_id}`).join(" ↔ "));
          tbody.appendChild(row);
        });
      }
      status.textContent = `${data.returned_spatial_correlations} spatial association(s). Coordinate proximity is a lead; review each source record and its reported accuracy.`;
    } catch (error) {
      showTableMessage(tbody, 6, `Could not load spatial associations: ${error.message}`);
      status.textContent = "Spatial analysis unavailable.";
    }
  }

  async function loadEntityCorrelations() {
    const tbody = document.getElementById("entity-correlation-table-body");
    const status = document.getElementById("entity-correlation-status");
    if (!tbody || !status) return;
    status.textContent = "Finding cross-source records with shared normalized identifiers…";
    try {
      const query = new URLSearchParams({
        case_id: DEMO_CASE_ID,
        cross_source_only: "true",
        limit: "500"
      });
      const response = await fetch(`/api/entity-correlations?${query}`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Entity correlation request failed");

      tbody.replaceChildren();
      if (!data.entity_correlations.length) {
        showTableMessage(tbody, 4, "No cross-source event pairs share a normalized identifier.");
      } else {
        data.entity_correlations.forEach(item => {
          const row = document.createElement("tr");
          addTextCell(row, item.relationship);
          addTextCell(row, item.shared_entities.map(entity => `${entity.entity_type}: ${entity.value}`).join(", "));
          addTextCell(row, item.events.map(event => `${event.source_type} / ${event.source_record_id}`).join(" ↔ "));
          addTextCell(row, item.interpretation);
          tbody.appendChild(row);
        });
      }
      status.textContent = `${data.returned_entity_correlations} shared-identifier association(s)${data.truncated ? " (results truncated)" : ""}. These links do not establish temporal sequence or causation.`;
    } catch (error) {
      showTableMessage(tbody, 4, `Could not load identifier links: ${error.message}`);
      status.textContent = "Identifier correlation unavailable.";
    }
  }

  function reconstructionQuery() {
    return new URLSearchParams({
      case_id: DEMO_CASE_ID,
      temporal_window_seconds: "900",
      spatial_radius_meters: "1000",
      spatial_time_window_seconds: "3600",
      limit: "2000"
    });
  }

  function appendReconstructionEvent(list, event) {
    const item = document.createElement("li");
    const heading = document.createElement("strong");
    heading.textContent = `${event.timestamp_utc || "Timestamp unavailable"} · ${event.source_type || "source"} · ${event.event_type || "event"}`;
    item.appendChild(heading);
    const summary = document.createElement("p");
    summary.textContent = event.summary || "Evidence event";
    item.appendChild(summary);
    const provenance = document.createElement("small");
    provenance.textContent = `Record ${event.source_record_id || "unknown"} · SHA-256 ${event.artifact_sha256 || "unavailable"} · acquisition ${event.acquisition_record_id || "unavailable"}`;
    item.appendChild(provenance);
    list.appendChild(item);
  }

  async function loadReconstruction() {
    const status = document.getElementById("reconstruction-status");
    const episodes = document.getElementById("reconstruction-episodes");
    const unlinkedDetails = document.getElementById("reconstruction-unlinked");
    const unlinkedSummary = document.getElementById("reconstruction-unlinked-summary");
    const unlinkedList = document.getElementById("reconstruction-unlinked-list");
    if (!status || !episodes || !unlinkedDetails || !unlinkedSummary || !unlinkedList) return;
    status.textContent = "Building evidence-linked episodes…";
    try {
      const response = await fetch(`/api/reconstruction?${reconstructionQuery()}`);
      const report = await response.json();
      if (!response.ok) throw new Error(report.detail || "Reconstruction request failed");
      episodes.replaceChildren();

      if (!report.episodes.length) {
        const empty = document.createElement("p");
        empty.className = "text-muted";
        empty.textContent = "No events met the configured association rules to form an episode.";
        episodes.appendChild(empty);
      }
      report.episodes.forEach(episode => {
        const card = document.createElement("article");
        card.className = "reconstruction-episode";
        const title = document.createElement("h3");
        title.textContent = `${episode.episode_id} · ${episode.event_count} events`;
        card.appendChild(title);
        const summary = document.createElement("p");
        summary.textContent = episode.summary;
        card.appendChild(summary);
        const meta = document.createElement("p");
        meta.className = "text-muted";
        meta.textContent = `Sources: ${episode.sources.join(", ")} · Associations: ${episode.relationship_types.join(", ") || "none"}`;
        card.appendChild(meta);

        const sequenceTitle = document.createElement("h4");
        sequenceTitle.textContent = "Chronological evidence sequence";
        card.appendChild(sequenceTitle);
        const sequence = document.createElement("ol");
        sequence.className = "reconstruction-event-list";
        episode.event_sequence.forEach(event => appendReconstructionEvent(sequence, event));
        card.appendChild(sequence);

        const links = document.createElement("details");
        const linksSummary = document.createElement("summary");
        linksSummary.textContent = `Why these events are grouped (${episode.associations.length} links)`;
        links.appendChild(linksSummary);
        const linkList = document.createElement("ul");
        episode.associations.forEach(link => {
          const row = document.createElement("li");
          const records = link.events.map(event => `${event.source_type} / ${event.source_record_id}`).join(" ↔ ");
          const signals = [
            link.time_gap_seconds == null ? null : `${link.time_gap_seconds}s apart`,
            link.distance_meters == null ? null : `${link.distance_meters}m apart`,
            ...(link.shared_entities || []).map(entity => `shared ${entity.entity_type}: ${entity.value}`)
          ].filter(Boolean).join("; ");
          row.textContent = `${link.relationship}: ${records}${signals ? ` · ${signals}` : ""}`;
          linkList.appendChild(row);
        });
        links.appendChild(linkList);
        const interpretation = document.createElement("p");
        interpretation.textContent = episode.interpretation;
        links.appendChild(interpretation);
        card.appendChild(links);
        episodes.appendChild(card);
      });

      unlinkedList.replaceChildren();
      report.unlinked_events.forEach(event => appendReconstructionEvent(unlinkedList, event));
      unlinkedDetails.hidden = report.unlinked_events.length === 0;
      unlinkedSummary.textContent = `Unlinked evidence (${report.unlinked_event_count})`;
      status.textContent = `${report.episode_count} episode(s), ${report.linked_event_count} linked events, ${report.unlinked_event_count} unlinked events. ${report.method}`;
      if (report.truncated_events || report.association_results_truncated) {
        status.textContent += " Results reached an analysis limit; increase the API limit or tighten the association windows.";
      }
    } catch (error) {
      episodes.textContent = `Could not build reconstruction: ${error.message}`;
      status.textContent = "Reconstruction unavailable.";
    }
  }

  document.getElementById("btn-export-reconstruction").addEventListener("click", async () => {
    const button = document.getElementById("btn-export-reconstruction");
    button.disabled = true;
    try {
      const response = await fetch(`/api/reconstruction?${reconstructionQuery()}`);
      const report = await response.json();
      if (!response.ok) throw new Error(report.detail || "Reconstruction export failed");
      const file = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(file);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `${DEMO_CASE_ID}-reconstruction.json`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      alert(`Could not export reconstruction: ${error.message}`);
    } finally {
      button.disabled = false;
    }
  });

  document.getElementById("btn-export-case-report").addEventListener("click", async () => {
    const button = document.getElementById("btn-export-case-report");
    const status = document.getElementById("case-report-status");
    button.disabled = true;
    if (status) status.textContent = "Preparing the full case report…";
    try {
      const query = new URLSearchParams({ case_id: DEMO_CASE_ID, limit: "2000" });
      const response = await fetch(`/api/case-report?${query}`);
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || "Case report export failed");
      }
      const file = await response.blob();
      const url = URL.createObjectURL(file);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `${DEMO_CASE_ID}-case-report.json`;
      anchor.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      if (status) status.textContent = "Case report downloaded. It includes audit status and automated leads for examiner review.";
    } catch (error) {
      if (status) status.textContent = `Could not export case report: ${error.message}`;
      else alert(`Could not export case report: ${error.message}`);
    } finally {
      button.disabled = false;
    }
  });

  document.getElementById("btn-refresh-timeline").addEventListener("click", () => {
    loadEvidenceTimeline();
    loadEvidenceCorrelations();
    loadSpatialCorrelations();
    loadEntityCorrelations();
    loadReconstruction();
  });

  // 5. Execute DuckDB SQL Query
  const btnRunSql = document.getElementById("btn-run-sql");
  btnRunSql.addEventListener("click", async () => {
    const query_id = document.getElementById("sql-query-input").value;
    const labelTime = document.getElementById("query-exec-time");
    labelTime.innerText = "Executing...";

    try {
      const res = await fetch("/api/query/sql", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query_id, limit: 20 })
      });
      const data = await res.json();

      if (!res.ok || !data.success) {
        labelTime.innerText = "Query failed";
        alert("Query failed: " + (data.error || data.detail || "Invalid request."));
        return;
      }

      labelTime.innerText = `⚡ Completed in ${data.execution_ms} ms (${data.row_count} rows)`;

      const thead = document.getElementById("sql-results-head");
      const tbody = document.getElementById("sql-results-body");
      thead.innerHTML = "";
      tbody.innerHTML = "";

      if (data.columns && data.columns.length) {
        const headerTr = document.createElement("tr");
        data.columns.forEach(col => {
          const th = document.createElement("th");
          th.innerText = col;
          headerTr.appendChild(th);
        });
        thead.appendChild(headerTr);

        data.data.forEach(row => {
          const tr = document.createElement("tr");
          data.columns.forEach(col => {
            const td = document.createElement("td");
            td.innerText = row[col] !== null ? row[col] : "NULL";
            tr.appendChild(td);
          });
          tbody.appendChild(tr);
        });
      }
    } catch (err) {
      labelTime.innerText = "Request failed";
      alert("SQL execution failed: " + err);
    }
  });

  // 6. Generate BSA Section 63 Certificate
  const btnCert = document.getElementById("btn-generate-cert");
  btnCert.addEventListener("click", async () => {
    btnCert.innerText = "⏳ Generating Courtroom Certificate...";
    const case_id = document.getElementById("cert-case-id").value;
    const examiner_name = document.getElementById("cert-examiner").value;
    const agency_name = document.getElementById("cert-agency").value;
    const artifact_name = document.getElementById("cert-artifact").value;

    try {
      const res = await fetch("/api/compliance/certificate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ case_id, examiner_name, agency_name, artifact_name })
      });
      const data = await res.json();
      btnCert.innerText = "✅ Certificate Issued";

      const container = document.getElementById("cert-download-container");
      container.innerHTML = `
        <div style="background: rgba(16, 185, 129, 0.15); border: 1px solid #10B981; padding: 12px; border-radius: 6px;">
          <p style="color: #10B981; font-weight: 600; margin-bottom: 6px;">
            Official BSA Section 63 Certificate Generated Successfully!
          </p>
          <a href="${data.pdf_download_url}" target="_blank" class="btn btn-emerald">
            📄 Download Official Section 63 PDF Certificate
          </a>
        </div>
      `;
    } catch (err) {
      alert("Certificate generation error: " + err);
      btnCert.innerText = "⚖️ Generate & Download Signed Section 63 PDF Certificate";
    }
  });

  // Trigger initial background load
  loadNetworkTriage();
  loadMobileTriage();
});
