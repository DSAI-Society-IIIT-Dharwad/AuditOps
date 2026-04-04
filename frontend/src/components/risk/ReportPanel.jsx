import { nodeDisplayLabel, nodeDisplayName, parseNodeId, severityForScore, toPercent } from "../../lib/reportUtils";

function formatRisk(value) {
  return Number(value || 0).toFixed(1);
}

export default function ReportPanel({ payload, selectedNodeId }) {
  const report = payload?.report || {};
  const metadata = report.metadata || {};
  const attackPaths = Array.isArray(report.attack_paths) ? report.attack_paths : [];
  const blastRows = Array.isArray(report.blast_radius_by_source) ? report.blast_radius_by_source : [];
  const cycles = Array.isArray(report.cycles) ? report.cycles : [];
  const criticalNodes = Array.isArray(report.critical_nodes) ? report.critical_nodes : [];
  const reportSummary = report.summary || {};
  const nodes = Array.isArray(payload?.nodes) ? payload.nodes : [];
  const nodeById = new Map(nodes.map((node) => [node.id, node]));

  const topCritical = criticalNodes[0] || null;
  const topCriticalParsed = parseNodeId(topCritical?.node_id || "");
  const maxRemoved = Math.max(1, ...criticalNodes.map((row) => Number(row.paths_removed || 0)));
  const selectedNode = nodeById.get(selectedNodeId || "") || null;

  const activeNode =
    selectedNode ||
    nodeById.get(topCritical?.node_id || "") ||
    nodes.find((node) => node.nvd_enriched) ||
    nodes[0] ||
    null;

  const activeNodeId = activeNode?.id || topCritical?.node_id || "";
  const activeNodeParsed = parseNodeId(activeNodeId);
  const activeNodeRisk = activeNode ? Number(activeNode.risk_score || 0) : Math.round(Number(topCritical?.paths_removed || 0) * 2.1);
  const activeNodeCves = Array.isArray(activeNode?.nvd_cve_ids) ? activeNode.nvd_cve_ids : [];
  const activeNodeImages = Array.isArray(activeNode?.nvd_image_refs) ? activeNode.nvd_image_refs : [];
  const activeNodeCvss = Number(activeNode?.nvd_max_cvss);
  const hasActiveNodeCvss = Number.isFinite(activeNodeCvss) && activeNodeCvss > 0;
  const hasNvdMetadata = Boolean(activeNode?.nvd_enriched);

  return (
    <aside className="report-panel">
      <section className="entity-focus">
        <div className="section-kicker">Selected Entity</div>
        <div className="entity-header">
          <div>
            <h2>{activeNodeParsed.name || topCriticalParsed.name || "No selected node"}</h2>
            <div className="entity-subline">
              {activeNodeParsed.entityType} | {activeNodeParsed.namespace}
            </div>
          </div>
          <div className="risk-pill">
            <div className="risk-pill-label">Risk</div>
            <div className="risk-pill-value">{formatRisk(activeNodeRisk)}</div>
          </div>
        </div>
        <div className="entity-meta-grid">
          <div className="entity-meta-item">
            <span>Cluster</span>
            <strong>{metadata.cluster || payload?.context?.cluster || "kind-hack2future"}</strong>
          </div>
          <div className="entity-meta-item">
            <span>Namespace</span>
            <strong>{metadata.namespace || payload?.context?.namespace || "all"}</strong>
          </div>
        </div>
        <div className="nvd-focus">
          <div className="nvd-focus-header">NVD Vulnerability Metadata</div>
          {!hasNvdMetadata && <div className="empty-state">No NVD metadata available for this node.</div>}
          {hasNvdMetadata && (
            <>
              <div className="nvd-focus-meta">
                <span>Source</span>
                <strong>{activeNode.nvd_source === "annotation" ? "Annotation" : "Live NVD"}</strong>
              </div>
              <div className="nvd-focus-meta">
                <span>Max CVSS</span>
                <strong>{hasActiveNodeCvss ? formatRisk(activeNodeCvss) : "N/A"}</strong>
              </div>
              {activeNodeImages.length > 0 && (
                <div className="nvd-focus-list">Images: {activeNodeImages.join(", ")}</div>
              )}
              {activeNodeCves.length > 0 && (
                <div className="nvd-chip-list">
                  {activeNodeCves.slice(0, 8).map((cveId) => (
                    <span className="nvd-chip" key={cveId}>
                      {cveId}
                    </span>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      </section>

      <section className="section-block">
        <h3>Section 1 - Attack Path Detection</h3>
        <div className="section-meta">{attackPaths.length} attack path(s) detected</div>
        <div className="path-list">
          {attackPaths.length === 0 && <div className="empty-state">No source-to-sink path detected.</div>}
          {attackPaths.map((path, index) => {
            const severity = path.severity || severityForScore(path.risk_score);
            return (
              <article className="path-card" key={`${path.source}-${path.target}-${index}`}>
                <div className="path-head">
                  <strong>Path #{index + 1}</strong>
                  <span>{path.hops || 0} hops</span>
                  <span>Risk {formatRisk(path.risk_score)} [{severity}]</span>
                </div>
                <div className="path-edges">
                  {(path.edges || []).map((edge, edgeIndex) => (
                    <div className="path-edge" key={`${edge.source}-${edge.target}-${edgeIndex}`}>
                      <span>{nodeDisplayLabel(edge.source)}</span>
                      <span className="path-arrow">--[{edge.relationship || "related_to"}]--&gt;</span>
                      <span>{nodeDisplayLabel(edge.target)}</span>
                      {edge.cve && typeof edge.cvss !== "undefined" && edge.cvss !== null && (
                        <span className="cve-chip">{edge.cve}, CVSS {formatRisk(edge.cvss)}</span>
                      )}
                    </div>
                  ))}
                </div>
              </article>
            );
          })}
        </div>
      </section>

      <section className="section-block">
        <h3>Section 2 - Blast Radius (BFS)</h3>
        <div className="blast-list">
          {blastRows.length === 0 && <div className="empty-state">No blast-radius rows available.</div>}
          {blastRows.map((row) => {
            const hops = row.hops || {};
            const hopKeys = Object.keys(hops).sort((a, b) => Number(a) - Number(b));
            return (
              <div className="blast-card" key={row.source}>
                <div className="blast-head">
                  <strong>{nodeDisplayName(row.source)}</strong>
                  <span>{row.count || 0} reachable resource(s)</span>
                </div>
                {hopKeys.map((hopKey) => (
                  <div className="blast-hop" key={`${row.source}-hop-${hopKey}`}>
                    <span>Hop {hopKey}:</span>
                    <span>{(hops[hopKey] || []).map((nodeId) => nodeDisplayName(nodeId)).join(", ") || "-"}</span>
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      </section>

      <section className="section-block">
        <h3>Section 3 - Circular Permission Detection</h3>
        <div className="section-meta">{cycles.length} cycle(s) detected</div>
        <div className="cycle-list">
          {cycles.length === 0 && <div className="empty-state">No directed cycle detected.</div>}
          {cycles.map((cycle, index) => (
            <div className="cycle-item" key={`cycle-${index}`}>
                Cycle #{index + 1}: {(cycle || []).map((nodeId) => nodeDisplayName(nodeId)).join(" <-> ")}
            </div>
          ))}
        </div>
      </section>

      <section className="section-block">
        <h3>Section 4 - Critical Node Analysis</h3>
        <div className="section-meta">Baseline attack paths: {report.baseline_attack_paths || 0}</div>
        {topCritical && (
          <div className="recommendation-block">
            Remove permission binding '{nodeDisplayName(topCritical.node_id)}' ({parseNodeId(topCritical.node_id).entityType}) to
            eliminate {topCritical.paths_removed || 0} path(s).
          </div>
        )}
        <div className="critical-list">
          {criticalNodes.length === 0 && <div className="empty-state">No critical node ranking available.</div>}
          {criticalNodes.map((row) => (
            <div className="critical-row" key={row.node_id}>
              <div className="critical-row-head">
                <span>{nodeDisplayName(row.node_id)}</span>
                <span>-{row.paths_removed || 0} paths</span>
              </div>
              <div className="critical-bar-track">
                <div className="critical-bar-fill" style={{ width: `${toPercent(row.paths_removed, maxRemoved)}%` }} />
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="section-block summary-block">
        <h3>Summary</h3>
        <div className="summary-grid">
          <div>
            <span>Attack paths found</span>
            <strong>{reportSummary.attack_paths_found || 0}</strong>
          </div>
          <div>
            <span>Circular permissions</span>
            <strong>{reportSummary.cycles_found || 0}</strong>
          </div>
          <div>
            <span>Total blast-radius nodes exposed</span>
            <strong>{reportSummary.blast_nodes_exposed || 0}</strong>
          </div>
          <div>
            <span>Critical node to remove</span>
            <strong>{nodeDisplayName(reportSummary.critical_node || "none")}</strong>
          </div>
        </div>
      </section>
    </aside>
  );
}
