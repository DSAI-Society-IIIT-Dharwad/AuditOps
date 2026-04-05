import { useMemo, useState } from "react";

import { useAnalysis } from "../app/AnalysisProvider";
import { nodeDisplayName } from "../lib/reportUtils";

export default function RisksPage() {
  const {
    namespace,
    setNamespace,
    includeClusterRbac,
    setIncludeClusterRbac,
    enableNvdScoring,
    setEnableNvdScoring,
    payload,
    loading,
    error,
    refreshAnalysis,
  } = useAnalysis();

  const [pathQuery, setPathQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [criticalNodeQuery, setCriticalNodeQuery] = useState("");

  const report = useMemo(() => payload?.report || {}, [payload]);
  const temporal = useMemo(() => payload?.temporal || report?.temporal || {}, [payload, report]);
  const criticalNodes = Array.isArray(report.critical_nodes) ? report.critical_nodes : [];
  const attackPaths = Array.isArray(report.attack_paths) ? report.attack_paths : [];

  const topPaths = useMemo(() => {
    const normalizedQuery = pathQuery.trim().toLowerCase();

    return [...attackPaths]
      .sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0))
      .filter((path) => {
        const severity = String(path.severity || "LOW").toUpperCase();
        if (severityFilter !== "ALL" && severity !== severityFilter) {
          return false;
        }
        if (!normalizedQuery) {
          return true;
        }

        const queryText = [
          nodeDisplayName(path.source),
          nodeDisplayName(path.target),
          String(path.source || ""),
          String(path.target || ""),
        ]
          .join(" ")
          .toLowerCase();
        return queryText.includes(normalizedQuery);
      })
      .slice(0, 10);
  }, [attackPaths, pathQuery, severityFilter]);

  const filteredCriticalNodes = useMemo(() => {
    const normalizedQuery = criticalNodeQuery.trim().toLowerCase();

    return [...criticalNodes]
      .sort((a, b) => Number(b.paths_removed || 0) - Number(a.paths_removed || 0))
      .filter((row) => {
        if (!normalizedQuery) {
          return true;
        }
        return nodeDisplayName(row.node_id).toLowerCase().includes(normalizedQuery);
      });
  }, [criticalNodeQuery, criticalNodes]);

  const onExportRiskCsv = () => {
    if (topPaths.length === 0) {
      return;
    }

    const rows = [
      ["source", "target", "hops", "risk_score", "severity"],
      ...topPaths.map((path) => [
        nodeDisplayName(path.source),
        nodeDisplayName(path.target),
        Number(path.hops || 0),
        Number(path.risk_score || 0).toFixed(1),
        String(path.severity || "LOW").toUpperCase(),
      ]),
    ];

    const csv = rows
      .map((row) => row.map((value) => `"${String(value).replaceAll('"', '""')}"`).join(","))
      .join("\n");

    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const safeNamespace = (namespace || "all").trim().replace(/[^a-zA-Z0-9-_]/g, "_") || "all";
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `risk-paths-${safeNamespace}.csv`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  return (
    <section>
      <h2 className="page-title">Risk Center</h2>
      <div className="card controls-row" style={{ marginBottom: 14 }}>
        <label htmlFor="risk-namespace" style={{ marginRight: 8, fontSize: 12, color: "var(--muted)" }}>
          Namespace
        </label>
        <input
          id="risk-namespace"
          value={namespace}
          onChange={(event) => setNamespace(event.target.value)}
          style={{ marginRight: 10 }}
        />
        <label style={{ fontSize: 12, color: "var(--muted)" }}>
          <input
            type="checkbox"
            checked={includeClusterRbac}
            onChange={(event) => setIncludeClusterRbac(event.target.checked)}
          />{" "}
          Include cluster RBAC
        </label>
        <label style={{ fontSize: 12, color: "var(--muted)" }}>
          <input
            type="checkbox"
            checked={enableNvdScoring}
            onChange={(event) => setEnableNvdScoring(event.target.checked)}
          />{" "}
          Enable live NVD scoring
        </label>
        <button
          onClick={() => refreshAnalysis({ namespace, includeClusterRbac, enableNvdScoring })}
          disabled={loading || !namespace.trim()}
          className="risk-load-button"
        >
          {loading ? "Loading..." : "Load Risks"}
        </button>

        <div className="control-group compact">
          <label htmlFor="risk-severity-filter">Severity</label>
          <select
            id="risk-severity-filter"
            value={severityFilter}
            onChange={(event) => setSeverityFilter(event.target.value)}
          >
            <option value="ALL">All</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>

        <div className="control-group">
          <label htmlFor="risk-path-query">Path search</label>
          <input
            id="risk-path-query"
            value={pathQuery}
            onChange={(event) => setPathQuery(event.target.value)}
            placeholder="source or target"
          />
        </div>

        <div className="control-group">
          <label htmlFor="risk-critical-query">Critical node search</label>
          <input
            id="risk-critical-query"
            value={criticalNodeQuery}
            onChange={(event) => setCriticalNodeQuery(event.target.value)}
            placeholder="node name"
          />
        </div>

        <button type="button" onClick={onExportRiskCsv} disabled={topPaths.length === 0}>
          Export Paths CSV
        </button>
      </div>

      {error && (
        <div className="card error-panel" role="alert">
          <div className="error-title">{error.title}</div>
          <div className="error-text">{error.message}</div>
          {error.hint && <div className="error-hint">{error.hint}</div>}
        </div>
      )}

      <div className="grid grid-2">
        <div className="grid" style={{ gap: 12 }}>
          <div className="card">
            <div style={{ fontSize: 12, color: "var(--muted)", textTransform: "uppercase", marginBottom: 8 }}>
              Highest Risk Attack Paths
            </div>
            <div style={{ color: "var(--muted)", fontSize: 11, marginBottom: 8 }}>
              Showing {topPaths.length} path(s)
            </div>
            {topPaths.length === 0 && <div style={{ color: "var(--muted)" }}>No source-to-sink path detected.</div>}
            {topPaths.map((path, index) => (
              <div key={`${path.source}-${path.target}-${index}`} style={{ marginBottom: 10, fontSize: 13 }}>
                <div>
                  {nodeDisplayName(path.source)} -&gt; {nodeDisplayName(path.target)}
                </div>
                <div style={{ color: "var(--muted)", fontSize: 12 }}>
                  Hops: {path.hops || 0} | Score: {Number(path.risk_score || 0).toFixed(1)} | Severity: {path.severity || "LOW"}
                </div>
              </div>
            ))}
          </div>

          <div className="card">
            <div style={{ fontSize: 12, color: "var(--muted)", textTransform: "uppercase", marginBottom: 8 }}>
              Critical Node Ranking
            </div>
            <div style={{ color: "var(--muted)", fontSize: 11, marginBottom: 8 }}>
              Showing {filteredCriticalNodes.length} node(s)
            </div>
            {filteredCriticalNodes.length === 0 && <div style={{ color: "var(--muted)" }}>No ranking available.</div>}
            {filteredCriticalNodes.map((row) => (
              <div key={row.node_id} style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                <span>{nodeDisplayName(row.node_id)}</span>
                <span style={{ color: "var(--danger)" }}>-{row.paths_removed || 0}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="grid" style={{ gap: 12 }}>
          <div className="card">
            <div style={{ fontSize: 12, color: "var(--muted)", textTransform: "uppercase", marginBottom: 8 }}>
              Temporal Alerts
            </div>
            <div style={{ marginBottom: 8 }}>New attack paths: {Number(temporal?.new_attack_paths_count || 0)}</div>
            <div style={{ marginBottom: 8 }}>
              Current snapshot: {temporal?.snapshot_timestamp || "n/a"}
            </div>
            <div style={{ marginBottom: 8 }}>
              Previous snapshot: {temporal?.previous_snapshot_timestamp || "n/a"}
            </div>
            {temporal?.is_first_snapshot && (
              <div style={{ color: "var(--muted)", fontSize: 12 }}>
                Baseline snapshot created. Run again to detect temporal drift.
              </div>
            )}
          </div>

          <div className="card">
            <div style={{ fontSize: 12, color: "var(--muted)", textTransform: "uppercase", marginBottom: 8 }}>Summary</div>
            <div style={{ marginBottom: 8 }}>Attack paths found: {report.summary?.attack_paths_found || 0}</div>
            <div style={{ marginBottom: 8 }}>Circular permissions: {report.summary?.cycles_found || 0}</div>
            <div style={{ marginBottom: 8 }}>Blast radius exposed: {report.summary?.blast_nodes_exposed || 0}</div>
            <div>Critical node: {nodeDisplayName(report.summary?.critical_node || "none")}</div>
          </div>

          <div className="card">
            <div style={{ fontSize: 12, color: "var(--muted)", textTransform: "uppercase", marginBottom: 8 }}>
              Recommendations
            </div>
            {(payload?.analysis?.recommendations || []).length === 0 && (
              <div style={{ color: "var(--muted)" }}>No recommendations generated.</div>
            )}
            {(payload?.analysis?.recommendations || []).map((item) => (
              <div key={item} style={{ marginBottom: 6 }}>
                - {item}
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
