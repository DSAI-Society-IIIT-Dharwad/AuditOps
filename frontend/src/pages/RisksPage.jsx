import { useMemo } from "react";

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

  const report = useMemo(() => payload?.report || {}, [payload]);
  const temporal = useMemo(() => payload?.temporal || report?.temporal || {}, [payload, report]);
  const criticalNodes = report.critical_nodes || [];
  const topPaths = (report.attack_paths || []).slice(-5).reverse();

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
          style={{ marginLeft: "auto" }}
        >
          {loading ? "Loading..." : "Load Risks"}
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
            {criticalNodes.length === 0 && <div style={{ color: "var(--muted)" }}>No ranking available.</div>}
            {criticalNodes.map((row) => (
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
