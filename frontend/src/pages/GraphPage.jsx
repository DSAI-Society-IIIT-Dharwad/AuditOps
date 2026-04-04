import { useMemo } from "react";

import GraphCanvas from "../components/graph/GraphCanvas";
import { useAnalysis } from "../app/AnalysisProvider";

export default function GraphPage() {
  const {
    namespace,
    setNamespace,
    includeClusterRbac,
    setIncludeClusterRbac,
    showAttackPath,
    setShowAttackPath,
    showBlastRadius,
    setShowBlastRadius,
    showCriticalNode,
    setShowCriticalNode,
    payload,
    loading,
    error,
    refreshAnalysis,
  } = useAnalysis();

  const summary = useMemo(() => payload?.summary || null, [payload]);

  return (
    <section>
      <h2 className="page-title">Graph View</h2>
      <div className="card controls-row" style={{ marginBottom: 14 }}>
        <label htmlFor="graph-namespace" style={{ marginRight: 8, fontSize: 12, color: "var(--muted)" }}>
          Namespace
        </label>
        <input
          id="graph-namespace"
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
        <button
          onClick={() => refreshAnalysis({ namespace, includeClusterRbac })}
          disabled={loading || !namespace.trim()}
          style={{ marginLeft: "auto" }}
        >
          {loading ? "Loading..." : "Load Graph"}
        </button>
      </div>

      <div className="card" style={{ marginBottom: 14 }}>
        <label>
          <input type="checkbox" checked={showAttackPath} onChange={(e) => setShowAttackPath(e.target.checked)} /> Attack Path
        </label>
        <label style={{ marginLeft: 12 }}>
          <input type="checkbox" checked={showBlastRadius} onChange={(e) => setShowBlastRadius(e.target.checked)} /> Blast Radius
        </label>
        <label style={{ marginLeft: 12 }}>
          <input type="checkbox" checked={showCriticalNode} onChange={(e) => setShowCriticalNode(e.target.checked)} /> Critical Node
        </label>
      </div>

      {error && (
        <div className="card error-panel" role="alert">
          <div className="error-title">{error.title}</div>
          <div className="error-text">{error.message}</div>
          {error.hint && <div className="error-hint">{error.hint}</div>}
        </div>
      )}

      {summary && (
        <div className="grid" style={{ gridTemplateColumns: "repeat(4, minmax(0, 1fr))", marginBottom: 14 }}>
          <div className="card"><div style={{ color: "var(--muted)", fontSize: 12 }}>Nodes</div><div className="metric">{summary.node_count}</div></div>
          <div className="card"><div style={{ color: "var(--muted)", fontSize: 12 }}>Edges</div><div className="metric">{summary.edge_count}</div></div>
          <div className="card"><div style={{ color: "var(--muted)", fontSize: 12 }}>Sources</div><div className="metric">{summary.source_count}</div></div>
          <div className="card"><div style={{ color: "var(--muted)", fontSize: 12 }}>Sinks</div><div className="metric">{summary.sink_count}</div></div>
        </div>
      )}

      <div className="panel">
        <GraphCanvas
          payload={payload}
          showAttackPath={showAttackPath}
          showBlastRadius={showBlastRadius}
          showCriticalNode={showCriticalNode}
        />
      </div>
    </section>
  );
}
