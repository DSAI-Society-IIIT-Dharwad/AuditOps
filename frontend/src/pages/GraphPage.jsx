import { useMemo } from "react";

import GraphCanvas from "../components/graph/GraphCanvas";
import ReportPanel from "../components/risk/ReportPanel";
import { useAnalysis } from "../app/AnalysisProvider";
import { nodeDisplayName } from "../lib/reportUtils";

export default function GraphPage() {
  const {
    namespace,
    setNamespace,
    includeClusterRbac,
    setIncludeClusterRbac,
    enableNvdScoring,
    setEnableNvdScoring,
    maxHops,
    setMaxHops,
    maxDepth,
    setMaxDepth,
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

  const summary = useMemo(() => payload?.summary || {}, [payload]);
  const report = useMemo(() => payload?.report || {}, [payload]);

  const contextLine = useMemo(() => {
    const topPath = report.attack_paths?.[0];
    if (!topPath) {
      return "No attack path currently detected between selected sources and sinks.";
    }

    return `Lateral movement path found from ${nodeDisplayName(topPath.source)} to ${nodeDisplayName(topPath.target)} (${topPath.hops || 0} hops).`;
  }, [report]);

  const onLoad = () => {
    refreshAnalysis({
      namespace,
      includeClusterRbac,
      enableNvdScoring,
      maxHops,
      maxDepth,
    });
  };

  return (
    <section className="console-page">
      <div className="card console-controls">
        <div className="control-group">
          <label htmlFor="graph-namespace">Namespace</label>
          <input
            id="graph-namespace"
            value={namespace}
            onChange={(event) => setNamespace(event.target.value)}
          />
        </div>

        <div className="control-group compact">
          <label htmlFor="max-hops">Max hops</label>
          <input
            id="max-hops"
            type="number"
            min={0}
            max={10}
            value={maxHops}
            onChange={(event) => setMaxHops(Number(event.target.value || 0))}
          />
        </div>

        <div className="control-group compact">
          <label htmlFor="max-depth">Max depth</label>
          <input
            id="max-depth"
            type="number"
            min={1}
            max={20}
            value={maxDepth}
            onChange={(event) => setMaxDepth(Number(event.target.value || 1))}
          />
        </div>

        <label className="checkbox-line">
          <input
            type="checkbox"
            checked={includeClusterRbac}
            onChange={(event) => setIncludeClusterRbac(event.target.checked)}
          />
          Include cluster RBAC
        </label>

        <label className="checkbox-line">
          <input
            type="checkbox"
            checked={enableNvdScoring}
            onChange={(event) => setEnableNvdScoring(event.target.checked)}
          />
          Enable live NVD scoring
        </label>

        <button onClick={onLoad} disabled={loading || !namespace.trim()} className="primary-action">
          {loading ? "Refreshing..." : "Initiate Scan"}
        </button>
      </div>

      <div className="dashboard-layout">
        <div className="graph-column">
          <div className="mode-strip">
            <button
              className={`mode-pill${showAttackPath ? " active" : ""}`}
              onClick={() => setShowAttackPath((prev) => !prev)}
            >
              Attack Path
            </button>
            <button
              className={`mode-pill${showBlastRadius ? " active" : ""}`}
              onClick={() => setShowBlastRadius((prev) => !prev)}
            >
              Blast Radius
            </button>
            <button
              className={`mode-pill${showCriticalNode ? " active" : ""}`}
              onClick={() => setShowCriticalNode((prev) => !prev)}
            >
              Critical Node
            </button>
          </div>

          <div className="threat-banner">{contextLine}</div>

          {error && (
            <div className="card error-panel" role="alert">
              <div className="error-title">{error.title}</div>
              <div className="error-text">{error.message}</div>
              {error.hint && <div className="error-hint">{error.hint}</div>}
            </div>
          )}

          <div className="quick-metrics">
            <div className="metric-card">
              <span>Nodes</span>
              <strong>{summary.node_count || 0}</strong>
            </div>
            <div className="metric-card">
              <span>Edges</span>
              <strong>{summary.edge_count || 0}</strong>
            </div>
            <div className="metric-card">
              <span>Sources</span>
              <strong>{summary.source_count || 0}</strong>
            </div>
            <div className="metric-card">
              <span>Sinks</span>
              <strong>{summary.sink_count || 0}</strong>
            </div>
          </div>

          <div className="panel graph-shell">
            <GraphCanvas
              payload={payload}
              showAttackPath={showAttackPath}
              showBlastRadius={showBlastRadius}
              showCriticalNode={showCriticalNode}
            />
          </div>

          <div className="data-ribbon">
            <span>SCAN MODE: CONTINUOUS</span>
            <span>THREAT LEVEL: {report.summary?.attack_paths_found ? "ELEVATED" : "NOMINAL"}</span>
            <span>ATTACK PATHS: {report.summary?.attack_paths_found || 0}</span>
            <span>CYCLES: {report.summary?.cycles_found || 0}</span>
            <span>EXPOSED: {report.summary?.blast_nodes_exposed || 0}</span>
          </div>
        </div>

        <ReportPanel payload={payload} />
      </div>
    </section>
  );
}
