import { useEffect, useMemo, useState } from "react";

import GraphCanvas from "../components/graph/GraphCanvas";
import AttackPathList from "../components/graph/AttackPathList";
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
  const attackPaths = useMemo(() => (Array.isArray(report.attack_paths) ? report.attack_paths : []), [report]);
  const temporal = useMemo(() => payload?.temporal || report?.temporal || {}, [payload, report]);
  const [selectedNodeId, setSelectedNodeId] = useState(null);
  const [hoveredPath, setHoveredPath] = useState(null);
  const [hoveredPathKey, setHoveredPathKey] = useState(null);
  const [autoRefreshSeconds, setAutoRefreshSeconds] = useState(0);
  const [copySummaryState, setCopySummaryState] = useState("");

  useEffect(() => {
    const nodes = Array.isArray(payload?.nodes) ? payload.nodes : [];
    if (nodes.length === 0) {
      setSelectedNodeId(null);
      return;
    }

    if (selectedNodeId && nodes.some((node) => node.id === selectedNodeId)) {
      return;
    }

    const preferredNodeId =
      payload?.analysis?.critical_node?.node_id ||
      payload?.report?.critical_nodes?.[0]?.node_id ||
      nodes.find((node) => node.nvd_enriched)?.id ||
      nodes[0].id;

    setSelectedNodeId(preferredNodeId);
  }, [payload, selectedNodeId]);

  useEffect(() => {
    setHoveredPath(null);
    setHoveredPathKey(null);
  }, [payload]);

  useEffect(() => {
    if (!copySummaryState) {
      return undefined;
    }
    const timeoutId = window.setTimeout(() => {
      setCopySummaryState("");
    }, 1800);
    return () => window.clearTimeout(timeoutId);
  }, [copySummaryState]);

  const contextLine = useMemo(() => {
    const newAttackPaths = Number(temporal?.new_attack_paths_count || 0);
    if (newAttackPaths > 0) {
      return `Temporal alert: ${newAttackPaths} new attack path(s) appeared since the previous scan.`;
    }

    if (temporal?.is_first_snapshot) {
      return "Baseline snapshot created. Run another scan to detect temporal drift.";
    }

    const topPath = report.attack_paths?.[0];
    if (!topPath) {
      return "No attack path currently detected between selected sources and sinks.";
    }

    return `Lateral movement path found from ${nodeDisplayName(topPath.source)} to ${nodeDisplayName(topPath.target)} (${topPath.hops || 0} hops).`;
  }, [report, temporal]);

  const executiveSummaryText = useMemo(() => {
    const reportSummary = report.summary || {};
    const topPath = attackPaths[0] || null;
    const lines = [
      `Hack2Future Risk Brief`,
      `Namespace: ${namespace || "all"}`,
      `Attack paths found: ${reportSummary.attack_paths_found || 0}`,
      `Circular permissions: ${reportSummary.cycles_found || 0}`,
      `Blast radius exposed: ${reportSummary.blast_nodes_exposed || 0}`,
      `Critical node: ${nodeDisplayName(reportSummary.critical_node || "none")}`,
      `New temporal alerts: ${Number(temporal?.new_attack_paths_count || 0)}`,
    ];

    if (topPath) {
      lines.push(
        `Top path: ${nodeDisplayName(topPath.source)} -> ${nodeDisplayName(topPath.target)} | hops ${topPath.hops || 0} | risk ${Number(topPath.risk_score || 0).toFixed(1)} | ${topPath.severity || "LOW"}`,
      );
    }

    return lines.join("\n");
  }, [attackPaths, namespace, report, temporal]);

  const onLoad = () => {
    refreshAnalysis({
      namespace,
      includeClusterRbac,
      enableNvdScoring,
      maxHops,
      maxDepth,
    });
  };

  const onDownloadAnalysis = () => {
    if (!payload) {
      return;
    }
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const safeNamespace = (namespace || "all").trim().replace(/[^a-zA-Z0-9-_]/g, "_") || "all";
    const stamp = String(temporal?.snapshot_timestamp || Date.now());
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `analysis-${safeNamespace}-${stamp}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const onCopyExecutiveSummary = async () => {
    if (!executiveSummaryText) {
      return;
    }

    try {
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(executiveSummaryText);
      } else {
        const textarea = document.createElement("textarea");
        textarea.value = executiveSummaryText;
        textarea.setAttribute("readonly", "true");
        textarea.style.position = "absolute";
        textarea.style.left = "-9999px";
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
      }
      setCopySummaryState("Copied");
    } catch (_error) {
      setCopySummaryState("Copy failed");
    }
  };

  useEffect(() => {
    if (!autoRefreshSeconds) {
      return undefined;
    }

    const intervalId = window.setInterval(() => {
      if (loading) {
        return;
      }
      refreshAnalysis({
        namespace,
        includeClusterRbac,
        enableNvdScoring,
        maxHops,
        maxDepth,
      });
    }, autoRefreshSeconds * 1000);

    return () => window.clearInterval(intervalId);
  }, [
    autoRefreshSeconds,
    enableNvdScoring,
    includeClusterRbac,
    loading,
    maxDepth,
    maxHops,
    namespace,
    refreshAnalysis,
  ]);

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

        <div className="control-group compact">
          <label htmlFor="auto-refresh">Auto refresh</label>
          <select
            id="auto-refresh"
            value={autoRefreshSeconds}
            onChange={(event) => setAutoRefreshSeconds(Number(event.target.value || 0))}
          >
            <option value={0}>Off</option>
            <option value={15}>15s</option>
            <option value={30}>30s</option>
            <option value={60}>60s</option>
          </select>
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
            onChange={(event) => {
              const checked = event.target.checked;
              setEnableNvdScoring(checked);
              refreshAnalysis({
                namespace,
                includeClusterRbac,
                enableNvdScoring: checked,
                maxHops,
                maxDepth,
              });
            }}
          />
          Enable live NVD scoring
        </label>

        <button onClick={onLoad} disabled={loading || !namespace.trim()} className="primary-action">
          {loading ? "Refreshing..." : "Initiate Scan"}
        </button>

        <button
          type="button"
          onClick={onDownloadAnalysis}
          disabled={!payload}
          className="secondary-action"
        >
          Download JSON
        </button>

        <button
          type="button"
          onClick={onCopyExecutiveSummary}
          disabled={!payload}
          className="secondary-action"
        >
          {copySummaryState || "Copy PPT Brief"}
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
              selectedNodeId={selectedNodeId}
              hoveredPath={hoveredPath}
              onSelectNode={setSelectedNodeId}
            />
          </div>

          <AttackPathList
            attackPaths={attackPaths}
            hoveredPathKey={hoveredPathKey}
            onHoverPath={(path, pathKey) => {
              setHoveredPath(path || null);
              setHoveredPathKey(pathKey || null);
            }}
            onLeavePath={() => {
              setHoveredPath(null);
              setHoveredPathKey(null);
            }}
          />

          <div className="data-ribbon">
            <span>SCAN MODE: CONTINUOUS</span>
            <span>THREAT LEVEL: {report.summary?.attack_paths_found ? "ELEVATED" : "NOMINAL"}</span>
            <span>ATTACK PATHS: {report.summary?.attack_paths_found || 0}</span>
            <span>CYCLES: {report.summary?.cycles_found || 0}</span>
            <span>EXPOSED: {report.summary?.blast_nodes_exposed || 0}</span>
            <span>NEW PATH ALERTS: {temporal?.new_attack_paths_count || 0}</span>
          </div>
        </div>

        <ReportPanel payload={payload} selectedNodeId={selectedNodeId} />
      </div>
    </section>
  );
}
