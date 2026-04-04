import { useEffect, useMemo, useState } from "react";

import { useAnalysis } from "../app/AnalysisProvider";
import AttackPathList from "../components/graph/AttackPathList";
import GraphCanvas from "../components/graph/GraphCanvas";
import ReportPanel from "../components/risk/ReportPanel";
import { fetchGraphAnalysisFromContent, GraphApiError } from "../lib/apiClient";

export default function IngestPage() {
  const {
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
  } = useAnalysis();

  const [contentFormat, setContentFormat] = useState("auto");
  const [content, setContent] = useState("");
  const [ingestNamespace, setIngestNamespace] = useState("");
  const [payload, setPayload] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [selectedNodeId, setSelectedNodeId] = useState(null);
  const [hoveredPath, setHoveredPath] = useState(null);
  const [hoveredPathKey, setHoveredPathKey] = useState(null);

  useEffect(() => {
    const nodes = Array.isArray(payload?.nodes) ? payload.nodes : [];
    if (nodes.length === 0) {
      setSelectedNodeId(null);
      return;
    }

    if (selectedNodeId && nodes.some((node) => node.id === selectedNodeId)) {
      return;
    }

    const preferred =
      payload?.analysis?.critical_node?.node_id ||
      payload?.report?.critical_nodes?.[0]?.node_id ||
      nodes[0].id;
    setSelectedNodeId(preferred);
  }, [payload, selectedNodeId]);

  const summary = useMemo(() => payload?.summary || {}, [payload]);
  const report = useMemo(() => payload?.report || {}, [payload]);
  const attackPaths = useMemo(() => (Array.isArray(report.attack_paths) ? report.attack_paths : []), [report]);
  const temporal = useMemo(() => payload?.temporal || report?.temporal || {}, [payload, report]);

  useEffect(() => {
    setHoveredPath(null);
    setHoveredPathKey(null);
  }, [payload]);

  const onAnalyze = async () => {
    const trimmed = content.trim();
    if (!trimmed) {
      setError({
        title: "Input is required",
        message: "Paste YAML or JSON content before running analysis.",
        hint: "You can also load content using the file picker.",
      });
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const response = await fetchGraphAnalysisFromContent({
        content: trimmed,
        format: contentFormat,
        namespace: ingestNamespace.trim() || null,
        includeClusterRbac,
        enableNvdScoring,
        maxHops,
        maxDepth,
      });
      setPayload(response);
    } catch (err) {
      setError(normalizeError(err));
    } finally {
      setLoading(false);
    }
  };

  const onPickFile = async (event) => {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }

    const text = await file.text();
    setContent(text);

    const name = file.name.toLowerCase();
    if (name.endsWith(".yaml") || name.endsWith(".yml")) {
      setContentFormat("yaml");
    } else if (name.endsWith(".json")) {
      setContentFormat("json");
    }
  };

  return (
    <section className="console-page">
      <div className="card">
        <h2 className="page-title" style={{ marginBottom: 10 }}>Ingest YAML / JSON</h2>
        <div className="console-controls">
          <div className="control-group">
            <label htmlFor="ingest-namespace">Namespace</label>
            <input
              id="ingest-namespace"
              value={ingestNamespace}
              onChange={(event) => setIngestNamespace(event.target.value)}
              placeholder="(optional) all namespaces"
            />
          </div>

          <div className="control-group compact">
            <label htmlFor="ingest-max-hops">Max hops</label>
            <input
              id="ingest-max-hops"
              type="number"
              min={0}
              max={10}
              value={maxHops}
              onChange={(event) => setMaxHops(Number(event.target.value || 0))}
            />
          </div>

          <div className="control-group compact">
            <label htmlFor="ingest-max-depth">Max depth</label>
            <input
              id="ingest-max-depth"
              type="number"
              min={1}
              max={20}
              value={maxDepth}
              onChange={(event) => setMaxDepth(Number(event.target.value || 1))}
            />
          </div>

          <div className="control-group compact">
            <label htmlFor="ingest-format">Format</label>
            <select
              id="ingest-format"
              value={contentFormat}
              onChange={(event) => setContentFormat(event.target.value)}
            >
              <option value="auto">Auto detect</option>
              <option value="yaml">YAML</option>
              <option value="json">JSON</option>
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
              onChange={(event) => setEnableNvdScoring(event.target.checked)}
            />
            Enable live NVD scoring
          </label>

          <button className="primary-action" onClick={onAnalyze} disabled={loading}>
            {loading ? "Analyzing..." : "Run Analysis"}
          </button>
        </div>

        <div className="ingest-actions">
          <input
            id="ingest-file"
            type="file"
            accept=".yaml,.yml,.json,text/plain,application/json"
            onChange={onPickFile}
          />
        </div>

        <textarea
          className="ingest-textarea"
          value={content}
          onChange={(event) => setContent(event.target.value)}
          placeholder="Paste Kubernetes YAML manifests or graph JSON payload here..."
        />
      </div>

      {error && (
        <div className="card error-panel" role="alert">
          <div className="error-title">{error.title}</div>
          <div className="error-text">{error.message}</div>
          {error.hint && <div className="error-hint">{error.hint}</div>}
        </div>
      )}

      {payload && (
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

            <div className="threat-banner">
              {temporal?.is_first_snapshot
                ? "Baseline snapshot created from uploaded content."
                : `Temporal alerts from upload scope: ${Number(temporal?.new_attack_paths_count || 0)} new path(s).`}
            </div>

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
              <span>ATTACK PATHS: {report.summary?.attack_paths_found || 0}</span>
              <span>CYCLES: {report.summary?.cycles_found || 0}</span>
              <span>EXPOSED: {report.summary?.blast_nodes_exposed || 0}</span>
              <span>NEW PATH ALERTS: {temporal?.new_attack_paths_count || 0}</span>
            </div>
          </div>

          <ReportPanel payload={payload} selectedNodeId={selectedNodeId} />
        </div>
      )}
    </section>
  );
}

function normalizeError(error) {
  if (error instanceof GraphApiError) {
    return {
      title: "Ingest analysis failed",
      message: error.detail || error.message,
      hint: "Validate YAML/JSON format and required Kubernetes object fields.",
    };
  }

  return {
    title: "Unexpected error",
    message: error instanceof Error ? error.message : "Failed to run analysis.",
    hint: "Retry with valid YAML/JSON content.",
  };
}
