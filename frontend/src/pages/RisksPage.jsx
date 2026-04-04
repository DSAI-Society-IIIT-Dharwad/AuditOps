import { useMemo } from "react";

import RiskSummary from "../components/risk/RiskSummary";
import { useAnalysis } from "../app/AnalysisProvider";

export default function RisksPage() {
  const {
    namespace,
    setNamespace,
    includeClusterRbac,
    setIncludeClusterRbac,
    payload,
    loading,
    error,
    refreshAnalysis,
  } = useAnalysis();

  const attackPath = useMemo(() => payload?.analysis?.attack_path || null, [payload]);

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
        <button
          onClick={() => refreshAnalysis({ namespace, includeClusterRbac })}
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
        <RiskSummary payload={payload} />
        <div className="grid" style={{ gap: 12 }}>
          <div className="card">
            <div style={{ fontSize: 12, color: "var(--muted)", textTransform: "uppercase", marginBottom: 8 }}>
              Attack Path
            </div>
            {!attackPath || !attackPath.path_node_ids?.length ? (
              <div style={{ color: "var(--muted)" }}>No source-to-sink path detected.</div>
            ) : (
              <>
                <div style={{ marginBottom: 8, fontSize: 13 }}>{attackPath.path_node_ids.join(" -> ")}</div>
                <div style={{ color: "var(--muted)", fontSize: 12 }}>
                  Hops: {attackPath.hops} | Score: {attackPath.risk_score} | Severity: {attackPath.severity}
                </div>
              </>
            )}
          </div>

          <div className="card">
            <div style={{ fontSize: 12, color: "var(--muted)", textTransform: "uppercase", marginBottom: 8 }}>
              Blast Radius
            </div>
            <div style={{ fontWeight: 700 }}>
              {(payload?.analysis?.blast_radius?.reachable_node_ids || []).length} reachable nodes
            </div>
            <div style={{ color: "var(--muted)", fontSize: 12, marginTop: 6 }}>
              Max hops: {payload?.analysis?.blast_radius?.max_hops ?? 0}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
