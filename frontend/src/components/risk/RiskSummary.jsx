export default function RiskSummary({ payload }) {
  if (!payload) {
    return null;
  }

  const attack = payload.analysis?.attack_path || {};
  const cycles = payload.analysis?.cycles || {};
  const critical = payload.analysis?.critical_node || {};

  return (
    <div className="grid" style={{ gap: 12 }}>
      <div className="card">
        <div style={{ fontSize: 12, color: "var(--muted)", textTransform: "uppercase" }}>Threat Level</div>
        <div className="metric">{attack.severity || "LOW"}</div>
        <div style={{ fontFamily: "JetBrains Mono, monospace", color: "var(--muted)", fontSize: 12 }}>
          Risk Score: {attack.risk_score ?? 0}
        </div>
      </div>

      <div className="card">
        <div style={{ fontSize: 12, color: "var(--muted)", textTransform: "uppercase" }}>Critical Node</div>
        <div style={{ fontWeight: 700 }}>{critical.node_id || "None"}</div>
        <div style={{ color: "var(--muted)", fontSize: 12 }}>Paths removed: {critical.paths_removed || 0}</div>
      </div>

      <div className="card">
        <div style={{ fontSize: 12, color: "var(--muted)", textTransform: "uppercase" }}>Cycle Alerts</div>
        <div className="metric" style={{ color: "var(--danger)" }}>{cycles.count || 0}</div>
      </div>

      <div className="card">
        <div style={{ fontSize: 12, color: "var(--muted)", textTransform: "uppercase", marginBottom: 6 }}>
          Recommendations
        </div>
        {(payload.analysis?.recommendations || []).length === 0 && <div style={{ color: "var(--muted)" }}>No recommendations.</div>}
        {(payload.analysis?.recommendations || []).map((item) => (
          <div key={item} style={{ marginBottom: 8, fontSize: 13 }}>
            - {item}
          </div>
        ))}
      </div>
    </div>
  );
}
