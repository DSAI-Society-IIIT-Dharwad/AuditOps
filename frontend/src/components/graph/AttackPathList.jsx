import { nodeDisplayName, severityForScore } from "../../lib/reportUtils";

function formatRisk(value) {
  return Number(value || 0).toFixed(1);
}

export default function AttackPathList({
  attackPaths,
  hoveredPathKey,
  onHoverPath,
  onLeavePath,
}) {
  const safeAttackPaths = Array.isArray(attackPaths) ? attackPaths : [];

  return (
    <section className="panel path-hover-panel" aria-label="Attack path list">
      <div className="path-hover-panel-head">
        <strong>Path Navigator</strong>
        <span>{safeAttackPaths.length} path(s)</span>
      </div>

      {safeAttackPaths.length === 0 && (
        <div className="empty-state">No source-to-sink path detected in this scan.</div>
      )}

      {safeAttackPaths.length > 0 && (
        <div className="path-hover-list">
          {safeAttackPaths.map((path, index) => {
            const pathKey = `${path.source || "unknown"}-${path.target || "unknown"}-${index}`;
            const isActive = hoveredPathKey === pathKey;
            const severity = path.severity || severityForScore(path.risk_score);
            const pathPreview = Array.isArray(path.path)
              ? path.path.map((nodeId) => nodeDisplayName(nodeId)).join(" -> ")
              : `${nodeDisplayName(path.source)} -> ${nodeDisplayName(path.target)}`;

            return (
              <button
                key={pathKey}
                type="button"
                className={`path-hover-item${isActive ? " active" : ""}`}
                onMouseEnter={() => onHoverPath?.(path, pathKey)}
                onMouseLeave={() => onLeavePath?.()}
                onFocus={() => onHoverPath?.(path, pathKey)}
                onBlur={() => onLeavePath?.()}
              >
                <div className="path-hover-item-head">
                  <span>Path #{index + 1}</span>
                  <span>{path.hops || 0} hops</span>
                  <span>
                    Risk {formatRisk(path.risk_score)} [{severity}]
                  </span>
                </div>
                <div className="path-hover-item-route">{pathPreview}</div>
              </button>
            );
          })}
        </div>
      )}
    </section>
  );
}