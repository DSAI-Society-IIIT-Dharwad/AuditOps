export function parseNodeId(nodeId) {
  const raw = String(nodeId || "");
  const parts = raw.split(":");
  if (parts.length < 3) {
    return {
      raw,
      entityType: "Unknown",
      namespace: "unknown",
      name: raw || "unknown",
    };
  }

  const [entityType, namespace, ...rest] = parts;
  return {
    raw,
    entityType,
    namespace,
    name: rest.join(":"),
  };
}

export function nodeDisplayName(nodeId) {
  return parseNodeId(nodeId).name;
}

export function nodeDisplayLabel(nodeId) {
  const parsed = parseNodeId(nodeId);
  return `${parsed.name} (${parsed.entityType})`;
}

export function severityForScore(score) {
  const numeric = Number(score || 0);
  if (numeric >= 20) {
    return "CRITICAL";
  }
  if (numeric >= 11) {
    return "HIGH";
  }
  if (numeric >= 9) {
    return "MEDIUM";
  }
  return "LOW";
}

export function toPercent(value, maxValue) {
  const safeValue = Math.max(0, Number(value || 0));
  const safeMax = Math.max(1, Number(maxValue || 1));
  return Math.min(100, (safeValue / safeMax) * 100);
}
