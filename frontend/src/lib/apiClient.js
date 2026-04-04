const API_BASE = "/api/v1";

const NAMESPACE_NOT_FOUND_PATTERN = /(namespaces?.*not found|namespace .* not found|notfound)/i;

export class GraphApiError extends Error {
  constructor(message, { status, detail, kind } = {}) {
    super(message);
    this.name = "GraphApiError";
    this.status = status;
    this.detail = detail;
    this.kind = kind;
  }
}

export async function fetchGraphAnalysis({ namespace = "vulnerable-ns", includeClusterRbac = true } = {}) {
  const query = new URLSearchParams({
    namespace,
    include_cluster_rbac: String(includeClusterRbac),
  });

  let response;
  try {
    response = await fetch(`${API_BASE}/graph-analysis?${query.toString()}`);
  } catch (_err) {
    throw new GraphApiError("Could not reach backend API.", {
      kind: "network",
      detail: "The API server may be down or unreachable.",
    });
  }

  if (!response.ok) {
    const errorPayload = await response.json().catch(() => ({}));
    const detail = String(errorPayload.detail || "");

    if ((response.status === 400 || response.status === 404 || response.status === 503) && NAMESPACE_NOT_FOUND_PATTERN.test(detail)) {
      throw new GraphApiError(`Namespace \"${namespace}\" was not found.`, {
        status: response.status,
        detail,
        kind: "namespace-not-found",
      });
    }

    if (response.status === 503) {
      throw new GraphApiError("Backend service is unavailable.", {
        status: response.status,
        detail: detail || "Try again after the backend recovers.",
        kind: "service-unavailable",
      });
    }

    if (response.status === 400 || response.status === 422) {
      throw new GraphApiError("Invalid request parameters.", {
        status: response.status,
        detail: detail || "Please review the input values.",
        kind: "validation",
      });
    }

    throw new GraphApiError(`API request failed (${response.status}).`, {
      status: response.status,
      detail: detail || "Unexpected API error.",
      kind: "api",
    });
  }

  const payload = await response.json();
  if (!String(payload.schema_version || "").startsWith("1.")) {
    throw new GraphApiError(`Unsupported schema version: ${payload.schema_version}`, {
      kind: "schema",
      detail: "Frontend supports schema version 1.x only.",
    });
  }

  return payload;
}
