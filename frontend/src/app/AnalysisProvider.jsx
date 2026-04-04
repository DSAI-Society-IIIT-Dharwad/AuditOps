import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";

import { fetchGraphAnalysis, GraphApiError } from "../lib/apiClient";

const AnalysisContext = createContext(null);

export function AnalysisProvider({ children }) {
  const [namespace, setNamespace] = useState("vulnerable-ns");
  const [includeClusterRbac, setIncludeClusterRbac] = useState(true);
  const [showAttackPath, setShowAttackPath] = useState(true);
  const [showBlastRadius, setShowBlastRadius] = useState(true);
  const [showCriticalNode, setShowCriticalNode] = useState(true);
  const [payload, setPayload] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const namespaceRef = useRef(namespace);
  const includeClusterRbacRef = useRef(includeClusterRbac);

  useEffect(() => {
    namespaceRef.current = namespace;
  }, [namespace]);

  useEffect(() => {
    includeClusterRbacRef.current = includeClusterRbac;
  }, [includeClusterRbac]);

  const refreshAnalysis = useCallback(async (overrides = {}) => {
    const nextNamespace = String(overrides.namespace ?? namespaceRef.current).trim();
    const nextIncludeClusterRbac = overrides.includeClusterRbac ?? includeClusterRbacRef.current;

    if (!nextNamespace) {
      setError({
        title: "Namespace is required",
        message: "Enter a namespace before loading analysis data.",
        hint: "Try vulnerable-ns or secure-ns.",
        kind: "validation",
      });
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const data = await fetchGraphAnalysis({
        namespace: nextNamespace,
        includeClusterRbac: nextIncludeClusterRbac,
      });
      setPayload(data);
    } catch (err) {
      // Keep raw diagnostics in the console but show friendly UI text.
      // eslint-disable-next-line no-console
      console.error("Graph analysis request failed", err);
      setError(normalizeError(err, nextNamespace));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshAnalysis({
      namespace: namespaceRef.current,
      includeClusterRbac: includeClusterRbacRef.current,
    });
  }, [refreshAnalysis]);

  const value = useMemo(
    () => ({
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
    }),
    [
      namespace,
      includeClusterRbac,
      showAttackPath,
      showBlastRadius,
      showCriticalNode,
      payload,
      loading,
      error,
      refreshAnalysis,
    ],
  );

  return <AnalysisContext.Provider value={value}>{children}</AnalysisContext.Provider>;
}

function normalizeError(error, namespace) {
  if (error instanceof GraphApiError) {
    if (error.kind === "namespace-not-found") {
      return {
        title: "Namespace not found",
        message: `The namespace \"${namespace}\" does not exist or is not accessible.`,
        hint: "Check kubectl context and namespace name, then try again.",
        kind: error.kind,
      };
    }

    if (error.kind === "service-unavailable") {
      return {
        title: "Backend unavailable (503)",
        message: "The analysis service is temporarily unavailable.",
        hint: "Confirm the backend server is running and kubectl can access the cluster.",
        kind: error.kind,
      };
    }

    if (error.kind === "network") {
      return {
        title: "Cannot reach backend",
        message: error.detail || "Could not connect to the API.",
        hint: "Start backend server on port 8000 and retry.",
        kind: error.kind,
      };
    }

    if (error.kind === "validation") {
      return {
        title: "Invalid request",
        message: "The submitted analysis parameters are invalid.",
        hint: "Review namespace and analysis parameters.",
        kind: error.kind,
      };
    }

    return {
      title: "API error",
      message: "An unexpected API error occurred while loading analysis data.",
      hint: "Check backend logs for details and retry.",
      kind: error.kind || "api",
    };
  }

  return {
    title: "Unexpected error",
    message: error instanceof Error ? error.message : "Failed to load graph analysis.",
    hint: "Retry or check backend/frontend logs.",
    kind: "unknown",
  };
}

export function useAnalysis() {
  const context = useContext(AnalysisContext);
  if (!context) {
    throw new Error("useAnalysis must be used within AnalysisProvider");
  }
  return context;
}
