import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";

import { fetchGraphAnalysis, GraphApiError } from "../lib/apiClient";

const AnalysisContext = createContext(null);
const ANALYSIS_PREFERENCES_KEY = "h2f.analysis.preferences.v1";

function loadStoredPreferences() {
  if (typeof window === "undefined") {
    return {};
  }

  try {
    const raw = window.localStorage.getItem(ANALYSIS_PREFERENCES_KEY);
    if (!raw) {
      return {};
    }
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch (_error) {
    return {};
  }
}

function saveStoredPreferences(preferences) {
  if (typeof window === "undefined") {
    return;
  }

  try {
    window.localStorage.setItem(ANALYSIS_PREFERENCES_KEY, JSON.stringify(preferences));
  } catch (_error) {
    // Ignore quota/security errors and continue with in-memory state.
  }
}

function toStoredString(value, fallback) {
  const text = String(value ?? "").trim();
  return text || fallback;
}

function toStoredBoolean(value, fallback) {
  return typeof value === "boolean" ? value : fallback;
}

function toStoredInteger(value, fallback, { min, max }) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  const integerValue = Math.trunc(parsed);
  if (integerValue < min || integerValue > max) {
    return fallback;
  }
  return integerValue;
}

export function AnalysisProvider({ children }) {
  const initialPreferencesRef = useRef(null);
  if (initialPreferencesRef.current === null) {
    initialPreferencesRef.current = loadStoredPreferences();
  }
  const initialPreferences = initialPreferencesRef.current;

  const [namespace, setNamespace] = useState(() => toStoredString(initialPreferences.namespace, "vulnerable-ns"));
  const [includeClusterRbac, setIncludeClusterRbac] = useState(() => toStoredBoolean(initialPreferences.includeClusterRbac, true));
  const [enableNvdScoring, setEnableNvdScoring] = useState(() => toStoredBoolean(initialPreferences.enableNvdScoring, false));
  const [maxHops, setMaxHops] = useState(() => toStoredInteger(initialPreferences.maxHops, 3, { min: 0, max: 10 }));
  const [maxDepth, setMaxDepth] = useState(() => toStoredInteger(initialPreferences.maxDepth, 8, { min: 1, max: 20 }));
  const [showAttackPath, setShowAttackPath] = useState(() => toStoredBoolean(initialPreferences.showAttackPath, true));
  const [showBlastRadius, setShowBlastRadius] = useState(() => toStoredBoolean(initialPreferences.showBlastRadius, true));
  const [showCriticalNode, setShowCriticalNode] = useState(() => toStoredBoolean(initialPreferences.showCriticalNode, true));
  const [payload, setPayload] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const namespaceRef = useRef(namespace);
  const includeClusterRbacRef = useRef(includeClusterRbac);
  const enableNvdScoringRef = useRef(enableNvdScoring);
  const maxHopsRef = useRef(maxHops);
  const maxDepthRef = useRef(maxDepth);

  useEffect(() => {
    namespaceRef.current = namespace;
  }, [namespace]);

  useEffect(() => {
    includeClusterRbacRef.current = includeClusterRbac;
  }, [includeClusterRbac]);

  useEffect(() => {
    enableNvdScoringRef.current = enableNvdScoring;
  }, [enableNvdScoring]);

  useEffect(() => {
    maxHopsRef.current = maxHops;
  }, [maxHops]);

  useEffect(() => {
    maxDepthRef.current = maxDepth;
  }, [maxDepth]);

  useEffect(() => {
    saveStoredPreferences({
      namespace,
      includeClusterRbac,
      enableNvdScoring,
      maxHops,
      maxDepth,
      showAttackPath,
      showBlastRadius,
      showCriticalNode,
    });
  }, [
    namespace,
    includeClusterRbac,
    enableNvdScoring,
    maxHops,
    maxDepth,
    showAttackPath,
    showBlastRadius,
    showCriticalNode,
  ]);

  const refreshAnalysis = useCallback(async (overrides = {}) => {
    const nextNamespace = String(overrides.namespace ?? namespaceRef.current).trim();
    const nextIncludeClusterRbac = overrides.includeClusterRbac ?? includeClusterRbacRef.current;
    const nextEnableNvdScoring = overrides.enableNvdScoring ?? enableNvdScoringRef.current;
    const nextMaxHops = Number.isFinite(overrides.maxHops) ? overrides.maxHops : maxHopsRef.current;
    const nextMaxDepth = Number.isFinite(overrides.maxDepth) ? overrides.maxDepth : maxDepthRef.current;

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
        enableNvdScoring: nextEnableNvdScoring,
        maxHops: nextMaxHops,
        maxDepth: nextMaxDepth,
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
      enableNvdScoring: enableNvdScoringRef.current,
      maxHops: maxHopsRef.current,
      maxDepth: maxDepthRef.current,
    });
  }, [refreshAnalysis]);

  const value = useMemo(
    () => ({
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
    }),
    [
      namespace,
      includeClusterRbac,
      enableNvdScoring,
      maxHops,
      maxDepth,
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
