import { useCallback, useEffect, useMemo, useState } from "react";

import { useAnalysis } from "../app/AnalysisProvider";
import { GraphApiError, fetchSnapshotDetail, fetchSnapshots, rollbackSnapshot } from "../lib/apiClient";

function snapshotKey(item) {
  return `${item.scope_id}::${item.snapshot_timestamp}`;
}

function formatTimestamp(value) {
  const text = String(value || "").trim();
  const match = text.match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})/);
  if (!match) {
    return text || "n/a";
  }

  const [, year, month, day, hour, minute, second] = match;
  const iso = `${year}-${month}-${day}T${hour}:${minute}:${second}Z`;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return text;
  }
  return `${date.toLocaleDateString()} ${date.toLocaleTimeString()}`;
}

function formatScope(scopeId) {
  return String(scopeId || "").replaceAll("__", " / ");
}

function normalizeError(err, fallbackTitle) {
  if (err instanceof GraphApiError) {
    return {
      title: fallbackTitle,
      message: err.detail || err.message,
    };
  }

  return {
    title: fallbackTitle,
    message: err instanceof Error ? err.message : "Unexpected error.",
  };
}

export default function SnapshotsPage() {
  const { namespace, includeClusterRbac, enableNvdScoring } = useAnalysis();

  const [scopeFilter, setScopeFilter] = useState("");
  const [namespaceFilter, setNamespaceFilter] = useState(namespace || "");
  const [currentModeOnly, setCurrentModeOnly] = useState(true);

  const [items, setItems] = useState([]);
  const [loadingList, setLoadingList] = useState(false);
  const [listError, setListError] = useState(null);

  const [selectedSnapshot, setSelectedSnapshot] = useState(null);
  const [snapshotDetail, setSnapshotDetail] = useState(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [detailError, setDetailError] = useState(null);

  const [actioningKey, setActioningKey] = useState("");
  const [actionMessage, setActionMessage] = useState("");

  const loadSnapshots = useCallback(async () => {
    setLoadingList(true);
    setListError(null);
    setActionMessage("");

    try {
      const rows = await fetchSnapshots({
        scopeId: scopeFilter.trim() || undefined,
        namespace: namespaceFilter.trim() || undefined,
        includeClusterRbac: currentModeOnly ? includeClusterRbac : undefined,
        enableNvdScoring: currentModeOnly ? enableNvdScoring : undefined,
        limit: 300,
      });
      setItems(rows);

      if (selectedSnapshot) {
        const hasSelected = rows.some(
          (row) =>
            row.scope_id === selectedSnapshot.scope_id &&
            row.snapshot_timestamp === selectedSnapshot.snapshot_timestamp,
        );
        if (!hasSelected) {
          setSelectedSnapshot(null);
          setSnapshotDetail(null);
          setDetailError(null);
        }
      }
    } catch (err) {
      setListError(normalizeError(err, "Failed to load snapshots"));
      setItems([]);
    } finally {
      setLoadingList(false);
    }
  }, [
    currentModeOnly,
    enableNvdScoring,
    includeClusterRbac,
    namespaceFilter,
    scopeFilter,
    selectedSnapshot,
  ]);

  useEffect(() => {
    loadSnapshots();
  }, [loadSnapshots]);

  const openSnapshot = async (item) => {
    setSelectedSnapshot(item);
    setSnapshotDetail(null);
    setDetailError(null);
    setLoadingDetail(true);

    try {
      const detail = await fetchSnapshotDetail({
        scopeId: item.scope_id,
        snapshotTimestamp: item.snapshot_timestamp,
      });
      setSnapshotDetail(detail);
    } catch (err) {
      setDetailError(normalizeError(err, "Failed to load snapshot detail"));
    } finally {
      setLoadingDetail(false);
    }
  };

  const onRollback = async (item) => {
    const confirm = window.confirm(
      `Rollback to snapshot ${item.snapshot_timestamp}? This will promote it as the latest baseline.`,
    );
    if (!confirm) {
      return;
    }

    const key = snapshotKey(item);
    setActioningKey(key);
    setActionMessage("");

    try {
      const result = await rollbackSnapshot({
        scopeId: item.scope_id,
        snapshotTimestamp: item.snapshot_timestamp,
        reason: "snapshot tab rollback",
      });
      setActionMessage(
        `Rollback created new baseline ${result.snapshot_timestamp} from ${result.rolled_back_from}.`,
      );
      await loadSnapshots();
    } catch (err) {
      setListError(normalizeError(err, "Rollback failed"));
    } finally {
      setActioningKey("");
    }
  };

  const detailSummary = useMemo(() => {
    const payload = snapshotDetail?.payload;
    if (!payload || typeof payload !== "object") {
      return null;
    }

    const nodes = Array.isArray(payload.nodes) ? payload.nodes : [];
    const edges = Array.isArray(payload.edges) ? payload.edges : [];
    const temporal = payload.temporal && typeof payload.temporal === "object" ? payload.temporal : {};
    const topNodes = [...nodes]
      .sort((a, b) => Number(b?.risk_score || 0) - Number(a?.risk_score || 0))
      .slice(0, 8);

    return {
      nodes,
      edges,
      temporal,
      topNodes,
    };
  }, [snapshotDetail]);

  const onDownloadJson = () => {
    if (!snapshotDetail?.payload || !selectedSnapshot) {
      return;
    }
    const blob = new Blob([JSON.stringify(snapshotDetail.payload, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `snapshot-${selectedSnapshot.snapshot_timestamp}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  return (
    <section className="snapshots-page">
      <h2 className="page-title">Snapshot Vault</h2>

      <div className="card snapshot-filters">
        <div className="control-group">
          <label htmlFor="snapshot-scope-filter">Scope filter</label>
          <input
            id="snapshot-scope-filter"
            value={scopeFilter}
            onChange={(event) => setScopeFilter(event.target.value)}
            placeholder="api__kubectl__vulnerable-ns..."
          />
        </div>

        <div className="control-group">
          <label htmlFor="snapshot-namespace-filter">Namespace</label>
          <input
            id="snapshot-namespace-filter"
            value={namespaceFilter}
            onChange={(event) => setNamespaceFilter(event.target.value)}
            placeholder="all"
          />
        </div>

        <label className="checkbox-line">
          <input
            type="checkbox"
            checked={currentModeOnly}
            onChange={(event) => setCurrentModeOnly(event.target.checked)}
          />
          Match current mode (RBAC + NVD)
        </label>

        <button className="primary-action" onClick={loadSnapshots} disabled={loadingList}>
          {loadingList ? "Refreshing..." : "Refresh Snapshots"}
        </button>
      </div>

      {actionMessage && <div className="card snapshot-success">{actionMessage}</div>}

      {listError && (
        <div className="card error-panel" role="alert">
          <div className="error-title">{listError.title}</div>
          <div className="error-text">{listError.message}</div>
        </div>
      )}

      <div className="snapshots-layout">
        <div className="panel snapshot-list-panel">
          <div className="snapshot-list-head">
            <strong>Available Snapshots</strong>
            <span>{items.length}</span>
          </div>

          {items.length === 0 && !loadingList && (
            <div className="empty-state">No snapshots found for the current filters.</div>
          )}

          <div className="snapshot-list">
            {items.map((item) => {
              const key = snapshotKey(item);
              const isSelected =
                selectedSnapshot?.scope_id === item.scope_id &&
                selectedSnapshot?.snapshot_timestamp === item.snapshot_timestamp;

              return (
                <div key={key} className={`snapshot-row${isSelected ? " active" : ""}`}>
                  <div className="snapshot-row-meta">
                    <div className="snapshot-row-title">{formatTimestamp(item.snapshot_timestamp)}</div>
                    <div className="snapshot-row-subtitle">{item.scope_id}</div>
                    <div className="snapshot-row-tags">
                      <span>{item.namespace}</span>
                      <span>{item.ingestor}</span>
                      <span>{item.source}</span>
                      <span>{item.node_count}N / {item.edge_count}E</span>
                    </div>
                  </div>

                  <div className="snapshot-row-actions">
                    <button type="button" onClick={() => openSnapshot(item)} disabled={loadingDetail}>
                      View
                    </button>
                    <button
                      type="button"
                      onClick={() => onRollback(item)}
                      disabled={actioningKey === key}
                    >
                      {actioningKey === key ? "Rolling back..." : "Rollback"}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="panel snapshot-detail-panel">
          <div className="snapshot-list-head">
            <strong>Snapshot Detail</strong>
            {selectedSnapshot ? (
              <span>{formatTimestamp(selectedSnapshot.snapshot_timestamp)}</span>
            ) : (
              <span>None selected</span>
            )}
          </div>

          {!selectedSnapshot && (
            <div className="empty-state">Select a snapshot to inspect old state details.</div>
          )}

          {loadingDetail && <div className="empty-state">Loading snapshot detail...</div>}

          {detailError && (
            <div className="error-panel" role="alert">
              <div className="error-title">{detailError.title}</div>
              <div className="error-text">{detailError.message}</div>
            </div>
          )}

          {selectedSnapshot && detailSummary && !loadingDetail && !detailError && (
            <div className="snapshot-detail-content">
              <div className="snapshot-kv-grid">
                <div>
                  <span>Scope</span>
                  <strong>{formatScope(selectedSnapshot.scope_id)}</strong>
                </div>
                <div>
                  <span>Snapshot</span>
                  <strong>{selectedSnapshot.snapshot_timestamp}</strong>
                </div>
                <div>
                  <span>Nodes</span>
                  <strong>{detailSummary.nodes.length}</strong>
                </div>
                <div>
                  <span>Edges</span>
                  <strong>{detailSummary.edges.length}</strong>
                </div>
                <div>
                  <span>Namespace</span>
                  <strong>{detailSummary.temporal.namespace || "all"}</strong>
                </div>
                <div>
                  <span>Rolled back from</span>
                  <strong>{detailSummary.temporal.rolled_back_from || "-"}</strong>
                </div>
              </div>

              <div className="snapshot-actions">
                <button type="button" onClick={onDownloadJson}>Download JSON</button>
              </div>

              <div className="snapshot-node-list">
                <div className="section-kicker">Top Risk Nodes In Snapshot</div>
                {detailSummary.topNodes.length === 0 && (
                  <div className="empty-state">No nodes in this snapshot payload.</div>
                )}
                {detailSummary.topNodes.map((node) => (
                  <div
                    key={node.node_id}
                    className="snapshot-node-row"
                  >
                    <span>{node.name} ({node.entity_type})</span>
                    <strong>{Number(node.risk_score || 0).toFixed(1)}</strong>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
