from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import json
import os
from pathlib import Path
from typing import Any

from analysis.shortest_path import dijkstra_shortest_path
from core.models import ClusterGraphData, Edge, Node
from graph.networkx_builder import NetworkXGraphStorage


@dataclass(slots=True, frozen=True)
class SnapshotRecord:
    scope_id: str
    timestamp: str
    path: Path
    storage: NetworkXGraphStorage
    metadata: dict[str, Any]


def build_scope_id(
    *,
    namespace: str | None,
    include_cluster_rbac: bool,
    ingestor: str,
    enable_nvd_scoring: bool,
    source: str,
) -> str:
    namespace_key = _slug(namespace or "all")
    rbac_key = "cluster-rbac" if include_cluster_rbac else "strict-rbac"
    nvd_key = "nvd-on" if enable_nvd_scoring else "nvd-off"
    return "__".join(
        [
            _slug(source),
            _slug(ingestor),
            namespace_key,
            rbac_key,
            nvd_key,
        ]
    )


def load_previous_snapshot(scope_id: str, *, snapshot_dir: str | None = None) -> SnapshotRecord | None:
    root = _resolve_snapshot_root(snapshot_dir)
    scope_path = root / scope_id
    if not scope_path.exists():
        return None

    candidates = sorted(scope_path.glob("snapshot-*.json"))
    if not candidates:
        return None

    return _load_snapshot_from_file(candidates[-1], scope_id)


def list_snapshots(*, snapshot_dir: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    root = _resolve_snapshot_root(snapshot_dir)
    if not root.exists():
        return []

    rows: list[dict[str, Any]] = []
    for scope_path in sorted(root.iterdir()):
        if not scope_path.is_dir():
            continue
        scope_id = scope_path.name
        for file_path in sorted(scope_path.glob("snapshot-*.json"), reverse=True):
            payload = _read_snapshot_payload(file_path)
            temporal_meta = payload.get("temporal") if isinstance(payload.get("temporal"), dict) else {}
            timestamp = str(temporal_meta.get("snapshot_timestamp") or _timestamp_from_file(file_path))
            rows.append(
                {
                    "scope_id": scope_id,
                    "snapshot_timestamp": timestamp,
                    "file_name": file_path.name,
                    "file_path": str(file_path),
                    "namespace": str(temporal_meta.get("namespace") or "all"),
                    "include_cluster_rbac": bool(temporal_meta.get("include_cluster_rbac", True)),
                    "ingestor": str(temporal_meta.get("ingestor") or "unknown"),
                    "enable_nvd_scoring": bool(temporal_meta.get("enable_nvd_scoring", False)),
                    "source": str(temporal_meta.get("source") or "unknown"),
                    "node_count": len(payload.get("nodes") or []),
                    "edge_count": len(payload.get("edges") or []),
                    "rolled_back_from": temporal_meta.get("rolled_back_from"),
                }
            )

    rows.sort(
        key=lambda row: (
            str(row.get("snapshot_timestamp") or ""),
            str(row.get("scope_id") or ""),
        ),
        reverse=True,
    )

    if limit > 0:
        return rows[:limit]
    return rows


def load_snapshot_payload(
    scope_id: str,
    snapshot_timestamp: str,
    *,
    snapshot_dir: str | None = None,
) -> dict[str, Any]:
    path = _find_snapshot_file(scope_id, snapshot_timestamp, snapshot_dir=snapshot_dir)
    payload = _read_snapshot_payload(path)
    if not isinstance(payload, dict):
        raise ValueError(f"snapshot payload must be a JSON object: {path}")
    return payload


def rollback_snapshot(
    scope_id: str,
    snapshot_timestamp: str,
    *,
    snapshot_dir: str | None = None,
    reason: str | None = None,
    actor: str = "api",
) -> dict[str, Any]:
    source_path = _find_snapshot_file(scope_id, snapshot_timestamp, snapshot_dir=snapshot_dir)
    payload = _read_snapshot_payload(source_path)
    if not isinstance(payload, dict):
        raise ValueError(f"snapshot payload must be a JSON object: {source_path}")

    temporal_meta = dict(payload.get("temporal") or {})
    new_timestamp = _snapshot_timestamp()
    temporal_meta["snapshot_timestamp"] = new_timestamp
    temporal_meta["scope_id"] = scope_id
    temporal_meta["rolled_back_from"] = snapshot_timestamp
    temporal_meta["rollback_actor"] = actor
    if reason:
        temporal_meta["rollback_reason"] = reason
    payload["temporal"] = temporal_meta

    root = _resolve_snapshot_root(snapshot_dir)
    scope_path = root / scope_id
    scope_path.mkdir(parents=True, exist_ok=True)

    target_path = scope_path / f"snapshot-{new_timestamp}.json"
    if target_path.exists():
        target_path = scope_path / f"snapshot-{new_timestamp}-{os.getpid()}.json"

    with target_path.open("w", encoding="utf-8") as fp:
        json.dump(payload, fp, indent=2)
        fp.write("\n")

    return {
        "scope_id": scope_id,
        "rolled_back_from": snapshot_timestamp,
        "snapshot_timestamp": new_timestamp,
        "file_path": str(target_path),
    }


def save_snapshot(
    graph_data: ClusterGraphData,
    *,
    scope_id: str,
    namespace: str | None,
    include_cluster_rbac: bool,
    ingestor: str,
    enable_nvd_scoring: bool,
    source: str,
    snapshot_dir: str | None = None,
    snapshot_timestamp: str | None = None,
) -> SnapshotRecord:
    timestamp = snapshot_timestamp or _snapshot_timestamp()
    root = _resolve_snapshot_root(snapshot_dir)
    scope_path = root / scope_id
    scope_path.mkdir(parents=True, exist_ok=True)

    file_path = scope_path / f"snapshot-{timestamp}.json"
    if file_path.exists():
        file_path = scope_path / f"snapshot-{timestamp}-{os.getpid()}.json"

    storage = NetworkXGraphStorage.from_cluster_graph_data(graph_data)
    payload = storage.to_exported_json()
    payload["temporal"] = {
        "snapshot_timestamp": timestamp,
        "scope_id": scope_id,
        "namespace": namespace or "all",
        "include_cluster_rbac": include_cluster_rbac,
        "ingestor": ingestor,
        "enable_nvd_scoring": enable_nvd_scoring,
        "source": source,
    }

    with file_path.open("w", encoding="utf-8") as fp:
        json.dump(payload, fp, indent=2)
        fp.write("\n")

    return SnapshotRecord(
        scope_id=scope_id,
        timestamp=timestamp,
        path=file_path,
        storage=storage,
        metadata=payload["temporal"],
    )


def compute_temporal_analysis(
    *,
    current_storage: NetworkXGraphStorage,
    previous_snapshot: SnapshotRecord | None,
    namespace: str | None,
    scope_id: str,
    snapshot_timestamp: str,
) -> dict[str, Any]:
    current_node_count = len(current_storage.all_nodes())
    current_edge_count = len(current_storage.all_edges())

    base: dict[str, Any] = {
        "enabled": True,
        "scope_id": scope_id,
        "snapshot_timestamp": snapshot_timestamp,
        "previous_snapshot_timestamp": previous_snapshot.timestamp if previous_snapshot else None,
        "is_first_snapshot": previous_snapshot is None,
        "new_attack_paths_count": 0,
        "alerts": [],
        "node_changes": {
            "added_count": 0,
            "removed_count": 0,
            "risk_changed_count": 0,
            "added": [],
            "removed": [],
            "risk_changed": [],
        },
        "edge_changes": {
            "added_count": 0,
            "removed_count": 0,
            "weight_changed_count": 0,
            "added": [],
            "removed": [],
            "weight_changed": [],
        },
        "connectivity": {
            "current_pair_count": 0,
            "previous_pair_count": 0,
            "new_attack_paths_count": 0,
            "resolved_attack_paths_count": 0,
            "new_attack_paths": [],
            "resolved_attack_paths": [],
        },
        "summary": {
            "current_node_count": current_node_count,
            "current_edge_count": current_edge_count,
            "previous_node_count": len(previous_snapshot.storage.all_nodes()) if previous_snapshot else 0,
            "previous_edge_count": len(previous_snapshot.storage.all_edges()) if previous_snapshot else 0,
        },
    }

    if previous_snapshot is None:
        return base

    previous_storage = previous_snapshot.storage

    node_changes = _build_node_changes(current_storage.all_nodes(), previous_storage.all_nodes())
    edge_changes = _build_edge_changes(current_storage.all_edges(), previous_storage.all_edges())

    current_connectivity = _reachable_pairs(current_storage, namespace=namespace)
    previous_connectivity = _reachable_pairs(previous_storage, namespace=namespace)

    current_keys = set(current_connectivity.keys())
    previous_keys = set(previous_connectivity.keys())
    new_keys = sorted(current_keys - previous_keys)
    resolved_keys = sorted(previous_keys - current_keys)

    new_attack_paths = [current_connectivity[key] for key in new_keys]
    resolved_attack_paths = [
        {
            "source": key[0],
            "target": key[1],
        }
        for key in resolved_keys
    ]

    alerts = [
        {
            "type": "new-attack-path",
            "severity": _severity_for_score(float(path.get("risk_score", 0.0))).lower(),
            "title": "New attack path detected",
            "description": f"{path['source']} can now reach {path['target']}.",
            "source": path["source"],
            "target": path["target"],
            "hops": path["hops"],
            "risk_score": path["risk_score"],
            "path": path["path"],
        }
        for path in new_attack_paths
    ]

    base["node_changes"] = node_changes
    base["edge_changes"] = edge_changes
    base["connectivity"] = {
        "current_pair_count": len(current_keys),
        "previous_pair_count": len(previous_keys),
        "new_attack_paths_count": len(new_attack_paths),
        "resolved_attack_paths_count": len(resolved_attack_paths),
        "new_attack_paths": new_attack_paths,
        "resolved_attack_paths": resolved_attack_paths,
    }
    base["alerts"] = alerts
    base["new_attack_paths_count"] = len(new_attack_paths)

    return base


def _build_node_changes(current_nodes: list[Node], previous_nodes: list[Node]) -> dict[str, Any]:
    current_by_id = {node.node_id: node for node in current_nodes}
    previous_by_id = {node.node_id: node for node in previous_nodes}

    current_ids = set(current_by_id.keys())
    previous_ids = set(previous_by_id.keys())

    added_ids = sorted(current_ids - previous_ids)
    removed_ids = sorted(previous_ids - current_ids)
    common_ids = sorted(current_ids & previous_ids)

    risk_changed: list[dict[str, Any]] = []
    for node_id in common_ids:
        current_risk = float(current_by_id[node_id].risk_score)
        previous_risk = float(previous_by_id[node_id].risk_score)
        delta = round(current_risk - previous_risk, 3)
        if abs(delta) < 0.001:
            continue
        risk_changed.append(
            {
                "node_id": node_id,
                "old_risk": previous_risk,
                "new_risk": current_risk,
                "risk_delta": delta,
            }
        )

    added = [
        {
            "node_id": node_id,
            "entity_type": current_by_id[node_id].entity_type,
            "namespace": current_by_id[node_id].namespace,
            "risk_score": current_by_id[node_id].risk_score,
        }
        for node_id in added_ids
    ]
    removed = [
        {
            "node_id": node_id,
            "entity_type": previous_by_id[node_id].entity_type,
            "namespace": previous_by_id[node_id].namespace,
            "risk_score": previous_by_id[node_id].risk_score,
        }
        for node_id in removed_ids
    ]

    return {
        "added_count": len(added),
        "removed_count": len(removed),
        "risk_changed_count": len(risk_changed),
        "added": added,
        "removed": removed,
        "risk_changed": risk_changed,
    }


def _build_edge_changes(current_edges: list[Edge], previous_edges: list[Edge]) -> dict[str, Any]:
    current_by_key = {_edge_key(edge): edge for edge in current_edges}
    previous_by_key = {_edge_key(edge): edge for edge in previous_edges}

    current_keys = set(current_by_key.keys())
    previous_keys = set(previous_by_key.keys())

    added_keys = sorted(current_keys - previous_keys)
    removed_keys = sorted(previous_keys - current_keys)
    common_keys = sorted(current_keys & previous_keys)

    added = [_edge_row(current_by_key[key]) for key in added_keys]
    removed = [_edge_row(previous_by_key[key]) for key in removed_keys]

    weight_changed: list[dict[str, Any]] = []
    for key in common_keys:
        current_weight = float(current_by_key[key].weight)
        previous_weight = float(previous_by_key[key].weight)
        delta = round(current_weight - previous_weight, 3)
        if abs(delta) < 0.001:
            continue
        row = _edge_row(current_by_key[key])
        row["old_weight"] = previous_weight
        row["new_weight"] = current_weight
        row["weight_delta"] = delta
        weight_changed.append(row)

    return {
        "added_count": len(added),
        "removed_count": len(removed),
        "weight_changed_count": len(weight_changed),
        "added": added,
        "removed": removed,
        "weight_changed": weight_changed,
    }


def _reachable_pairs(storage: NetworkXGraphStorage, *, namespace: str | None) -> dict[tuple[str, str], dict[str, Any]]:
    source_ids = _resolve_sources(storage, namespace)
    sink_ids = _resolve_sinks(storage, namespace)

    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for source_id in source_ids:
        for sink_id in sink_ids:
            if source_id == sink_id:
                continue
            if not storage.has_node(source_id) or not storage.has_node(sink_id):
                continue

            result = dijkstra_shortest_path(storage, source_id, sink_id, include_node_risk=False)
            if result is None:
                continue

            rows[(source_id, sink_id)] = {
                "source": source_id,
                "target": sink_id,
                "hops": result.hops,
                "risk_score": round(float(result.total_cost), 3),
                "severity": _severity_for_score(float(result.total_cost)),
                "path": list(result.path),
            }

    return rows


def _resolve_sources(storage: NetworkXGraphStorage, namespace: str | None) -> list[str]:
    nodes = _nodes_in_scope(storage, namespace)
    flagged = sorted(node.node_id for node in nodes if node.is_source)
    if flagged:
        return flagged

    pod_candidates = sorted(node.node_id for node in nodes if node.entity_type == "Pod")
    if pod_candidates:
        return [pod_candidates[0]]

    all_ids = sorted(node.node_id for node in nodes)
    return [all_ids[0]] if all_ids else []


def _resolve_sinks(storage: NetworkXGraphStorage, namespace: str | None) -> list[str]:
    nodes = _nodes_in_scope(storage, namespace)
    flagged = sorted(node.node_id for node in nodes if node.is_sink)
    if flagged:
        return flagged

    keyword_nodes = sorted(
        node.node_id
        for node in nodes
        if node.entity_type in {"Secret", "ConfigMap", "Database"}
        and any(token in node.name.lower() for token in ("db", "cred", "secret", "prod"))
    )
    if keyword_nodes:
        return keyword_nodes

    fallback = sorted(node.node_id for node in nodes if node.entity_type in {"Secret", "ConfigMap", "Database"})
    return fallback


def _nodes_in_scope(storage: NetworkXGraphStorage, namespace: str | None) -> list[Node]:
    if not namespace:
        return storage.all_nodes()
    return [
        node
        for node in storage.all_nodes()
        if node.namespace == namespace or node.namespace == "cluster"
    ]


def _edge_key(edge: Edge) -> tuple[str, str, str]:
    return (edge.source_id, edge.target_id, edge.relationship_type)


def _edge_row(edge: Edge) -> dict[str, Any]:
    return {
        "source": edge.source_id,
        "target": edge.target_id,
        "relationship_type": edge.relationship_type,
        "weight": float(edge.weight),
    }


def _severity_for_score(score: float) -> str:
    if score >= 20:
        return "CRITICAL"
    if score >= 11:
        return "HIGH"
    if score >= 9:
        return "MEDIUM"
    return "LOW"


def _resolve_snapshot_root(snapshot_dir: str | None) -> Path:
    if snapshot_dir:
        return Path(snapshot_dir)
    env_dir = os.getenv("H2F_TEMPORAL_SNAPSHOT_DIR")
    if env_dir:
        return Path(env_dir)
    return Path(__file__).resolve().parents[3] / "out" / "snapshots"


def _snapshot_timestamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")


def _slug(value: str) -> str:
    text = str(value).strip().lower()
    if not text:
        return "unknown"
    allowed = [ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in text]
    collapsed = "".join(allowed)
    while "--" in collapsed:
        collapsed = collapsed.replace("--", "-")
    return collapsed.strip("-") or "unknown"


def _load_snapshot_from_file(path: Path, scope_id: str) -> SnapshotRecord:
    with path.open("r", encoding="utf-8") as fp:
        payload = json.load(fp)
    if not isinstance(payload, dict):
        raise ValueError(f"snapshot payload must be a JSON object: {path}")

    temporal_meta = payload.get("temporal") if isinstance(payload.get("temporal"), dict) else {}
    timestamp = str(temporal_meta.get("snapshot_timestamp") or path.stem.replace("snapshot-", ""))
    storage = NetworkXGraphStorage.from_exported_json(payload)
    return SnapshotRecord(
        scope_id=scope_id,
        timestamp=timestamp,
        path=path,
        storage=storage,
        metadata=dict(temporal_meta),
    )


def _find_snapshot_file(scope_id: str, snapshot_timestamp: str, *, snapshot_dir: str | None = None) -> Path:
    root = _resolve_snapshot_root(snapshot_dir)
    scope_path = root / scope_id
    if not scope_path.exists() or not scope_path.is_dir():
        raise FileNotFoundError(f"snapshot scope not found: {scope_id}")

    exact_path = scope_path / f"snapshot-{snapshot_timestamp}.json"
    if exact_path.exists():
        return exact_path

    for file_path in sorted(scope_path.glob("snapshot-*.json"), reverse=True):
        if file_path.name.startswith(f"snapshot-{snapshot_timestamp}"):
            return file_path
        payload = _read_snapshot_payload(file_path)
        temporal_meta = payload.get("temporal") if isinstance(payload.get("temporal"), dict) else {}
        if str(temporal_meta.get("snapshot_timestamp") or "") == snapshot_timestamp:
            return file_path

    raise FileNotFoundError(f"snapshot not found: {scope_id}/{snapshot_timestamp}")


def _read_snapshot_payload(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fp:
        payload = json.load(fp)
    if not isinstance(payload, dict):
        raise ValueError(f"snapshot payload must be a JSON object: {path}")
    return payload


def _timestamp_from_file(path: Path) -> str:
    name = path.stem
    if name.startswith("snapshot-"):
        return name.replace("snapshot-", "", 1)
    return name
