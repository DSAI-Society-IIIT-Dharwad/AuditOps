from __future__ import annotations

from datetime import UTC, datetime
from collections.abc import Mapping
from typing import Any

from analysis.blast_radius import calculate_blast_radius
from analysis.critical_node import identify_critical_node
from analysis.cycle_detect import detect_cycles
from graph.networkx_builder import NetworkXGraphStorage
from ingestion.kubectl_runner import KubectlDataIngestor
from ingestion.mock_parser import parse_cluster_graph_payload
from main import (
    _build_recommendations,
    _calculate_blast_radius_by_source,
    _enumerate_attack_paths,
    _find_best_attack_path,
    _rank_critical_nodes_from_paths,
    _resolve_sink_ids,
    _resolve_source_id,
    _resolve_source_ids,
)
from services.cve.nvd_scorer import NVDCveScorer
from services.contracts.graph_analysis_contract import (
    build_attack_path,
    build_base_response,
    build_blast_radius,
    build_critical_node,
    build_cycles,
    build_edges,
    build_nodes,
)
from services.temporal import build_scope_id, compute_temporal_analysis, load_previous_snapshot, save_snapshot


def get_graph_analysis(
    *,
    namespace: str | None,
    include_cluster_rbac: bool = True,
    enable_nvd_scoring: bool = False,
    max_hops: int = 3,
    max_depth: int = 8,
) -> dict[str, Any]:
    cve_scorer = NVDCveScorer() if enable_nvd_scoring else None
    ingestor = KubectlDataIngestor(
        namespace=namespace,
        include_cluster_rbac=include_cluster_rbac,
        cve_scorer=cve_scorer,
    )
    graph_data = ingestor.ingest()
    return _build_graph_analysis_response(
        graph_data,
        namespace=namespace,
        include_cluster_rbac=include_cluster_rbac,
        enable_nvd_scoring=enable_nvd_scoring,
        max_hops=max_hops,
        max_depth=max_depth,
        temporal_source="api",
        temporal_ingestor="kubectl",
    )


def get_graph_analysis_from_payload(
    *,
    graph_payload: Mapping[str, Any],
    namespace: str | None,
    include_cluster_rbac: bool = True,
    enable_nvd_scoring: bool = False,
    max_hops: int = 3,
    max_depth: int = 8,
) -> dict[str, Any]:
    cve_scorer = NVDCveScorer() if enable_nvd_scoring else None
    graph_data = parse_cluster_graph_payload(
        graph_payload,
        namespace_scope=namespace,
        include_cluster_rbac=include_cluster_rbac,
        cve_scorer=cve_scorer,
    )
    return _build_graph_analysis_response(
        graph_data,
        namespace=namespace,
        include_cluster_rbac=include_cluster_rbac,
        enable_nvd_scoring=enable_nvd_scoring,
        max_hops=max_hops,
        max_depth=max_depth,
        temporal_source="api-upload",
        temporal_ingestor="payload",
    )


def _build_graph_analysis_response(
    graph_data: Any,
    *,
    namespace: str | None,
    include_cluster_rbac: bool,
    enable_nvd_scoring: bool,
    max_hops: int,
    max_depth: int,
    temporal_source: str,
    temporal_ingestor: str,
) -> dict[str, Any]:
    storage = NetworkXGraphStorage.from_cluster_graph_data(graph_data)

    temporal_scope_id = build_scope_id(
        namespace=namespace,
        include_cluster_rbac=include_cluster_rbac,
        ingestor=temporal_ingestor,
        enable_nvd_scoring=enable_nvd_scoring,
        source=temporal_source,
    )
    snapshot_timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    previous_snapshot = None
    temporal_error: str | None = None
    try:
        previous_snapshot = load_previous_snapshot(temporal_scope_id)
    except Exception as exc:  # pragma: no cover - defensive runtime guard
        temporal_error = f"Failed to load previous snapshot: {exc}"

    source_id = _resolve_source_id(storage, explicit_source=None, namespace=namespace)
    source_ids = _resolve_source_ids(storage, explicit_source=None, namespace=namespace)
    sink_ids = _resolve_sink_ids(storage, explicit_target=None, namespace=namespace)

    attack_path_result = _find_best_attack_path(storage, source_id, sink_ids)
    all_attack_paths = _enumerate_attack_paths(
        storage,
        source_ids=source_ids,
        sink_ids=sink_ids,
        max_depth=max_depth,
    )
    attack_paths = all_attack_paths
    blast_result = calculate_blast_radius(storage, source_id=source_id, max_hops=max_hops)
    blast_radius_by_source = _calculate_blast_radius_by_source(storage, source_ids=source_ids, max_hops=max_hops)
    cycles = detect_cycles(storage)
    critical_result = identify_critical_node(
        storage,
        source_ids=source_ids,
        sink_ids=sink_ids,
        max_depth=max_depth,
    )
    critical_nodes = _rank_critical_nodes_from_paths(
        all_attack_paths,
        source_ids=source_ids,
        sink_ids=sink_ids,
        top_n=5,
    )

    temporal = compute_temporal_analysis(
        current_storage=storage,
        previous_snapshot=previous_snapshot,
        namespace=namespace,
        scope_id=temporal_scope_id,
        snapshot_timestamp=snapshot_timestamp,
    )
    if temporal_error:
        temporal["snapshot_error"] = temporal_error
    temporal_node_rows = _build_temporal_node_rows(temporal)

    nodes = storage.all_nodes()
    edges = storage.all_edges()
    edge_rows, edge_ids_by_pair = build_edges(edges)

    response = build_base_response(namespace=namespace, nodes=nodes, edges=edges)
    response["nodes"] = build_nodes(nodes, temporal_node_by_id=temporal_node_rows)
    response["edges"] = edge_rows
    response["analysis"] = {
        "attack_path": build_attack_path(
            attack_path_result,
            source_id=source_id,
            sink_ids=sink_ids,
            edge_ids_by_pair=edge_ids_by_pair,
        ),
        "blast_radius": build_blast_radius(blast_result),
        "cycles": build_cycles(cycles),
        "critical_node": build_critical_node(critical_result),
        "recommendations": _build_recommendations(attack_path_result, critical_result, cycles),
    }

    total_blast_exposed = sum(int(row.get("count", 0)) for row in blast_radius_by_source)
    response["report"] = {
        "metadata": {
            "generated_at": response["generated_at"],
            "cluster": response["context"].get("cluster", ""),
            "namespace": response["context"].get("namespace", "all"),
            "nodes": response["summary"].get("node_count", 0),
            "edges": response["summary"].get("edge_count", 0),
        },
        "attack_paths": attack_paths,
        "blast_radius_by_source": blast_radius_by_source,
        "cycles": cycles,
        "baseline_attack_paths": len(all_attack_paths),
        "critical_nodes": critical_nodes,
        "summary": {
            "attack_paths_found": len(all_attack_paths),
            "cycles_found": len(cycles),
            "blast_nodes_exposed": total_blast_exposed,
            "critical_node": critical_nodes[0]["node_id"] if critical_nodes else "none",
        },
        "temporal": temporal,
    }

    response["temporal"] = temporal

    try:
        saved_snapshot = save_snapshot(
            graph_data,
            scope_id=temporal_scope_id,
            namespace=namespace,
            include_cluster_rbac=include_cluster_rbac,
            ingestor=temporal_ingestor,
            enable_nvd_scoring=enable_nvd_scoring,
            source=temporal_source,
            snapshot_timestamp=snapshot_timestamp,
        )
        response["temporal"]["current_snapshot_path"] = str(saved_snapshot.path)
        response["report"]["temporal"]["current_snapshot_path"] = str(saved_snapshot.path)
    except Exception as exc:  # pragma: no cover - defensive runtime guard
        response["temporal"]["snapshot_error"] = f"Failed to save snapshot: {exc}"
        response["report"]["temporal"]["snapshot_error"] = response["temporal"]["snapshot_error"]

    return response


def _build_temporal_node_rows(temporal: dict[str, Any]) -> dict[str, dict[str, Any]]:
    node_rows: dict[str, dict[str, Any]] = {}
    node_changes = temporal.get("node_changes") if isinstance(temporal.get("node_changes"), dict) else {}

    for added in node_changes.get("added", []):
        if not isinstance(added, dict):
            continue
        node_id = str(added.get("node_id") or "").strip()
        if not node_id:
            continue
        node_rows[node_id] = {
            "status": "added",
            "risk_delta": None,
        }

    for changed in node_changes.get("risk_changed", []):
        if not isinstance(changed, dict):
            continue
        node_id = str(changed.get("node_id") or "").strip()
        if not node_id:
            continue
        node_rows[node_id] = {
            "status": "risk_changed",
            "risk_delta": changed.get("risk_delta"),
        }

    return node_rows
