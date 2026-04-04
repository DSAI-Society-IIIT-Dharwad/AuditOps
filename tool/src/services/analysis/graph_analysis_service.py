from __future__ import annotations

from typing import Any

from analysis.blast_radius import calculate_blast_radius
from analysis.critical_node import identify_critical_node
from analysis.cycle_detect import detect_cycles
from graph.networkx_builder import NetworkXGraphStorage
from ingestion.kubectl_runner import KubectlDataIngestor
from main import _build_recommendations, _find_best_attack_path, _resolve_sink_ids, _resolve_source_id
from services.contracts.graph_analysis_contract import (
    build_attack_path,
    build_base_response,
    build_blast_radius,
    build_critical_node,
    build_cycles,
    build_edges,
    build_nodes,
)


def get_graph_analysis(
    *,
    namespace: str | None,
    include_cluster_rbac: bool = True,
    max_hops: int = 3,
    max_depth: int = 8,
) -> dict[str, Any]:
    ingestor = KubectlDataIngestor(namespace=namespace, include_cluster_rbac=include_cluster_rbac)
    graph_data = ingestor.ingest()
    storage = NetworkXGraphStorage.from_cluster_graph_data(graph_data)

    source_id = _resolve_source_id(storage, explicit_source=None, namespace=namespace)
    sink_ids = _resolve_sink_ids(storage, explicit_target=None, namespace=namespace)

    attack_path_result = _find_best_attack_path(storage, source_id, sink_ids)
    blast_result = calculate_blast_radius(storage, source_id=source_id, max_hops=max_hops)
    cycles = detect_cycles(storage)
    critical_result = identify_critical_node(
        storage,
        source_ids=[source_id],
        sink_ids=sink_ids,
        max_depth=max_depth,
    )

    nodes = storage.all_nodes()
    edges = storage.all_edges()
    edge_rows, edge_ids_by_pair = build_edges(edges)

    response = build_base_response(namespace=namespace, nodes=nodes, edges=edges)
    response["nodes"] = build_nodes(nodes)
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
    return response
