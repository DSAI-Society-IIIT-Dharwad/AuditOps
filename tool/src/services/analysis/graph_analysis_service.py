from __future__ import annotations

from typing import Any

from analysis.blast_radius import calculate_blast_radius
from analysis.critical_node import identify_critical_node
from analysis.cycle_detect import detect_cycles
from graph.networkx_builder import NetworkXGraphStorage
from ingestion.kubectl_runner import KubectlDataIngestor
from main import (
    _build_recommendations,
    _calculate_blast_radius_by_source,
    _enumerate_attack_paths,
    _enumerate_best_attack_paths,
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
    storage = NetworkXGraphStorage.from_cluster_graph_data(graph_data)

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
    attack_paths = _enumerate_best_attack_paths(storage, source_ids=source_ids, sink_ids=sink_ids)[:18]
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
            "attack_paths_found": len(attack_paths),
            "cycles_found": len(cycles),
            "blast_nodes_exposed": total_blast_exposed,
            "critical_node": critical_nodes[0]["node_id"] if critical_nodes else "none",
        },
    }
    return response
