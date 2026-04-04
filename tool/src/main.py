from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from analysis.blast_radius import calculate_blast_radius
from analysis.critical_node import identify_critical_node
from analysis.cycle_detect import detect_cycles
from analysis.shortest_path import dijkstra_shortest_path
from core.models import ClusterGraphData
from graph.networkx_builder import NetworkXGraphStorage
from ingestion.kubectl_runner import KubectlDataIngestor
from ingestion.mock_parser import MockDataIngestor
from reporting.cli_formatter import render_cli_report


def main() -> int:
    args = _parse_args()
    if args.graph_in:
        storage = NetworkXGraphStorage.from_json_file(args.graph_in)
        graph_data = storage.to_cluster_graph_data()
    else:
        if args.ingestor == "mock":
            ingestor = MockDataIngestor(file_path=args.mock_file)
        else:
            ingestor = KubectlDataIngestor(fallback_file=args.fallback_file, namespace=args.namespace)

        graph_data = ingestor.ingest()
        storage = NetworkXGraphStorage.from_cluster_graph_data(graph_data)

    _export_graph_data(graph_data, args.graph_out)

    source_id = _resolve_source_id(storage, args.source, namespace=args.namespace)
    sink_ids = _resolve_sink_ids(storage, args.target, namespace=args.namespace)

    attack_path_result = _find_best_attack_path(storage, source_id, sink_ids)
    blast_result = calculate_blast_radius(storage, source_id=source_id, max_hops=args.max_hops)
    cycles = detect_cycles(storage)
    critical_result = identify_critical_node(
        storage,
        source_ids=[source_id],
        sink_ids=sink_ids,
        max_depth=args.max_depth,
    )

    report = {
        "attack_path": attack_path_result.to_dict() if attack_path_result is not None else {
            "source": source_id,
            "target": sink_ids[0] if sink_ids else "unknown-target",
            "path": [source_id],
            "risk_score": 0.0,
        },
        "blast_radius": blast_result.to_dict(),
        "cycles": cycles,
        "critical_node": critical_result.to_dict() if critical_result is not None else {},
        "recommendations": _build_recommendations(attack_path_result, critical_result, cycles),
    }

    sys.stdout.write(render_cli_report(report))
    return 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Kubernetes Attack Path Visualizer")
    parser.add_argument("--ingestor", choices=("kubectl", "mock"), default="kubectl")
    parser.add_argument(
        "--mock-file",
        default="mock-cluster-graph.json",
        help="Path to mock JSON file (used when --ingestor mock)",
    )
    parser.add_argument(
        "--graph-in",
        default=None,
        help="Optional path to exported cluster graph JSON to load directly",
    )
    parser.add_argument(
        "--graph-out",
        default="cluster-graph.json",
        help="Output path for normalized graph JSON export",
    )
    parser.add_argument(
        "--fallback-file",
        default=None,
        help="Optional fallback JSON if kubectl ingestion fails",
    )
    parser.add_argument("--source", default=None, help="Override source node_id")
    parser.add_argument("--target", default=None, help="Override target sink node_id")
    parser.add_argument(
        "--namespace",
        default=None,
        help="Namespace scope for kubectl ingestion and auto source/sink selection",
    )
    parser.add_argument("--max-hops", type=int, default=3, help="Max hops for blast radius BFS")
    parser.add_argument("--max-depth", type=int, default=8, help="Max DFS depth used in critical-node path counting")
    return parser.parse_args()


def _resolve_source_id(storage: NetworkXGraphStorage, explicit_source: str | None, *, namespace: str | None) -> str:
    if explicit_source:
        if not storage.has_node(explicit_source):
            raise KeyError(f"source node not found: {explicit_source}")
        return explicit_source

    nodes = _nodes_in_scope(storage, namespace)
    flagged = [node.node_id for node in nodes if node.is_source]
    if flagged:
        return flagged[0]

    pod_candidates = [node.node_id for node in nodes if node.entity_type == "Pod"]
    if pod_candidates:
        return sorted(pod_candidates)[0]

    if not nodes:
        raise RuntimeError("graph is empty after ingestion")
    return sorted(node.node_id for node in nodes)[0]


def _resolve_sink_ids(storage: NetworkXGraphStorage, explicit_target: str | None, *, namespace: str | None) -> list[str]:
    if explicit_target:
        if not storage.has_node(explicit_target):
            raise KeyError(f"target node not found: {explicit_target}")
        return [explicit_target]

    nodes = _nodes_in_scope(storage, namespace)
    flagged = [node.node_id for node in nodes if node.is_sink]
    if flagged:
        return sorted(flagged)

    keyword_nodes = [
        node.node_id
        for node in nodes
        if node.entity_type in {"Secret", "ConfigMap", "Database"}
        and any(token in node.name.lower() for token in ("db", "cred", "secret", "prod"))
    ]
    if keyword_nodes:
        return sorted(keyword_nodes)

    fallback = [node.node_id for node in nodes if node.entity_type in {"Secret", "ConfigMap", "Database"}]
    return sorted(fallback)


def _nodes_in_scope(storage: NetworkXGraphStorage, namespace: str | None):
    if not namespace:
        return storage.all_nodes()
    # Keep cluster-scoped entities available while filtering namespaced resources.
    return [
        node
        for node in storage.all_nodes()
        if node.namespace == namespace or node.namespace == "cluster"
    ]


def _find_best_attack_path(storage: NetworkXGraphStorage, source_id: str, sink_ids: list[str]):
    best = None
    for sink_id in sink_ids:
        path_result = dijkstra_shortest_path(storage, source_id, sink_id)
        if path_result is None:
            continue
        if best is None or path_result.total_cost < best.total_cost:
            best = path_result
    return best


def _build_recommendations(attack_path_result: Any, critical_result: Any, cycles: list[list[str]]) -> list[str]:
    recommendations: list[str] = []
    if attack_path_result is not None:
        recommendations.append("Reduce privileges on the shortest attack path to increase traversal cost.")
    else:
        recommendations.append("No source-to-sink path found with current graph constraints.")

    if critical_result is not None:
        recommendations.append(
            f"Harden or remove {critical_result.node_id} to break {critical_result.paths_removed} path(s)."
        )

    if cycles:
        recommendations.append("Break circular permission chains in role bindings and grants.")

    if not cycles and critical_result is None:
        recommendations.append("Review unflagged crown jewels and public entrypoints to improve detection fidelity.")

    return recommendations


def _export_graph_data(graph_data: ClusterGraphData, output_path: str | None) -> None:
    if not output_path:
        return

    path = Path(output_path)
    if path.parent and path.parent != Path("."):
        path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as fp:
        json.dump(_graph_data_to_dict(graph_data), fp, indent=2)
        fp.write("\n")


def _graph_data_to_dict(graph_data: ClusterGraphData) -> dict[str, Any]:
    node_rows = [
        {
            "node_id": node.node_id,
            "entity_type": node.entity_type,
            "name": node.name,
            "namespace": node.namespace,
            "risk_score": node.risk_score,
            "is_source": node.is_source,
            "is_sink": node.is_sink,
        }
        for node in graph_data.nodes
    ]
    edge_rows = [
        {
            "source_id": edge.source_id,
            "target_id": edge.target_id,
            "relationship_type": edge.relationship_type,
            "weight": edge.weight,
        }
        for edge in graph_data.edges
    ]

    node_rows.sort(key=lambda row: str(row["node_id"]))
    edge_rows.sort(key=lambda row: (str(row["source_id"]), str(row["target_id"]), str(row["relationship_type"])))

    return {
        "schema_version": "1.0.0",
        "nodes": node_rows,
        "edges": edge_rows,
    }


if __name__ == "__main__":
	raise SystemExit(main())
