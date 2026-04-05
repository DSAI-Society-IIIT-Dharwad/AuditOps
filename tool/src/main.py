from __future__ import annotations

import argparse
from datetime import UTC, datetime
from importlib import metadata as importlib_metadata
import json
from pathlib import Path
import sys
from typing import Any

import networkx as nx

from analysis.blast_radius import calculate_blast_radius
from analysis.critical_node import identify_critical_node
from analysis.cycle_detect import detect_cycles
from analysis.shortest_path import dijkstra_shortest_path
from core.models import ClusterGraphData, Edge
from graph.networkx_builder import NetworkXGraphStorage
from ingestion.kubectl_runner import KubectlDataIngestor
from ingestion.mock_parser import MockDataIngestor
from reporting.cli_formatter import render_cli_report
from reporting.pdf_generator import generate_pdf_report
from services.cve.nvd_scorer import NVDCveScorer
from services.temporal import build_scope_id, compute_temporal_analysis, load_previous_snapshot, save_snapshot


def main() -> int:
    args = _parse_args()
    include_cluster_rbac = _parse_bool_flag(args.include_cluster_rbac)
    enable_nvd_scoring = _parse_bool_flag(args.enable_nvd_scoring)
    ingestor_mode = "graph-in" if args.graph_in else args.ingestor

    if args.graph_in:
        storage = NetworkXGraphStorage.from_json_file(args.graph_in)
        graph_data = storage.to_cluster_graph_data()
    else:
        if args.ingestor == "mock":
            ingestor = MockDataIngestor(file_path=args.mock_file)
        else:
            kubectl_kwargs: dict[str, Any] = {
                "fallback_file": args.fallback_file,
                "namespace": args.namespace,
                "include_cluster_rbac": include_cluster_rbac,
            }
            if enable_nvd_scoring:
                kubectl_kwargs["cve_scorer"] = NVDCveScorer(
                    api_key=args.nvd_api_key,
                    timeout=args.nvd_timeout,
                )
            ingestor = KubectlDataIngestor(**kubectl_kwargs)

        graph_data = ingestor.ingest()
        storage = NetworkXGraphStorage.from_cluster_graph_data(graph_data)

    _export_graph_data(graph_data, args.graph_out)

    source_id = _resolve_source_id(storage, args.source, namespace=args.namespace)
    source_ids = _resolve_source_ids(storage, args.source, namespace=args.namespace)
    sink_ids = _resolve_sink_ids(storage, args.target, namespace=args.namespace)

    attack_path_result = _find_best_attack_path(storage, source_id, sink_ids)
    all_attack_paths = _enumerate_attack_paths(
        storage,
        source_ids=source_ids,
        sink_ids=sink_ids,
        max_depth=args.max_depth,
    )
    attack_paths = _enumerate_best_attack_paths(
        storage,
        source_ids=source_ids,
        sink_ids=sink_ids,
    )
    blast_result = calculate_blast_radius(storage, source_id=source_id, max_hops=args.max_hops)
    blast_radius_by_source = _calculate_blast_radius_by_source(storage, source_ids=source_ids, max_hops=args.max_hops)
    cycles = detect_cycles(storage)
    critical_result = identify_critical_node(
        storage,
        source_ids=source_ids,
        sink_ids=sink_ids,
        max_depth=args.max_depth,
    )
    critical_nodes = _rank_critical_nodes_from_paths(
        all_attack_paths,
        source_ids=source_ids,
        sink_ids=sink_ids,
        top_n=5,
    )

    temporal_scope_id = build_scope_id(
        namespace=args.namespace,
        include_cluster_rbac=include_cluster_rbac,
        ingestor=ingestor_mode,
        enable_nvd_scoring=enable_nvd_scoring,
        source="cli",
    )
    snapshot_timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    previous_snapshot = None
    temporal_error: str | None = None
    try:
        previous_snapshot = load_previous_snapshot(
            temporal_scope_id,
            snapshot_dir=args.snapshot_dir,
        )
    except Exception as exc:  # pragma: no cover - defensive runtime guard
        temporal_error = f"Failed to load previous snapshot: {exc}"

    temporal = compute_temporal_analysis(
        current_storage=storage,
        previous_snapshot=previous_snapshot,
        namespace=args.namespace,
        scope_id=temporal_scope_id,
        snapshot_timestamp=snapshot_timestamp,
    )
    if temporal_error:
        temporal["snapshot_error"] = temporal_error

    metadata = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "nodes": len(storage.all_nodes()),
        "edges": len(storage.all_edges()),
    }
    metadata.update(_load_mock_metadata_if_available(args.ingestor, args.mock_file))
    total_blast_exposed = sum(int(row.get("count", 0)) for row in blast_radius_by_source)

    report = {
        "metadata": metadata,
        "attack_paths": attack_paths,
        "blast_radius_by_source": blast_radius_by_source,
        "baseline_attack_paths": len(all_attack_paths),
        "critical_nodes": critical_nodes,
        "summary": {
            "attack_paths_found": len(attack_paths),
            "cycles_found": len(cycles),
            "blast_nodes_exposed": total_blast_exposed,
            "critical_node": critical_nodes[0]["node_id"] if critical_nodes else "none",
        },
        "attack_path": attack_path_result.to_dict() if attack_path_result is not None else {
            "source": source_id,
            "target": sink_ids[0] if sink_ids else "unknown-target",
            "path": [],
            "risk_score": 0.0,
        },
        "blast_radius": blast_result.to_dict(),
        "cycles": cycles,
        "critical_node": critical_result.to_dict() if critical_result is not None else {},
        "recommendations": _build_recommendations(attack_path_result, critical_result, cycles),
        "temporal": temporal,
    }

    try:
        saved_snapshot = save_snapshot(
            graph_data,
            scope_id=temporal_scope_id,
            namespace=args.namespace,
            include_cluster_rbac=include_cluster_rbac,
            ingestor=ingestor_mode,
            enable_nvd_scoring=enable_nvd_scoring,
            source="cli",
            snapshot_dir=args.snapshot_dir,
            snapshot_timestamp=snapshot_timestamp,
        )
        report["temporal"]["current_snapshot_path"] = str(saved_snapshot.path)
    except Exception as exc:  # pragma: no cover - defensive runtime guard
        report["temporal"]["snapshot_error"] = f"Failed to save snapshot: {exc}"

    selected_modes = _selected_report_modes(args)
    report_to_render = _select_report_view(report, selected_modes)

    _export_pdf_report(report, args.pdf_out)
    sys.stdout.write(render_cli_report(report_to_render))
    return 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Kubernetes Attack Path Visualizer")
    parser.add_argument(
        "--version",
        action="version",
        version=f"hack2future-cli {_resolve_cli_version()}",
    )
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
        "--pdf-out",
        default=None,
        help="Optional output path for PDF kill-chain report",
    )
    parser.add_argument(
        "--fallback-file",
        default=None,
        help="Optional fallback JSON if kubectl ingestion fails",
    )
    parser.add_argument(
        "--snapshot-dir",
        default=None,
        help="Optional directory for temporal snapshots (defaults to tool/out/snapshots).",
    )
    parser.add_argument(
        "--include-cluster-rbac",
        choices=("true", "false"),
        default="true",
        help=(
            "Include cluster-level RBAC nodes. true: include cluster role bindings "
            "(hybrid-filtered when --namespace is set). false: strict namespace mode."
        ),
    )
    parser.add_argument(
        "--enable-nvd-scoring",
        choices=("true", "false"),
        default="false",
        help="Enable live NVD CVE scoring for Pod container images.",
    )
    parser.add_argument(
        "--nvd-api-key",
        default=None,
        help="Optional NVD API key (falls back to NVD_API_KEY environment variable).",
    )
    parser.add_argument(
        "--nvd-timeout",
        type=float,
        default=10.0,
        help="Timeout in seconds for outbound NVD API requests.",
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
    parser.add_argument(
        "--full-report",
        action="store_true",
        help="Render full kill-chain report with all sections.",
    )
    parser.add_argument(
        "--attack-path",
        action="store_true",
        help="Render only the shortest attack-path section (Dijkstra).",
    )
    parser.add_argument(
        "--blast-radius",
        action="store_true",
        help="Render only blast-radius section (BFS).",
    )
    parser.add_argument(
        "--cycles",
        action="store_true",
        help="Render only cycle-detection section (DFS).",
    )
    parser.add_argument(
        "--critical-node",
        action="store_true",
        help="Render only critical-node analysis section.",
    )
    return parser.parse_args()


def _selected_report_modes(args: argparse.Namespace) -> dict[str, bool]:
    modes = {
        "full_report": bool(getattr(args, "full_report", False)),
        "attack_path": bool(getattr(args, "attack_path", False) or args.source or args.target),
        "blast_radius": bool(getattr(args, "blast_radius", False)),
        "cycles": bool(getattr(args, "cycles", False)),
        "critical_node": bool(getattr(args, "critical_node", False)),
    }

    if not any(modes.values()):
        modes["full_report"] = True

    return modes


def _select_report_view(full_report: dict[str, Any], modes: dict[str, bool]) -> dict[str, Any]:
    if modes.get("full_report"):
        return full_report

    selected: dict[str, Any] = {}
    if modes.get("attack_path"):
        selected["attack_path"] = full_report.get("attack_path", {})
    if modes.get("blast_radius"):
        selected["blast_radius"] = full_report.get("blast_radius", {})
    if modes.get("cycles"):
        selected["cycles"] = full_report.get("cycles", [])
    if modes.get("critical_node"):
        selected["critical_node"] = full_report.get("critical_node", {})

    # Keep remediation visible even in focused algorithm mode output.
    selected["recommendations"] = full_report.get("recommendations", [])
    selected["temporal"] = full_report.get("temporal", {})
    return selected


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


def _resolve_source_ids(storage: NetworkXGraphStorage, explicit_source: str | None, *, namespace: str | None) -> list[str]:
    if explicit_source:
        return [_resolve_source_id(storage, explicit_source, namespace=namespace)]

    nodes = _nodes_in_scope(storage, namespace)
    flagged = [node.node_id for node in nodes if node.is_source]
    if flagged:
        return sorted(set(flagged))

    pod_candidates = sorted(node.node_id for node in nodes if node.entity_type == "Pod")
    if pod_candidates:
        return pod_candidates

    if nodes:
        return sorted(node.node_id for node in nodes)

    return []


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


def _enumerate_attack_paths(
    storage: NetworkXGraphStorage,
    *,
    source_ids: list[str],
    sink_ids: list[str],
    max_depth: int,
    max_paths: int = 200,
) -> list[dict[str, Any]]:
    if max_depth < 1:
        return []

    graph = storage.raw_graph()
    paths: list[dict[str, Any]] = []

    for source_id in sorted(set(source_ids)):
        if not graph.has_node(source_id):
            continue
        for sink_id in sorted(set(sink_ids)):
            if source_id == sink_id or not graph.has_node(sink_id):
                continue

            try:
                for path_nodes in nx.all_simple_paths(graph, source=source_id, target=sink_id, cutoff=max_depth):
                    if len(path_nodes) < 2:
                        continue
                    paths.append(_build_path_record(storage, path_nodes))
                    if len(paths) >= max_paths:
                        return _sort_attack_paths(paths)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

    return _sort_attack_paths(paths)


def _enumerate_best_attack_paths(
    storage: NetworkXGraphStorage,
    *,
    source_ids: list[str],
    sink_ids: list[str],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for source_id in sorted(set(source_ids)):
        for sink_id in sorted(set(sink_ids)):
            if source_id == sink_id:
                continue
            result = dijkstra_shortest_path(
                storage,
                source_id,
                sink_id,
                include_node_risk=False,
            )
            if result is None:
                continue
            rows.append(_build_path_record(storage, result.path, total_cost_override=result.total_cost))

    return _sort_attack_paths(rows)


def _build_path_record(
    storage: NetworkXGraphStorage,
    path_nodes: list[str],
    *,
    total_cost_override: float | None = None,
) -> dict[str, Any]:
    edges: list[dict[str, Any]] = []
    total_cost = 0.0

    for idx in range(len(path_nodes) - 1):
        source_id = path_nodes[idx]
        target_id = path_nodes[idx + 1]
        edge = _edge_between(storage, source_id, target_id)

        edge_weight = float(edge.weight) if edge is not None else float(storage.get_edge_weight(source_id, target_id))
        total_cost += edge_weight

        edges.append(
            {
                "source": source_id,
                "target": target_id,
                "relationship": edge.relationship_type if edge is not None else "related_to",
                "weight": edge_weight,
                "cve": edge.cve if edge is not None else None,
                "cvss": edge.cvss if edge is not None else None,
            }
        )

    total_cost_value = round(total_cost_override if total_cost_override is not None else total_cost, 1)

    return {
        "source": path_nodes[0],
        "target": path_nodes[-1],
        "path": path_nodes,
        "hops": max(0, len(path_nodes) - 1),
        "risk_score": total_cost_value,
        "severity": _risk_level_for_score(total_cost_value),
        "edges": edges,
    }


def _load_mock_metadata_if_available(ingestor: str, mock_file: str) -> dict[str, Any]:
    if ingestor != "mock":
        return {}

    path = Path(mock_file)
    if not path.exists():
        return {}

    try:
        with path.open("r", encoding="utf-8") as fp:
            payload = json.load(fp)
    except (OSError, json.JSONDecodeError):
        return {}

    if not isinstance(payload, dict):
        return {}

    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        return {}

    cluster_name = metadata.get("cluster")
    generated = metadata.get("generated")
    result: dict[str, Any] = {}
    if isinstance(cluster_name, str) and cluster_name.strip():
        result["cluster"] = cluster_name.strip()
    if isinstance(generated, str) and generated.strip():
        result["source_generated"] = generated.strip()
    return result


def _edge_between(storage: NetworkXGraphStorage, source_id: str, target_id: str) -> Edge | None:
    edge_data = storage.raw_graph().get_edge_data(source_id, target_id) or {}
    edge = edge_data.get("edge")
    if isinstance(edge, Edge):
        return edge
    return None


def _sort_attack_paths(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        paths,
        key=lambda row: (
            float(row.get("risk_score", 0.0)),
            int(row.get("hops", 0)),
            tuple(str(node_id) for node_id in row.get("path", [])),
        ),
    )


def _calculate_blast_radius_by_source(
    storage: NetworkXGraphStorage,
    *,
    source_ids: list[str],
    max_hops: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for source_id in sorted(source_ids, key=_source_sort_key):
        result = calculate_blast_radius(storage, source_id=source_id, max_hops=max_hops)
        hop_map: dict[str, list[str]] = {}
        for node_id, hop in result.hops_by_node.items():
            hop_key = str(hop)
            hop_map.setdefault(hop_key, []).append(node_id)
        rows.append(
            {
                "source": source_id,
                "max_hops": max_hops,
                "count": result.count,
                "hops": hop_map,
            }
        )
    return rows


def _source_sort_key(source_id: str) -> tuple[int, int, str, str]:
    parts = source_id.split(":", 2)
    if len(parts) == 3:
        entity_type, namespace, name = parts
    else:
        entity_type, namespace, name = "", "", source_id

    entity_priority = {
        "ExternalActor": 0,
        "User": 1,
        "Service": 2,
    }.get(entity_type, 9)

    # Keep common interactive users in the default namespace ahead of automation users.
    namespace_priority = 0 if namespace == "default" else 1
    return (entity_priority, namespace_priority, name, source_id)


def _rank_critical_nodes_from_paths(
    attack_paths: list[dict[str, Any]],
    *,
    source_ids: list[str],
    sink_ids: list[str],
    top_n: int,
) -> list[dict[str, Any]]:
    baseline = len(attack_paths)
    if baseline == 0:
        return []

    protected = set(source_ids) | set(sink_ids)
    impact: dict[str, int] = {}
    first_seen: dict[str, int] = {}
    seen_counter = 0

    for row in attack_paths:
        seen_in_path: set[str] = set()
        path_nodes = [str(node_id) for node_id in row.get("path", [])]
        for node_id in path_nodes:
            if node_id in protected:
                continue
            if node_id in seen_in_path:
                continue
            seen_in_path.add(node_id)

            if node_id not in first_seen:
                first_seen[node_id] = seen_counter
                seen_counter += 1

            impact[node_id] = impact.get(node_id, 0) + 1

    ranked = [
        {
            "node_id": node_id,
            "total_paths_before": baseline,
            "total_paths_after": baseline - removed,
            "paths_removed": removed,
        }
        for node_id, removed in impact.items()
    ]
    ranked.sort(key=lambda row: (-int(row["paths_removed"]), first_seen.get(str(row["node_id"]), 10**9)))
    return ranked[:top_n]


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


def _risk_level_for_score(score: float) -> str:
    if score >= 20:
        return "CRITICAL"
    if score >= 11:
        return "HIGH"
    if score >= 9:
        return "MEDIUM"
    return "LOW"


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
            "cves": list(node.cves),
            "nvd_enriched": node.nvd_enriched,
            "nvd_source": node.nvd_source,
            "nvd_max_cvss": node.nvd_max_cvss,
            "nvd_cve_ids": list(node.nvd_cve_ids),
            "nvd_image_refs": list(node.nvd_image_refs),
        }
        for node in graph_data.nodes
    ]
    edge_rows = []
    for edge in graph_data.edges:
        row: dict[str, Any] = {
            "source_id": edge.source_id,
            "target_id": edge.target_id,
            "relationship_type": edge.relationship_type,
            "weight": edge.weight,
        }
        if edge.source_ref is not None:
            row["source_ref"] = edge.source_ref
        if edge.target_ref is not None:
            row["target_ref"] = edge.target_ref
        if edge.cve is not None:
            row["cve"] = edge.cve
        if edge.cvss is not None:
            row["cvss"] = edge.cvss
        if edge.escalation_type is not None:
            row["escalation_type"] = edge.escalation_type
        edge_rows.append(row)

    node_rows.sort(key=lambda row: str(row["node_id"]))
    edge_rows.sort(key=lambda row: (str(row["source_id"]), str(row["target_id"]), str(row["relationship_type"])))

    return {
        "schema_version": "1.0.0",
        "nodes": node_rows,
        "edges": edge_rows,
    }


def _export_pdf_report(report: dict[str, Any], output_path: str | None) -> None:
    if not output_path:
        return
    generate_pdf_report(report, output_path)


def _parse_bool_flag(value: str) -> bool:
    return value.strip().lower() == "true"


def _resolve_cli_version() -> str:
    try:
        return importlib_metadata.version("hack2future-cli")
    except importlib_metadata.PackageNotFoundError:
        return "dev"


if __name__ == "__main__":
	raise SystemExit(main())
