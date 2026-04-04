from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from collections.abc import Mapping
from typing import Any

from analysis.blast_radius import BlastRadiusResult
from analysis.critical_node import CriticalNodeResult
from analysis.shortest_path import ShortestPathResult
from core.models import Edge, Node


def build_context(namespace: str | None) -> dict[str, Any]:
    return {
        "cluster": "kind-hack2future",
        "namespace": namespace or "all",
        "directed": True,
    }


def build_summary(nodes: list[Node], edges: list[Edge]) -> dict[str, int]:
    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "source_count": sum(1 for node in nodes if node.is_source),
        "sink_count": sum(1 for node in nodes if node.is_sink),
    }


def build_nodes(
    nodes: list[Node],
    *,
    temporal_node_by_id: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    temporal_node_by_id = temporal_node_by_id or {}
    sorted_nodes = sorted(nodes, key=lambda node: node.node_id)
    rows: list[dict[str, Any]] = []
    for node in sorted_nodes:
        temporal_row = temporal_node_by_id.get(node.node_id, {})
        temporal_status = temporal_row.get("status")
        risk_delta = temporal_row.get("risk_delta")

        rows.append(
            {
                "id": node.node_id,
                "entity_type": node.entity_type,
                "name": node.name,
                "namespace": node.namespace,
                "risk_score": node.risk_score,
                "is_source": node.is_source,
                "is_sink": node.is_sink,
                "nvd_enriched": node.nvd_enriched,
                "nvd_source": node.nvd_source,
                "nvd_max_cvss": node.nvd_max_cvss,
                "nvd_cve_ids": list(node.nvd_cve_ids),
                "nvd_image_refs": list(node.nvd_image_refs),
                "temporal_status": temporal_status,
                "risk_delta": risk_delta,
                "tags": _tags_for_node(node, temporal_status=temporal_status),
            }
        )

    return rows


def build_edges(edges: list[Edge]) -> tuple[list[dict[str, Any]], dict[tuple[str, str], list[str]]]:
    sorted_edges = sorted(edges, key=lambda edge: (edge.source_id, edge.target_id, edge.relationship_type))
    by_pair: dict[tuple[str, str], list[str]] = defaultdict(list)
    rows: list[dict[str, Any]] = []

    for idx, edge in enumerate(sorted_edges, start=1):
        edge_id = f"e-{idx}"
        by_pair[(edge.source_id, edge.target_id)].append(edge_id)
        rows.append(
            {
                "id": edge_id,
                "source": edge.source_id,
                "target": edge.target_id,
                "relationship_type": edge.relationship_type,
                "weight": edge.weight,
            }
        )

    return rows, dict(by_pair)


def build_attack_path(
    attack_path_result: ShortestPathResult | None,
    *,
    source_id: str,
    sink_ids: list[str],
    edge_ids_by_pair: dict[tuple[str, str], list[str]],
) -> dict[str, Any]:
    if attack_path_result is None:
        return {
            "source": source_id,
            "target": sink_ids[0] if sink_ids else "unknown-target",
            "path_node_ids": [],
            "path_edge_ids": [],
            "hops": 0,
            "risk_score": 0.0,
            "severity": "LOW",
        }

    node_ids = attack_path_result.path
    edge_ids: list[str] = []
    for index in range(len(node_ids) - 1):
        pair = (node_ids[index], node_ids[index + 1])
        pair_edge_ids = edge_ids_by_pair.get(pair, [])
        if pair_edge_ids:
            edge_ids.append(pair_edge_ids[0])

    return {
        "source": attack_path_result.source,
        "target": attack_path_result.target,
        "path_node_ids": node_ids,
        "path_edge_ids": edge_ids,
        "hops": attack_path_result.hops,
        "risk_score": round(attack_path_result.total_cost, 3),
        "severity": _severity_for_score(attack_path_result.total_cost),
    }


def build_blast_radius(blast_result: BlastRadiusResult) -> dict[str, Any]:
    return {
        "source": blast_result.source,
        "max_hops": blast_result.max_hops,
        "reachable_node_ids": blast_result.reachable_nodes,
        "hops_by_node": blast_result.hops_by_node,
    }


def build_cycles(cycles: list[list[str]]) -> dict[str, Any]:
    return {
        "count": len(cycles),
        "items": [{"node_ids": cycle} for cycle in cycles],
    }


def build_critical_node(critical_result: CriticalNodeResult | None) -> dict[str, Any]:
    if critical_result is None:
        return {}
    return critical_result.to_dict()


def build_base_response(
    *,
    namespace: str | None,
    nodes: list[Node],
    edges: list[Edge],
) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "context": build_context(namespace),
        "summary": build_summary(nodes, edges),
    }


def _severity_for_score(score: float) -> str:
    if score >= 25:
        return "CRITICAL"
    if score >= 15:
        return "HIGH"
    if score >= 7:
        return "MEDIUM"
    return "LOW"


def _tags_for_node(node: Node, *, temporal_status: Any = None) -> list[str]:
    tags: list[str] = []
    if node.is_source:
        tags.append("public-entrypoint")
    if node.is_sink:
        tags.append("crown-jewel")
    if node.entity_type in {"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"} and node.risk_score >= 6.5:
        tags.append("rbac-high-risk")
    if node.nvd_enriched:
        tags.append("nvd-enriched")
    if temporal_status:
        tags.append(f"temporal-{str(temporal_status)}")
    return tags
