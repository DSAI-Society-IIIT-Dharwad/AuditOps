"""Mock ingestion parser for local JSON-driven testing."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING
from typing import Any

from core.interfaces import DataIngestor
from core.models import ClusterGraphData, Edge, Node
from ingestion.kubectl_runner import build_cluster_graph_data

if TYPE_CHECKING:
	from services.cve.nvd_scorer import NVDCveScorer


class MockParserError(RuntimeError):
	"""Raised when mock input is invalid or unreadable."""


class MockDataIngestor(DataIngestor):
	"""Loads cluster state from a local JSON file for offline analysis."""

	def __init__(self, file_path: str | Path = "mock-cluster-graph.json") -> None:
		self._file_path = Path(file_path)

	def source_name(self) -> str:
		return "mock-file"

	def ingest(self) -> ClusterGraphData:
		if not self._file_path.exists():
			raise MockParserError(f"mock file not found: {self._file_path}")

		try:
			with self._file_path.open("r", encoding="utf-8") as fp:
				payload = json.load(fp)
		except json.JSONDecodeError as exc:
			raise MockParserError(f"mock file has invalid JSON: {self._file_path}") from exc

		if not isinstance(payload, Mapping):
			raise MockParserError("mock JSON must be an object at top-level")

		return parse_cluster_graph_payload(payload)


def parse_cluster_graph_payload(
	payload: Mapping[str, Any],
	*,
	namespace_scope: str | None = None,
	include_cluster_rbac: bool = True,
	cve_scorer: NVDCveScorer | None = None,
) -> ClusterGraphData:
	"""Parse graph input from normalized graph rows or kubectl-style resources."""
	# Accept either pre-normalized graph payload or kubectl-style mocked resources.
	if "nodes" in payload and "edges" in payload:
		return _parse_normalized_graph(payload)

	return build_cluster_graph_data(
		payload,
		namespace_scope=namespace_scope,
		include_cluster_rbac=include_cluster_rbac,
		cve_scorer=cve_scorer,
	)


def _parse_normalized_graph(payload: Mapping[str, Any]) -> ClusterGraphData:
	node_rows = payload.get("nodes")
	edge_rows = payload.get("edges")
	if not isinstance(node_rows, list) or not isinstance(edge_rows, list):
		raise MockParserError("normalized payload requires list fields: nodes, edges")

	nodes_by_id: dict[str, Node] = {}
	alias_to_node_id: dict[str, str] = {}
	for row in node_rows:
		if not isinstance(row, Mapping):
			raise MockParserError("each node entry must be an object")
		node = _node_from_row(row)
		nodes_by_id[node.node_id] = node
		for alias in _node_aliases(row, node):
			alias_to_node_id[alias] = node.node_id

	edges: list[Edge] = []
	for row in edge_rows:
		if not isinstance(row, Mapping):
			raise MockParserError("each edge entry must be an object")
		edge = _edge_from_row(row, alias_to_node_id)
		if edge is None:
			continue
		if edge.source_id not in nodes_by_id:
			raise MockParserError(f"edge source node not found: {edge.source_id}")
		if edge.target_id not in nodes_by_id:
			raise MockParserError(f"edge target node not found: {edge.target_id}")
		edges.append(edge)

	return ClusterGraphData(nodes=list(nodes_by_id.values()), edges=edges)


def _node_aliases(row: Mapping[str, Any], node: Node) -> set[str]:
	aliases = {node.node_id}
	for key in ("id", "node_id", "nodeId"):
		value = _text_value(row.get(key))
		if value:
			aliases.add(value)
	return aliases


def _node_from_row(row: Mapping[str, Any]) -> Node:
	entity_type = str(row.get("entity_type") or row.get("entityType") or row.get("type") or "").strip()
	name = str(row.get("name") or "").strip()
	namespace = str(row.get("namespace") or "default").strip() or "default"
	risk_score = _float_value(row.get("risk_score", row.get("riskScore", 0.0)), "node risk_score")
	is_source = bool(row.get("is_source", row.get("isSource", False)))
	is_sink = bool(row.get("is_sink", row.get("isSink", False)))

	node = Node(
		entity_type=entity_type,
		name=name,
		namespace=namespace,
		risk_score=risk_score,
		is_source=is_source,
		is_sink=is_sink,
	)
	return node


def _edge_from_row(row: Mapping[str, Any], alias_to_node_id: Mapping[str, str]) -> Edge | None:
	source_ref = _text_value(row.get("source_id") or row.get("source_node_id") or row.get("sourceNodeId") or row.get("source"))
	target_ref = _text_value(row.get("target_id") or row.get("target_node_id") or row.get("targetNodeId") or row.get("target"))
	relationship_type = _text_value(row.get("relationship_type") or row.get("relationshipType") or row.get("relationship"))

	if not source_ref and not target_ref and not relationship_type and row.get("comment"):
		return None

	weight = _float_value(row.get("weight", 1.0), "edge weight")
	cve = _text_value(row.get("cve"))
	cvss = _optional_float_value(row.get("cvss"), "edge cvss")
	escalation_type = _text_value(row.get("escalation_type") or row.get("escalationType"))
	source_ref_meta = _text_value(row.get("source_ref"))
	target_ref_meta = _text_value(row.get("target_ref"))

	source_id = alias_to_node_id.get(source_ref, source_ref)
	target_id = alias_to_node_id.get(target_ref, target_ref)

	return Edge(
		source_id=source_id,
		target_id=target_id,
		relationship_type=relationship_type,
		weight=weight,
		source_ref=source_ref_meta or (source_ref if source_ref and source_ref != source_id else None),
		target_ref=target_ref_meta or (target_ref if target_ref and target_ref != target_id else None),
		cve=cve,
		cvss=cvss,
		escalation_type=escalation_type,
	)


def _float_value(value: Any, label: str) -> float:
	try:
		return float(value)
	except (TypeError, ValueError) as exc:
		raise MockParserError(f"{label} must be numeric") from exc


def _optional_float_value(value: Any, label: str) -> float | None:
	if value is None:
		return None
	return _float_value(value, label)


def _text_value(value: Any) -> str:
	if value is None:
		return ""
	return str(value).strip()

