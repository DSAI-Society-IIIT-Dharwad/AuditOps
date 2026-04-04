"""NetworkX-backed graph storage implementation."""

from __future__ import annotations

from collections.abc import Iterable
import json
from pathlib import Path
from typing import Any

import networkx as nx

from core.interfaces import GraphStorage
from core.models import ClusterGraphData, Edge, Node


class NetworkXGraphStorage(GraphStorage):
	"""Concrete graph storage built on top of networkx.DiGraph."""

	def __init__(self) -> None:
		self._graph = nx.DiGraph()

	def add_node(self, node: Node) -> None:
		self._graph.add_node(node.node_id, node=node)

	def add_edge(self, edge: Edge) -> None:
		if not self._graph.has_node(edge.source_id):
			raise KeyError(f"source node does not exist: {edge.source_id}")
		if not self._graph.has_node(edge.target_id):
			raise KeyError(f"target node does not exist: {edge.target_id}")

		self._graph.add_edge(
			edge.source_id,
			edge.target_id,
			relationship_type=edge.relationship_type,
			weight=edge.weight,
			edge=edge,
		)

	def add_nodes(self, nodes: Iterable[Node]) -> None:
		for node in nodes:
			self.add_node(node)

	def add_edges(self, edges: Iterable[Edge]) -> None:
		for edge in edges:
			self.add_edge(edge)

	def get_node(self, node_id: str) -> Node | None:
		if not self._graph.has_node(node_id):
			return None
		node_data = self._graph.nodes[node_id]
		return node_data.get("node")

	def neighbors(self, node_id: str) -> list[str]:
		if not self._graph.has_node(node_id):
			return []
		return list(self._graph.successors(node_id))

	def get_edge_weight(self, source_id: str, target_id: str) -> float:
		if not self._graph.has_edge(source_id, target_id):
			raise KeyError(f"edge not found: {source_id} -> {target_id}")
		edge_data = self._graph.get_edge_data(source_id, target_id)
		if edge_data is None:
			raise KeyError(f"edge not found: {source_id} -> {target_id}")
		return float(edge_data.get("weight", 1.0))

	def all_nodes(self) -> list[Node]:
		return [data["node"] for _, data in self._graph.nodes(data=True) if "node" in data]

	def all_edges(self) -> list[Edge]:
		edges: list[Edge] = []
		for source_id, target_id, data in self._graph.edges(data=True):
			stored = data.get("edge")
			if isinstance(stored, Edge):
				edges.append(stored)
				continue
			edges.append(
				Edge(
					source_id=source_id,
					target_id=target_id,
					relationship_type=str(data.get("relationship_type", "related_to")),
					weight=float(data.get("weight", 1.0)),
				)
			)
		return edges

	def has_node(self, node_id: str) -> bool:
		return self._graph.has_node(node_id)

	def clear(self) -> None:
		self._graph.clear()

	def as_adjacency(self) -> dict[str, list[str]]:
		return {node_id: list(self._graph.successors(node_id)) for node_id in self._graph.nodes}

	def raw_graph(self) -> nx.DiGraph:
		return self._graph

	def is_dag(self) -> bool:
		"""Return whether the currently built directed graph is acyclic."""
		return nx.is_directed_acyclic_graph(self._graph)

	def to_cluster_graph_data(self) -> ClusterGraphData:
		"""Return normalized dataclass transport object from current graph state."""
		return ClusterGraphData(nodes=self.all_nodes(), edges=self.all_edges())

	def to_exported_json(self) -> dict[str, Any]:
		"""Return deterministic JSON-ready graph payload used by artifact export."""
		node_rows = [
			{
				"node_id": node.node_id,
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
			}
			for node in self.all_nodes()
		]
		edge_rows = []
		for edge in self.all_edges():
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

	def save_json(self, file_path: str | Path) -> None:
		"""Write exported JSON artifact to disk."""
		path = Path(file_path)
		if path.parent and path.parent != Path("."):
			path.parent.mkdir(parents=True, exist_ok=True)
		with path.open("w", encoding="utf-8") as fp:
			json.dump(self.to_exported_json(), fp, indent=2)
			fp.write("\n")

	@classmethod
	def from_cluster_graph_data(cls, data: ClusterGraphData) -> NetworkXGraphStorage:
		"""Create and populate storage from normalized cluster graph data."""
		storage = cls()
		storage.add_nodes(data.nodes)
		storage.add_edges(data.edges)
		return storage

	@classmethod
	def from_exported_json(cls, payload: dict[str, Any]) -> NetworkXGraphStorage:
		"""Build graph from exported JSON payload.

		Cycle handling: this loader does not enforce DAG constraints. Cycles are
		preserved as-is so dedicated analysis modules can detect and report them.
		"""
		if not isinstance(payload, dict):
			raise ValueError("graph artifact must be a JSON object")

		schema_version = payload.get("schema_version")
		if schema_version is not None and not str(schema_version).startswith("1."):
			raise ValueError(f"unsupported schema_version: {schema_version}")

		node_rows = payload.get("nodes", [])
		edge_rows = payload.get("edges", [])
		if not isinstance(node_rows, list) or not isinstance(edge_rows, list):
			raise ValueError("graph artifact must include list fields: nodes, edges")

		nodes: list[Node] = []
		alias_to_node_id: dict[str, str] = {}
		for row in node_rows:
			if not isinstance(row, dict):
				raise ValueError("each node entry must be an object")
			node = _node_from_export_row(row)
			nodes.append(node)
			for alias in _node_aliases_from_row(row, node):
				alias_to_node_id[alias] = node.node_id

		edges: list[Edge] = []
		for row in edge_rows:
			if not isinstance(row, dict):
				raise ValueError("each edge entry must be an object")
			edge = _edge_from_export_row(row, alias_to_node_id)
			if edge is None:
				continue
			edges.append(edge)

		return cls.from_cluster_graph_data(ClusterGraphData(nodes=nodes, edges=edges))

	@classmethod
	def from_json_file(cls, file_path: str | Path) -> NetworkXGraphStorage:
		"""Build graph from an exported JSON artifact file."""
		path = Path(file_path)
		with path.open("r", encoding="utf-8") as fp:
			payload = json.load(fp)
		if not isinstance(payload, dict):
			raise ValueError("graph artifact file must contain a JSON object")
		return cls.from_exported_json(payload)


def _node_from_export_row(row: dict[str, Any]) -> Node:
	node = Node(
		entity_type=str(row.get("entity_type") or row.get("entityType") or row.get("type") or "").strip(),
		name=str(row.get("name") or "").strip(),
		namespace=str(row.get("namespace") or "default").strip() or "default",
		risk_score=float(row.get("risk_score", row.get("riskScore", 0.0))),
		is_source=bool(row.get("is_source", row.get("isSource", False))),
		is_sink=bool(row.get("is_sink", row.get("isSink", False))),
		nvd_enriched=bool(row.get("nvd_enriched", row.get("nvdEnriched", False))),
		nvd_source=str(row.get("nvd_source") or row.get("nvdSource") or "").strip() or None,
		nvd_max_cvss=(
			float(row["nvd_max_cvss"])
			if row.get("nvd_max_cvss") is not None
			else (float(row["nvdMaxCvss"]) if row.get("nvdMaxCvss") is not None else None)
		),
		nvd_cve_ids=_string_tuple_from_row(row, "nvd_cve_ids", "nvdCveIds"),
		nvd_image_refs=_string_tuple_from_row(row, "nvd_image_refs", "nvdImageRefs"),
	)
	return node


def _string_tuple_from_row(row: dict[str, Any], *keys: str) -> tuple[str, ...]:
	for key in keys:
		value = row.get(key)
		if isinstance(value, list):
			return tuple(str(item).strip() for item in value if str(item).strip())
	return ()


def _node_aliases_from_row(row: dict[str, Any], node: Node) -> set[str]:
	aliases = {node.node_id}
	for key in ("id", "node_id", "nodeId"):
		value = str(row.get(key) or "").strip()
		if value:
			aliases.add(value)
	return aliases


def _edge_from_export_row(row: dict[str, Any], alias_to_node_id: dict[str, str]) -> Edge | None:
	source_ref = str(
		row.get("source_id")
		or row.get("sourceNodeId")
		or row.get("source_node_id")
		or row.get("source")
		or ""
	).strip()
	target_ref = str(
		row.get("target_id")
		or row.get("targetNodeId")
		or row.get("target_node_id")
		or row.get("target")
		or ""
	).strip()
	relationship_type = str(row.get("relationship_type") or row.get("relationshipType") or row.get("relationship") or "").strip()

	if not source_ref and not target_ref and not relationship_type and row.get("comment"):
		return None

	source_id = alias_to_node_id.get(source_ref, source_ref)
	target_id = alias_to_node_id.get(target_ref, target_ref)
	source_ref_meta = str(row.get("source_ref") or "").strip() or None
	target_ref_meta = str(row.get("target_ref") or "").strip() or None

	return Edge(
		source_id=source_id,
		target_id=target_id,
		relationship_type=relationship_type,
		weight=float(row.get("weight", 1.0)),
		source_ref=source_ref_meta or (source_ref if source_ref and source_ref != source_id else None),
		target_ref=target_ref_meta or (target_ref if target_ref and target_ref != target_id else None),
		cve=str(row.get("cve") or "").strip() or None,
		cvss=float(row["cvss"]) if row.get("cvss") is not None else None,
		escalation_type=str(row.get("escalation_type") or row.get("escalationType") or "").strip() or None,
	)

