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
			}
			for node in self.all_nodes()
		]
		edge_rows = [
			{
				"source_id": edge.source_id,
				"target_id": edge.target_id,
				"relationship_type": edge.relationship_type,
				"weight": edge.weight,
			}
			for edge in self.all_edges()
		]

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
		for row in node_rows:
			if not isinstance(row, dict):
				raise ValueError("each node entry must be an object")
			node = _node_from_export_row(row)
			nodes.append(node)

		edges: list[Edge] = []
		for row in edge_rows:
			if not isinstance(row, dict):
				raise ValueError("each edge entry must be an object")
			edges.append(_edge_from_export_row(row))

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
		entity_type=str(row.get("entity_type") or row.get("entityType") or "").strip(),
		name=str(row.get("name") or "").strip(),
		namespace=str(row.get("namespace") or "default").strip() or "default",
		risk_score=float(row.get("risk_score", row.get("riskScore", 0.0))),
		is_source=bool(row.get("is_source", row.get("isSource", False))),
		is_sink=bool(row.get("is_sink", row.get("isSink", False))),
	)
	provided_id = row.get("node_id") or row.get("nodeId")
	if provided_id and str(provided_id) != node.node_id:
		raise ValueError(f"node_id mismatch: expected {node.node_id}, got {provided_id}")
	return node


def _edge_from_export_row(row: dict[str, Any]) -> Edge:
	return Edge(
		source_id=str(row.get("source_id") or row.get("sourceNodeId") or row.get("source_node_id") or "").strip(),
		target_id=str(row.get("target_id") or row.get("targetNodeId") or row.get("target_node_id") or "").strip(),
		relationship_type=str(row.get("relationship_type") or row.get("relationshipType") or "").strip(),
		weight=float(row.get("weight", 1.0)),
	)

