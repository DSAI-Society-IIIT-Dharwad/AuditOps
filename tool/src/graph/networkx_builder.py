"""NetworkX-backed graph storage implementation."""

from __future__ import annotations

from collections.abc import Iterable

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

	@classmethod
	def from_cluster_graph_data(cls, data: ClusterGraphData) -> NetworkXGraphStorage:
		"""Create and populate storage from normalized cluster graph data."""
		storage = cls()
		storage.add_nodes(data.nodes)
		storage.add_edges(data.edges)
		return storage

