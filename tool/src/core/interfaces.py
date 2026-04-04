"""Core interfaces shared across layers.

Concrete implementations should live in feature-specific packages such as
ingestion/ and graph/.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Any

from .models import ClusterGraphData, Edge, Node


class DataIngestor(ABC):
	"""Contract for loading and normalizing cluster state into graph entities."""

	@abstractmethod
	def ingest(self) -> ClusterGraphData:
		"""Return normalized nodes and edges from live or mock sources."""

	@abstractmethod
	def source_name(self) -> str:
		"""Human-readable source identifier (e.g., kubectl, mock-file)."""


class GraphStorage(ABC):
	"""Contract for in-memory graph operations used by analysis strategies."""

	@abstractmethod
	def add_node(self, node: Node) -> None:
		"""Insert a node into the backing graph."""

	@abstractmethod
	def add_edge(self, edge: Edge) -> None:
		"""Insert a directed edge into the backing graph."""

	@abstractmethod
	def add_nodes(self, nodes: Iterable[Node]) -> None:
		"""Insert multiple nodes efficiently."""

	@abstractmethod
	def add_edges(self, edges: Iterable[Edge]) -> None:
		"""Insert multiple edges efficiently."""

	@abstractmethod
	def get_node(self, node_id: str) -> Node | None:
		"""Return node metadata by id, if present."""

	@abstractmethod
	def neighbors(self, node_id: str) -> list[str]:
		"""Return outbound neighbor ids for traversal algorithms."""

	@abstractmethod
	def get_edge_weight(self, source_id: str, target_id: str) -> float:
		"""Return edge traversal cost used by shortest-path algorithms."""

	@abstractmethod
	def all_nodes(self) -> list[Node]:
		"""Return all nodes in the graph."""

	@abstractmethod
	def all_edges(self) -> list[Edge]:
		"""Return all edges in the graph."""

	@abstractmethod
	def has_node(self, node_id: str) -> bool:
		"""Check whether a node exists in the graph."""

	@abstractmethod
	def clear(self) -> None:
		"""Reset graph state (useful for no-cache fresh analysis runs)."""

	@abstractmethod
	def as_adjacency(self) -> dict[str, list[str]]:
		"""Expose adjacency information for diagnostics/testing."""

	@abstractmethod
	def raw_graph(self) -> Any:
		"""Return backing graph object for advanced operations when needed."""

