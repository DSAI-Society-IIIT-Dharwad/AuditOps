"""Critical node analysis based on source-to-sink path disruption."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import networkx as nx

from core.interfaces import GraphStorage


@dataclass(slots=True, frozen=True)
class CriticalNodeResult:
	"""Node whose removal disrupts the largest number of attack paths."""

	node_id: str
	total_paths_before: int
	total_paths_after: int
	paths_removed: int

	def to_dict(self) -> dict[str, Any]:
		return {
			"node_id": self.node_id,
			"total_paths_before": self.total_paths_before,
			"total_paths_after": self.total_paths_after,
			"paths_removed": self.paths_removed,
		}


def identify_critical_node(
	storage: GraphStorage,
	*,
	source_ids: list[str] | None = None,
	sink_ids: list[str] | None = None,
	max_depth: int = 8,
) -> CriticalNodeResult | None:
	"""Identify node whose removal breaks the most source-to-sink paths."""
	graph = storage.raw_graph().copy()

	if source_ids is None:
		source_ids = [node.node_id for node in storage.all_nodes() if node.is_source]
	if sink_ids is None:
		sink_ids = [node.node_id for node in storage.all_nodes() if node.is_sink]

	if not source_ids or not sink_ids:
		return None

	base_paths = _count_source_to_sink_paths(graph, source_ids, sink_ids, max_depth)
	if base_paths == 0:
		return None

	protected = set(source_ids) | set(sink_ids)
	best_node: str | None = None
	best_after = base_paths

	for node_id in sorted(graph.nodes):
		if node_id in protected:
			continue
		trial = graph.copy()
		trial.remove_node(node_id)
		after_paths = _count_source_to_sink_paths(trial, source_ids, sink_ids, max_depth)
		if after_paths < best_after:
			best_after = after_paths
			best_node = node_id

	if best_node is None:
		return None

	return CriticalNodeResult(
		node_id=best_node,
		total_paths_before=base_paths,
		total_paths_after=best_after,
		paths_removed=base_paths - best_after,
	)


def _count_source_to_sink_paths(
	graph: nx.DiGraph,
	source_ids: list[str],
	sink_ids: list[str],
	max_depth: int,
) -> int:
	sources = [node_id for node_id in source_ids if graph.has_node(node_id)]
	sinks = [node_id for node_id in sink_ids if graph.has_node(node_id)]
	if not sources or not sinks:
		return 0

	total_paths = 0
	for source_id in sources:
		for sink_id in sinks:
			if source_id == sink_id:
				continue
			try:
				for _ in nx.all_simple_paths(graph, source=source_id, target=sink_id, cutoff=max_depth):
					total_paths += 1
			except (nx.NetworkXNoPath, nx.NodeNotFound):
				continue
	return total_paths

