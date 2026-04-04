"""Shortest path analysis using Dijkstra's algorithm."""

from __future__ import annotations

from dataclasses import dataclass
import heapq
from typing import Any

from core.interfaces import GraphStorage


@dataclass(slots=True, frozen=True)
class ShortestPathResult:
	"""Result payload for weighted shortest path queries."""

	source: str
	target: str
	path: list[str]
	total_cost: float

	@property
	def hops(self) -> int:
		return max(0, len(self.path) - 1)

	def to_dict(self) -> dict[str, Any]:
		return {
			"source": self.source,
			"target": self.target,
			"path": self.path,
			"risk_score": self.total_cost,
			"hops": self.hops,
		}


def dijkstra_shortest_path(
	storage: GraphStorage,
	source_id: str,
	target_id: str,
	*,
	penalty_by_edge: dict[tuple[str, str], float] | None = None,
	include_node_risk: bool = True,
) -> ShortestPathResult | None:
	"""Return minimum-cost path from source to target.

	Cost model:
	- base edge weight
	- plus target-node risk score (optional)
	- plus optional misconfiguration penalty per edge
	"""
	if not storage.has_node(source_id):
		raise KeyError(f"source node not found: {source_id}")
	if not storage.has_node(target_id):
		raise KeyError(f"target node not found: {target_id}")

	penalty_by_edge = penalty_by_edge or {}

	distances: dict[str, float] = {source_id: 0.0}
	previous: dict[str, str] = {}
	pq: list[tuple[float, str]] = [(0.0, source_id)]
	visited: set[str] = set()

	while pq:
		current_cost, current = heapq.heappop(pq)
		if current in visited:
			continue
		visited.add(current)

		if current == target_id:
			break

		for neighbor in storage.neighbors(current):
			if neighbor in visited:
				continue

			edge_cost = storage.get_edge_weight(current, neighbor)
			node_risk = 0.0
			if include_node_risk:
				node = storage.get_node(neighbor)
				node_risk = float(node.risk_score) if node is not None else 0.0
			penalty = float(penalty_by_edge.get((current, neighbor), 0.0))
			step_cost = edge_cost + node_risk + penalty

			new_cost = current_cost + step_cost
			if new_cost < distances.get(neighbor, float("inf")):
				distances[neighbor] = new_cost
				previous[neighbor] = current
				heapq.heappush(pq, (new_cost, neighbor))

	if target_id not in distances:
		return None

	return ShortestPathResult(
		source=source_id,
		target=target_id,
		path=_reconstruct_path(previous, source_id, target_id),
		total_cost=distances[target_id],
	)


def shortest_path_to_any_sink(
	storage: GraphStorage,
	source_id: str,
	*,
	penalty_by_edge: dict[tuple[str, str], float] | None = None,
	include_node_risk: bool = True,
) -> ShortestPathResult | None:
	"""Return shortest path from source to the nearest sink node."""
	sink_ids = [node.node_id for node in storage.all_nodes() if node.is_sink]
	best: ShortestPathResult | None = None

	for sink_id in sink_ids:
		result = dijkstra_shortest_path(
			storage,
			source_id,
			sink_id,
			penalty_by_edge=penalty_by_edge,
			include_node_risk=include_node_risk,
		)
		if result is None:
			continue
		if best is None or result.total_cost < best.total_cost:
			best = result

	return best


def _reconstruct_path(previous: dict[str, str], source_id: str, target_id: str) -> list[str]:
	path: list[str] = [target_id]
	cursor = target_id
	while cursor != source_id:
		cursor = previous[cursor]
		path.append(cursor)
	path.reverse()
	return path

