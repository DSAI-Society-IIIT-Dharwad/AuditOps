"""Blast radius analysis using Breadth-First Search (BFS)."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from core.interfaces import GraphStorage


@dataclass(slots=True, frozen=True)
class BlastRadiusResult:
	"""Result of bounded BFS traversal from a compromised source."""

	source: str
	max_hops: int
	reachable_nodes: list[str]
	hops_by_node: dict[str, int]

	@property
	def count(self) -> int:
		return len(self.reachable_nodes)

	def to_dict(self) -> dict[str, object]:
		return {
			"source": self.source,
			"max_hops": self.max_hops,
			"reachable_nodes": self.reachable_nodes,
			"hops_by_node": self.hops_by_node,
			"count": self.count,
		}


def calculate_blast_radius(storage: GraphStorage, source_id: str, max_hops: int = 3) -> BlastRadiusResult:
	"""Run BFS from source up to max_hops and return reachable node set."""
	if max_hops < 0:
		raise ValueError("max_hops must be >= 0")
	if not storage.has_node(source_id):
		raise KeyError(f"source node not found: {source_id}")

	visited: set[str] = {source_id}
	hops_by_node: dict[str, int] = {}
	queue: deque[tuple[str, int]] = deque([(source_id, 0)])

	while queue:
		current, hops = queue.popleft()
		if hops >= max_hops:
			continue

		for neighbor in storage.neighbors(current):
			if neighbor in visited:
				continue
			visited.add(neighbor)
			next_hops = hops + 1
			hops_by_node[neighbor] = next_hops
			queue.append((neighbor, next_hops))

	reachable = list(hops_by_node.keys())
	return BlastRadiusResult(
		source=source_id,
		max_hops=max_hops,
		reachable_nodes=reachable,
		hops_by_node=hops_by_node,
	)

