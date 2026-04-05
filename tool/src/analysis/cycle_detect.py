"""Circular permission detection using DFS back-edge discovery."""

from __future__ import annotations

from core.interfaces import GraphStorage


def detect_cycles(storage: GraphStorage) -> list[list[str]]:
	"""Detect all unique directed cycles and return ordered node lists.

	Each cycle is returned once (no rotation or direction duplicates) and does
	not repeat the start node at the end, e.g. [A, B] instead of [A, B, A].
	"""
	adjacency = {
		node_id: sorted(neighbors)
		for node_id, neighbors in storage.as_adjacency().items()
	}
	seen_cycles: set[tuple[str, ...]] = set()
	found_cycles: list[list[str]] = []

	def dfs(start_node: str, current_node: str, path: list[str], path_set: set[str]) -> None:
		for neighbor in adjacency.get(current_node, []):
			if neighbor == start_node and len(path) >= 2:
				canonical = _canonical_cycle(path)
				if canonical not in seen_cycles:
					seen_cycles.add(canonical)
					found_cycles.append(list(canonical))
				continue

			if neighbor in path_set:
				continue

			path.append(neighbor)
			path_set.add(neighbor)
			dfs(start_node, neighbor, path, path_set)
			path_set.remove(neighbor)
			path.pop()

	for node_id in sorted(adjacency.keys()):
		dfs(node_id, node_id, [node_id], {node_id})

	return sorted(found_cycles, key=lambda cycle: tuple(cycle))


def _canonical_cycle(cycle: list[str]) -> tuple[str, ...]:
	"""Convert cycle into rotation/direction-invariant tuple for dedupe."""
	if len(cycle) <= 1:
		return tuple(cycle)

	# Drop duplicated terminal node while canonicalizing.
	core = cycle[:-1] if cycle[0] == cycle[-1] else cycle[:]
	if not core:
		return tuple()

	rotations = [tuple(core[idx:] + core[:idx]) for idx in range(len(core))]
	reversed_core = list(reversed(core))
	reverse_rotations = [tuple(reversed_core[idx:] + reversed_core[:idx]) for idx in range(len(reversed_core))]
	return min(rotations + reverse_rotations)

