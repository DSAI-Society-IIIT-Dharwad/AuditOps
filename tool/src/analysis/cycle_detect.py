"""Circular permission detection using DFS back-edge discovery."""

from __future__ import annotations

from core.interfaces import GraphStorage


def detect_cycles(storage: GraphStorage) -> list[list[str]]:
	"""Detect directed cycles and return unique cycle lists."""
	adjacency = {
		node_id: list(neighbors)
		for node_id, neighbors in storage.as_adjacency().items()
	}
	visited: set[str] = set()
	stack: list[str] = []
	stack_index: dict[str, int] = {}
	in_stack: set[str] = set()
	seen_cycles: set[tuple[str, ...]] = set()
	found_cycles: list[list[str]] = []

	def dfs(node_id: str) -> None:
		visited.add(node_id)
		stack_index[node_id] = len(stack)
		stack.append(node_id)
		in_stack.add(node_id)

		for neighbor in adjacency.get(node_id, []):
			if neighbor not in visited:
				dfs(neighbor)
			elif neighbor in in_stack:
				cycle_start = stack_index[neighbor]
				cycle = stack[cycle_start:] + [neighbor]
				canonical = _canonical_cycle(cycle)
				if canonical not in seen_cycles:
					seen_cycles.add(canonical)
					found_cycles.append(cycle)

		stack.pop()
		stack_index.pop(node_id, None)
		in_stack.remove(node_id)

	for node_id in sorted(adjacency.keys()):
		if node_id not in visited:
			dfs(node_id)

	return found_cycles


def _canonical_cycle(cycle: list[str]) -> tuple[str, ...]:
	"""Convert cycle into rotation-invariant tuple for dedupe."""
	if len(cycle) <= 1:
		return tuple(cycle)

	# Drop duplicated terminal node while canonicalizing.
	core = cycle[:-1] if cycle[0] == cycle[-1] else cycle[:]
	if not core:
		return tuple()

	rotations = [tuple(core[idx:] + core[:idx]) for idx in range(len(core))]
	best = min(rotations)
	return best + (best[0],)

