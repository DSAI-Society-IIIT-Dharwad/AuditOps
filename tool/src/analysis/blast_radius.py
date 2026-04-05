"""Blast radius analysis using Breadth-First Search (BFS)."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from dataclasses import field

from core.interfaces import GraphStorage


NON_PROPAGATING_RELATIONSHIPS = {
	"grants-access-to",
	"admin-over",
}

SERVICE_ACCOUNT_LINK_RELATIONSHIPS = {
	"uses",
	"falls-back-to",
}


@dataclass(slots=True, frozen=True)
class BlastRadiusResult:
	"""Result of bounded BFS traversal from a compromised source."""

	source: str
	max_hops: int
	reachable_nodes: list[str]
	hops_by_node: dict[str, int]
	paths_by_node: dict[str, list[str]] = field(default_factory=dict)

	@property
	def count(self) -> int:
		return len(self.reachable_nodes)

	def to_dict(self) -> dict[str, object]:
		return {
			"source": self.source,
			"max_hops": self.max_hops,
			"reachable_nodes": self.reachable_nodes,
			"hops_by_node": self.hops_by_node,
			"paths_by_node": self.paths_by_node,
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
	parents: dict[str, str] = {}
	queue: deque[tuple[str, int]] = deque([(source_id, 0)])

	while queue:
		current, hops = queue.popleft()
		if hops >= max_hops:
			continue

		for neighbor in _bfs_neighbors(storage, current, source_id=source_id):
			if neighbor in visited:
				continue
			visited.add(neighbor)
			next_hops = hops + 1
			hops_by_node[neighbor] = next_hops
			parents[neighbor] = current
			queue.append((neighbor, next_hops))

	reachable = list(hops_by_node.keys())
	paths_by_node = {
		node_id: _reconstruct_path(parents, source_id, node_id)
		for node_id in reachable
	}
	return BlastRadiusResult(
		source=source_id,
		max_hops=max_hops,
		reachable_nodes=reachable,
		hops_by_node=hops_by_node,
		paths_by_node=paths_by_node,
	)


def _bfs_neighbors(storage: GraphStorage, node_id: str, *, source_id: str) -> list[str]:
	neighbors: list[str] = []
	for neighbor_id in storage.neighbors(node_id):
		if _is_non_propagating_edge(storage, node_id, neighbor_id):
			continue
		if _is_default_sa_secret_read_edge(storage, node_id, neighbor_id):
			continue
		neighbors.append(neighbor_id)

	# In practice, sidecars often share service accounts with their parent pod.
	# Apply this only for the initial source expansion to avoid over-expansion.
	if node_id == source_id:
		for sibling_id in _pod_siblings_via_shared_service_account(storage, node_id):
			if sibling_id not in neighbors:
				neighbors.append(sibling_id)

	return neighbors


def _pod_siblings_via_shared_service_account(storage: GraphStorage, pod_id: str) -> list[str]:
	graph = _raw_graph(storage)
	if graph is None or _node_type(pod_id) != "Pod":
		return []

	service_accounts: set[str] = set()
	for _, target_id in graph.out_edges(pod_id):
		relationship = _edge_relationship(graph, pod_id, target_id)
		if relationship not in SERVICE_ACCOUNT_LINK_RELATIONSHIPS:
			continue
		if _node_type(target_id) == "ServiceAccount":
			service_accounts.add(target_id)

	if not service_accounts:
		return []

	siblings: set[str] = set()
	for sa_id in service_accounts:
		for source_id, _ in graph.in_edges(sa_id):
			if source_id == pod_id or _node_type(source_id) != "Pod":
				continue
			relationship = _edge_relationship(graph, source_id, sa_id)
			if relationship in SERVICE_ACCOUNT_LINK_RELATIONSHIPS:
				siblings.add(source_id)

	return sorted(siblings)


def _is_non_propagating_edge(storage: GraphStorage, source_id: str, target_id: str) -> bool:
	graph = _raw_graph(storage)
	if graph is None:
		return False
	return _edge_relationship(graph, source_id, target_id) in NON_PROPAGATING_RELATIONSHIPS


def _is_default_sa_secret_read_edge(storage: GraphStorage, source_id: str, target_id: str) -> bool:
	graph = _raw_graph(storage)
	if graph is None:
		return False
	if _node_type(source_id) != "ServiceAccount" or _node_type(target_id) != "Secret":
		return False
	if _node_name(source_id) != "default":
		return False
	return _edge_relationship(graph, source_id, target_id) == "can-read"


def _raw_graph(storage: GraphStorage):
	getter = getattr(storage, "raw_graph", None)
	if callable(getter):
		return getter()
	return None


def _edge_relationship(graph, source_id: str, target_id: str) -> str:
	edge_data = graph.get_edge_data(source_id, target_id) or {}
	relationship = str(edge_data.get("relationship_type") or "").strip().lower()
	return relationship.replace("_", "-")


def _node_type(node_id: str) -> str:
	parts = str(node_id).split(":", 2)
	if len(parts) == 3:
		return parts[0]
	return ""


def _node_name(node_id: str) -> str:
	parts = str(node_id).split(":", 2)
	if len(parts) == 3:
		return parts[2]
	return str(node_id)


def _reconstruct_path(parents: dict[str, str], source_id: str, target_id: str) -> list[str]:
	path: list[str] = [target_id]
	cursor = target_id
	while cursor != source_id:
		cursor = parents[cursor]
		path.append(cursor)
	path.reverse()
	return path

