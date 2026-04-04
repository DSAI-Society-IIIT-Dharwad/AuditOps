from __future__ import annotations

import importlib
import unittest
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
	sys.path.insert(0, str(SRC))

models = importlib.import_module("core.models")
builder = importlib.import_module("graph.networkx_builder")
shortest_path_mod = importlib.import_module("analysis.shortest_path")

Node = models.Node
Edge = models.Edge
NetworkXGraphStorage = builder.NetworkXGraphStorage
dijkstra_shortest_path = shortest_path_mod.dijkstra_shortest_path
shortest_path_to_any_sink = shortest_path_mod.shortest_path_to_any_sink


class TestShortestPath(unittest.TestCase):
	def setUp(self) -> None:
		self.storage = NetworkXGraphStorage()
		source = Node(entity_type="User", name="dev-1", namespace="cluster", is_source=True)
		mid1 = Node(entity_type="Role", name="r1", namespace="default", risk_score=2.0)
		mid2 = Node(entity_type="Role", name="r2", namespace="default", risk_score=1.0)
		sink1 = Node(entity_type="Database", name="db1", namespace="prod", risk_score=6.0, is_sink=True)
		sink2 = Node(entity_type="Database", name="db2", namespace="prod", risk_score=3.0, is_sink=True)
		self.storage.add_nodes([source, mid1, mid2, sink1, sink2])

		self.storage.add_edges(
			[
				Edge(source_id=source.node_id, target_id=mid1.node_id, relationship_type="to", weight=1.0),
				Edge(source_id=mid1.node_id, target_id=sink1.node_id, relationship_type="to", weight=1.0),
				Edge(source_id=source.node_id, target_id=mid2.node_id, relationship_type="to", weight=2.0),
				Edge(source_id=mid2.node_id, target_id=sink2.node_id, relationship_type="to", weight=1.0),
			]
		)

		self.source = source
		self.mid1 = mid1
		self.mid2 = mid2
		self.sink1 = sink1
		self.sink2 = sink2

	def test_dijkstra_path_and_cost(self) -> None:
		result = dijkstra_shortest_path(self.storage, self.source.node_id, self.sink1.node_id)
		self.assertIsNotNone(result)
		assert result is not None
		self.assertEqual(result.path, [self.source.node_id, self.mid1.node_id, self.sink1.node_id])
		# cost: (1 + risk(mid1)=2) + (1 + risk(sink1)=6) = 10
		self.assertEqual(result.total_cost, 10.0)

	def test_penalty_changes_total_cost(self) -> None:
		penalty = {(self.source.node_id, self.mid1.node_id): 3.5}
		result = dijkstra_shortest_path(
			self.storage,
			self.source.node_id,
			self.sink1.node_id,
			penalty_by_edge=penalty,
		)
		self.assertIsNotNone(result)
		assert result is not None
		self.assertEqual(result.total_cost, 13.5)

	def test_shortest_to_any_sink(self) -> None:
		result = shortest_path_to_any_sink(self.storage, self.source.node_id)
		self.assertIsNotNone(result)
		assert result is not None
		self.assertEqual(result.target, self.sink2.node_id)

	def test_no_path_returns_none(self) -> None:
		orphan = Node(entity_type="User", name="orphan", namespace="cluster")
		self.storage.add_node(orphan)
		result = dijkstra_shortest_path(self.storage, orphan.node_id, self.sink1.node_id)
		self.assertIsNone(result)


if __name__ == "__main__":
	unittest.main()
