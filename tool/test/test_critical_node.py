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
critical_mod = importlib.import_module("analysis.critical_node")

Node = models.Node
Edge = models.Edge
NetworkXGraphStorage = builder.NetworkXGraphStorage
identify_critical_node = critical_mod.identify_critical_node


class TestCriticalNode(unittest.TestCase):
	def test_identifies_node_with_highest_path_disruption(self) -> None:
		storage = NetworkXGraphStorage()
		s = Node(entity_type="User", name="source", namespace="cluster", is_source=True)
		a = Node(entity_type="Role", name="a", namespace="default")
		b = Node(entity_type="Role", name="b", namespace="default")
		t = Node(entity_type="Database", name="target", namespace="prod", is_sink=True)
		storage.add_nodes([s, a, b, t])
		storage.add_edges(
			[
				Edge(source_id=s.node_id, target_id=a.node_id, relationship_type="to"),
				Edge(source_id=s.node_id, target_id=b.node_id, relationship_type="to"),
				Edge(source_id=a.node_id, target_id=t.node_id, relationship_type="to"),
				Edge(source_id=b.node_id, target_id=t.node_id, relationship_type="to"),
				Edge(source_id=a.node_id, target_id=b.node_id, relationship_type="to"),
			]
		)

		result = identify_critical_node(storage)
		self.assertIsNotNone(result)
		assert result is not None
		self.assertIn(result.node_id, {a.node_id, b.node_id})
		self.assertEqual(result.total_paths_before, 3)
		self.assertGreaterEqual(result.paths_removed, 2)

	def test_returns_none_when_no_source_or_sink(self) -> None:
		storage = NetworkXGraphStorage()
		n1 = Node(entity_type="Pod", name="p1", namespace="default")
		n2 = Node(entity_type="Pod", name="p2", namespace="default")
		storage.add_nodes([n1, n2])
		storage.add_edge(Edge(source_id=n1.node_id, target_id=n2.node_id, relationship_type="to"))

		result = identify_critical_node(storage)
		self.assertIsNone(result)


if __name__ == "__main__":
	unittest.main()
