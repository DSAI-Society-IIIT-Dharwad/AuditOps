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
cycle_mod = importlib.import_module("analysis.cycle_detect")

Node = models.Node
Edge = models.Edge
NetworkXGraphStorage = builder.NetworkXGraphStorage
detect_cycles = cycle_mod.detect_cycles


class TestCycleDetect(unittest.TestCase):
	def test_detects_directed_cycle(self) -> None:
		storage = NetworkXGraphStorage()
		a = Node(entity_type="ServiceAccount", name="a", namespace="default")
		b = Node(entity_type="ServiceAccount", name="b", namespace="default")
		c = Node(entity_type="ServiceAccount", name="c", namespace="default")
		storage.add_nodes([a, b, c])
		storage.add_edges(
			[
				Edge(source_id=a.node_id, target_id=b.node_id, relationship_type="admin"),
				Edge(source_id=b.node_id, target_id=c.node_id, relationship_type="admin"),
				Edge(source_id=c.node_id, target_id=a.node_id, relationship_type="admin"),
			]
		)

		cycles = detect_cycles(storage)
		self.assertEqual(len(cycles), 1)
		cycle = cycles[0]
		self.assertGreaterEqual(len(cycle), 4)
		self.assertEqual(cycle[0], cycle[-1])

	def test_no_cycles_returns_empty(self) -> None:
		storage = NetworkXGraphStorage()
		a = Node(entity_type="Role", name="a", namespace="default")
		b = Node(entity_type="Role", name="b", namespace="default")
		storage.add_nodes([a, b])
		storage.add_edge(Edge(source_id=a.node_id, target_id=b.node_id, relationship_type="to"))

		cycles = detect_cycles(storage)
		self.assertEqual(cycles, [])


if __name__ == "__main__":
	unittest.main()
