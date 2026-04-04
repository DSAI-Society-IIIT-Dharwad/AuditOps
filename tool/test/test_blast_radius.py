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
blast_radius_mod = importlib.import_module("analysis.blast_radius")

Node = models.Node
Edge = models.Edge
NetworkXGraphStorage = builder.NetworkXGraphStorage
calculate_blast_radius = blast_radius_mod.calculate_blast_radius


class TestBlastRadius(unittest.TestCase):
	def setUp(self) -> None:
		self.storage = NetworkXGraphStorage()
		a = Node(entity_type="Pod", name="a", namespace="default")
		b = Node(entity_type="Pod", name="b", namespace="default")
		c = Node(entity_type="Pod", name="c", namespace="default")
		d = Node(entity_type="Pod", name="d", namespace="default")
		self.storage.add_nodes([a, b, c, d])
		self.storage.add_edges(
			[
				Edge(source_id=a.node_id, target_id=b.node_id, relationship_type="to"),
				Edge(source_id=b.node_id, target_id=c.node_id, relationship_type="to"),
				Edge(source_id=c.node_id, target_id=d.node_id, relationship_type="to"),
			]
		)
		self.a = a
		self.b = b
		self.c = c
		self.d = d

	def test_bfs_with_hop_limit(self) -> None:
		result = calculate_blast_radius(self.storage, self.a.node_id, max_hops=2)
		self.assertEqual(result.reachable_nodes, [self.b.node_id, self.c.node_id])
		self.assertEqual(result.hops_by_node[self.b.node_id], 1)
		self.assertEqual(result.hops_by_node[self.c.node_id], 2)
		self.assertEqual(result.count, 2)

	def test_invalid_source_raises(self) -> None:
		with self.assertRaises(KeyError):
			calculate_blast_radius(self.storage, "Pod:default:missing", max_hops=2)

	def test_negative_hops_raises(self) -> None:
		with self.assertRaises(ValueError):
			calculate_blast_radius(self.storage, self.a.node_id, max_hops=-1)


if __name__ == "__main__":
	unittest.main()
