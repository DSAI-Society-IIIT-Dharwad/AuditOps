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
mock_parser_mod = importlib.import_module("ingestion.mock_parser")

Node = models.Node
Edge = models.Edge
NetworkXGraphStorage = builder.NetworkXGraphStorage
detect_cycles = cycle_mod.detect_cycles
MockDataIngestor = mock_parser_mod.MockDataIngestor


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
		self.assertEqual(len(cycle), 3)
		self.assertEqual(set(cycle), {a.node_id, b.node_id, c.node_id})

	def test_no_cycles_returns_empty(self) -> None:
		storage = NetworkXGraphStorage()
		a = Node(entity_type="Role", name="a", namespace="default")
		b = Node(entity_type="Role", name="b", namespace="default")
		storage.add_nodes([a, b])
		storage.add_edge(Edge(source_id=a.node_id, target_id=b.node_id, relationship_type="to"))

		cycles = detect_cycles(storage)
		self.assertEqual(cycles, [])


class TestCycleDetectRubricCases(unittest.TestCase):
	@classmethod
	def setUpClass(cls) -> None:
		fixture_path = ROOT.parent / "tests" / "mock-cluster-graph.json"
		graph_data = MockDataIngestor(file_path=fixture_path).ingest()
		cls.storage = NetworkXGraphStorage.from_cluster_graph_data(graph_data)

	def test_dfs_1_mock_full_graph_exactly_one_expected_cycle(self) -> None:
		cycles = detect_cycles(self.storage)
		self.assertEqual(len(cycles), 1)

		cycle = cycles[0]
		expected_nodes = {
			"Service:default:service-a",
			"Service:default:service-b",
		}
		self.assertEqual(set(cycle), expected_nodes)
		self.assertEqual(len(cycle), 2)

	def test_dfs_2_three_planted_cycles_no_duplicates(self) -> None:
		storage = NetworkXGraphStorage()
		nodes = [
			Node(entity_type="Role", name="a", namespace="default"),
			Node(entity_type="Role", name="b", namespace="default"),
			Node(entity_type="Role", name="c", namespace="default"),
			Node(entity_type="Role", name="d", namespace="default"),
			Node(entity_type="Role", name="e", namespace="default"),
			Node(entity_type="Role", name="f", namespace="default"),
			Node(entity_type="Role", name="g", namespace="default"),
		]
		storage.add_nodes(nodes)

		a, b, c, d, e, f, g = nodes
		storage.add_edges(
			[
				# Cycle 1: a -> b -> a
				Edge(source_id=a.node_id, target_id=b.node_id, relationship_type="admin"),
				Edge(source_id=b.node_id, target_id=a.node_id, relationship_type="admin"),
				# Cycle 2: c -> d -> e -> c
				Edge(source_id=c.node_id, target_id=d.node_id, relationship_type="admin"),
				Edge(source_id=d.node_id, target_id=e.node_id, relationship_type="admin"),
				Edge(source_id=e.node_id, target_id=c.node_id, relationship_type="admin"),
				# Cycle 3: e -> f -> g -> e
				Edge(source_id=e.node_id, target_id=f.node_id, relationship_type="admin"),
				Edge(source_id=f.node_id, target_id=g.node_id, relationship_type="admin"),
				Edge(source_id=g.node_id, target_id=e.node_id, relationship_type="admin"),
				# Extra edges to increase traversal complexity without adding new cycles.
				Edge(source_id=b.node_id, target_id=c.node_id, relationship_type="to"),
			]
		)

		cycles = detect_cycles(storage)
		cycle_sets = {frozenset(cycle) for cycle in cycles}

		expected_cycle_sets = {
			frozenset({a.node_id, b.node_id}),
			frozenset({c.node_id, d.node_id, e.node_id}),
			frozenset({e.node_id, f.node_id, g.node_id}),
		}

		self.assertEqual(len(cycles), 3)
		self.assertEqual(cycle_sets, expected_cycle_sets)
		self.assertEqual(len(cycles), len(cycle_sets))
		for cycle in cycles:
			self.assertEqual(len(cycle), len(set(cycle)))


if __name__ == "__main__":
	unittest.main()
