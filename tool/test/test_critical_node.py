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
mock_parser_mod = importlib.import_module("ingestion.mock_parser")
main_mod = importlib.import_module("main")

Node = models.Node
Edge = models.Edge
NetworkXGraphStorage = builder.NetworkXGraphStorage
identify_critical_node = critical_mod.identify_critical_node
MockDataIngestor = mock_parser_mod.MockDataIngestor


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


class TestCriticalNodeRubricCases(unittest.TestCase):
	@classmethod
	def setUpClass(cls) -> None:
		fixture_path = ROOT.parent / "tests" / "mock-cluster-graph.json"
		graph_data = MockDataIngestor(file_path=fixture_path).ingest()
		cls.storage = NetworkXGraphStorage.from_cluster_graph_data(graph_data)
		cls.source_ids = main_mod._resolve_source_ids(cls.storage, None, namespace=None)
		cls.sink_ids = main_mod._resolve_sink_ids(cls.storage, None, namespace=None)

	def test_identify_critical_node_matches_mock_expected_node_and_counts(self) -> None:
		result = identify_critical_node(
			self.storage,
			source_ids=self.source_ids,
			sink_ids=self.sink_ids,
			max_depth=8,
		)

		self.assertIsNotNone(result)
		assert result is not None
		self.assertEqual(result.node_id, "Pod:default:web-frontend")
		self.assertEqual(result.total_paths_before, 46)
		self.assertEqual(result.paths_removed, 32)
		self.assertEqual(result.total_paths_after, 14)

		source_sink_ids = set(self.source_ids) | set(self.sink_ids)
		self.assertNotIn(result.node_id, source_sink_ids)

	def test_top_five_ranking_matches_mock_expected_order(self) -> None:
		all_paths = main_mod._enumerate_attack_paths(
			self.storage,
			source_ids=self.source_ids,
			sink_ids=self.sink_ids,
			max_depth=8,
		)
		ranked = main_mod._rank_critical_nodes_from_paths(
			all_paths,
			source_ids=self.source_ids,
			sink_ids=self.sink_ids,
			top_n=5,
		)

		expected = [
			("Pod:default:web-frontend", 32),
			("Pod:default:api-server", 24),
			("Service:default:internal-api-svc", 16),
			("ServiceAccount:default:sa-worker", 14),
			("Role:default:pod-exec", 14),
		]

		actual = [(str(row["node_id"]), int(row["paths_removed"])) for row in ranked]
		self.assertEqual(actual, expected)


if __name__ == "__main__":
	unittest.main()
