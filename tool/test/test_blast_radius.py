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
mock_parser_mod = importlib.import_module("ingestion.mock_parser")

Node = models.Node
Edge = models.Edge
NetworkXGraphStorage = builder.NetworkXGraphStorage
calculate_blast_radius = blast_radius_mod.calculate_blast_radius
MockDataIngestor = mock_parser_mod.MockDataIngestor


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
		self.assertEqual(result.paths_by_node[self.b.node_id], [self.a.node_id, self.b.node_id])
		self.assertEqual(result.paths_by_node[self.c.node_id], [self.a.node_id, self.b.node_id, self.c.node_id])
		self.assertEqual(result.count, 2)

	def test_invalid_source_raises(self) -> None:
		with self.assertRaises(KeyError):
			calculate_blast_radius(self.storage, "Pod:default:missing", max_hops=2)

	def test_negative_hops_raises(self) -> None:
		with self.assertRaises(ValueError):
			calculate_blast_radius(self.storage, self.a.node_id, max_hops=-1)


class TestBlastRadiusRubricCases(unittest.TestCase):
	@classmethod
	def setUpClass(cls) -> None:
		fixture_path = ROOT.parent / "tests" / "mock-cluster-graph.json"
		graph_data = MockDataIngestor(file_path=fixture_path).ingest()
		cls.storage = NetworkXGraphStorage.from_cluster_graph_data(graph_data)

	def test_bfs_1_webfront_hops_three_exact_layers(self) -> None:
		result = calculate_blast_radius(self.storage, "Pod:default:web-frontend", max_hops=3)

		hop1_expected = {
			"ServiceAccount:default:sa-webapp",
			"ServiceAccount:default:default",
			"Service:default:internal-api-svc",
			"Pod:default:sidecar-proxy",
		}
		hop2_expected = {
			"Role:default:secret-reader",
			"Secret:default:tls-cert",
			"Secret:default:api-key",
			"ClusterRole:cluster:cluster-admin",
			"Pod:default:api-server",
		}
		hop3_expected = {
			"Secret:default:db-credentials",
			"Secret:kube-system:admin-token",
			"ServiceAccount:default:sa-worker",
			"ConfigMap:default:db-url-config",
		}

		hop1_actual = _nodes_at_hop(result, 1)
		hop2_actual = _nodes_at_hop(result, 2)
		hop3_actual = _nodes_at_hop(result, 3)

		self.assertEqual(hop1_actual, hop1_expected)
		self.assertEqual(hop2_actual, hop2_expected)
		self.assertEqual(hop3_actual, hop3_expected)

		# Nodes should not be repeated across different hop layers.
		all_nodes = hop1_actual | hop2_actual | hop3_actual
		self.assertEqual(len(all_nodes), len(hop1_actual) + len(hop2_actual) + len(hop3_actual))

	def test_bfs_2_cicd_hops_two_exact_layers(self) -> None:
		result = calculate_blast_radius(self.storage, "User:ci:cicd-bot", max_hops=2)

		hop1_expected = {"ServiceAccount:ci:sa-cicd"}
		hop2_expected = {
			"ClusterRole:cluster:deployer",
			"Secret:ci:cicd-deploy-token",
		}

		self.assertEqual(_nodes_at_hop(result, 1), hop1_expected)
		self.assertEqual(_nodes_at_hop(result, 2), hop2_expected)

	def test_bfs_3_single_isolated_source_returns_empty_radius(self) -> None:
		storage = NetworkXGraphStorage()
		source = Node(entity_type="Pod", name="isolated", namespace="default")
		storage.add_node(source)

		result = calculate_blast_radius(storage, source.node_id, max_hops=3)

		self.assertEqual(result.count, 0)
		self.assertEqual(result.reachable_nodes, [])
		self.assertEqual(result.hops_by_node, {})
		self.assertEqual(result.paths_by_node, {})


def _nodes_at_hop(result, hop: int) -> set[str]:
	return {
		node_id
		for node_id, depth in result.hops_by_node.items()
		if depth == hop
	}


if __name__ == "__main__":
	unittest.main()
