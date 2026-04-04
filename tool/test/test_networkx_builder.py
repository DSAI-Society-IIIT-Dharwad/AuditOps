from __future__ import annotations

import importlib
import json
import tempfile
import unittest
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
	sys.path.insert(0, str(SRC))

core_models = importlib.import_module("core.models")
graph_builder = importlib.import_module("graph.networkx_builder")

ClusterGraphData = core_models.ClusterGraphData
Edge = core_models.Edge
Node = core_models.Node
NetworkXGraphStorage = graph_builder.NetworkXGraphStorage


class TestNetworkXGraphStorage(unittest.TestCase):
	def setUp(self) -> None:
		self.storage = NetworkXGraphStorage()
		self.user = Node(entity_type="User", name="dev-1", namespace="cluster", is_source=True)
		self.role = Node(entity_type="Role", name="secret-reader", namespace="default")
		self.secret = Node(entity_type="Secret", name="db-creds", namespace="default", is_sink=True)

	def test_add_node_and_get_node(self) -> None:
		self.storage.add_node(self.user)
		self.assertTrue(self.storage.has_node(self.user.node_id))
		self.assertEqual(self.storage.get_node(self.user.node_id), self.user)
		self.assertIsNone(self.storage.get_node("User:cluster:missing"))

	def test_add_edge_requires_existing_nodes(self) -> None:
		edge = Edge(
			source_id=self.user.node_id,
			target_id=self.role.node_id,
			relationship_type="bound_to",
			weight=2.0,
		)
		with self.assertRaises(KeyError):
			self.storage.add_edge(edge)

	def test_add_nodes_add_edges_and_neighbors(self) -> None:
		self.storage.add_nodes([self.user, self.role, self.secret])
		edges = [
			Edge(
				source_id=self.user.node_id,
				target_id=self.role.node_id,
				relationship_type="bound_to",
				weight=2.2,
			),
			Edge(
				source_id=self.role.node_id,
				target_id=self.secret.node_id,
				relationship_type="can_read",
				weight=3.0,
			),
		]
		self.storage.add_edges(edges)

		self.assertEqual(set(self.storage.neighbors(self.user.node_id)), {self.role.node_id})
		self.assertEqual(self.storage.get_edge_weight(self.user.node_id, self.role.node_id), 2.2)
		self.assertEqual(len(self.storage.all_nodes()), 3)
		self.assertEqual(len(self.storage.all_edges()), 2)

	def test_get_edge_weight_raises_for_missing_edge(self) -> None:
		self.storage.add_nodes([self.user, self.role])
		with self.assertRaises(KeyError):
			self.storage.get_edge_weight(self.user.node_id, self.role.node_id)

	def test_as_adjacency_and_clear(self) -> None:
		self.storage.add_nodes([self.user, self.role])
		self.storage.add_edge(
			Edge(
				source_id=self.user.node_id,
				target_id=self.role.node_id,
				relationship_type="bound_to",
			)
		)
		adj = self.storage.as_adjacency()
		self.assertIn(self.user.node_id, adj)
		self.assertEqual(adj[self.user.node_id], [self.role.node_id])

		self.storage.clear()
		self.assertEqual(self.storage.all_nodes(), [])
		self.assertEqual(self.storage.all_edges(), [])

	def test_is_dag_true_and_false(self) -> None:
		a = Node(entity_type="Pod", name="a", namespace="default")
		b = Node(entity_type="Pod", name="b", namespace="default")
		c = Node(entity_type="Pod", name="c", namespace="default")
		self.storage.add_nodes([a, b, c])

		self.storage.add_edge(Edge(source_id=a.node_id, target_id=b.node_id, relationship_type="to"))
		self.storage.add_edge(Edge(source_id=b.node_id, target_id=c.node_id, relationship_type="to"))
		self.assertTrue(self.storage.is_dag())

		self.storage.add_edge(Edge(source_id=c.node_id, target_id=a.node_id, relationship_type="to"))
		self.assertFalse(self.storage.is_dag())

	def test_from_cluster_graph_data(self) -> None:
		nodes = [self.user, self.role]
		edges = [
			Edge(
				source_id=self.user.node_id,
				target_id=self.role.node_id,
				relationship_type="bound_to",
				weight=1.7,
			)
		]
		data = ClusterGraphData(nodes=nodes, edges=edges)

		storage = NetworkXGraphStorage.from_cluster_graph_data(data)
		self.assertEqual(len(storage.all_nodes()), 2)
		self.assertEqual(len(storage.all_edges()), 1)
		self.assertEqual(storage.get_edge_weight(self.user.node_id, self.role.node_id), 1.7)

	def test_raw_graph_returns_digraph(self) -> None:
		raw = self.storage.raw_graph()
		self.assertEqual(raw.__class__.__name__, "DiGraph")

	def test_json_round_trip_preserves_nodes_edges_and_metadata(self) -> None:
		source = Node(entity_type="Pod", name="web", namespace="default", risk_score=7.5, is_source=True)
		target = Node(entity_type="Secret", name="db-creds", namespace="default", risk_score=9.0, is_sink=True)
		edge = Edge(
			source_id=source.node_id,
			target_id=target.node_id,
			relationship_type="can_read",
			weight=4.4,
		)

		storage = NetworkXGraphStorage()
		storage.add_nodes([source, target])
		storage.add_edge(edge)

		with tempfile.TemporaryDirectory() as tmp_dir:
			artifact = Path(tmp_dir) / "cluster-graph.json"
			storage.save_json(artifact)
			loaded = NetworkXGraphStorage.from_json_file(artifact)

		self.assertEqual(
			{(n.node_id, n.risk_score, n.is_source, n.is_sink) for n in storage.all_nodes()},
			{(n.node_id, n.risk_score, n.is_source, n.is_sink) for n in loaded.all_nodes()},
		)
		self.assertEqual(
			{(e.source_id, e.target_id, e.relationship_type, e.weight) for e in storage.all_edges()},
			{(e.source_id, e.target_id, e.relationship_type, e.weight) for e in loaded.all_edges()},
		)

	def test_from_exported_json_keeps_cycles(self) -> None:
		payload = {
			"schema_version": "1.0.0",
			"nodes": [
				{
					"node_id": "Role:default:a",
					"entity_type": "Role",
					"name": "a",
					"namespace": "default",
					"risk_score": 1.0,
					"is_source": False,
					"is_sink": False,
				},
				{
					"node_id": "Role:default:b",
					"entity_type": "Role",
					"name": "b",
					"namespace": "default",
					"risk_score": 1.0,
					"is_source": False,
					"is_sink": False,
				},
			],
			"edges": [
				{
					"source_id": "Role:default:a",
					"target_id": "Role:default:b",
					"relationship_type": "admin",
					"weight": 1.0,
				},
				{
					"source_id": "Role:default:b",
					"target_id": "Role:default:a",
					"relationship_type": "admin",
					"weight": 1.0,
				},
			],
		}

		loaded = NetworkXGraphStorage.from_exported_json(payload)
		self.assertFalse(loaded.is_dag())
		self.assertEqual(len(loaded.all_edges()), 2)

	def test_from_json_file_rejects_node_id_mismatch(self) -> None:
		payload = {
			"schema_version": "1.0.0",
			"nodes": [
				{
					"node_id": "Pod:default:wrong",
					"entity_type": "Pod",
					"name": "web",
					"namespace": "default",
					"risk_score": 1.0,
					"is_source": False,
					"is_sink": False,
				}
			],
			"edges": [],
		}

		with tempfile.TemporaryDirectory() as tmp_dir:
			artifact = Path(tmp_dir) / "cluster-graph.json"
			artifact.write_text(json.dumps(payload), encoding="utf-8")
			with self.assertRaises(ValueError):
				NetworkXGraphStorage.from_json_file(artifact)


if __name__ == "__main__":
	unittest.main()
