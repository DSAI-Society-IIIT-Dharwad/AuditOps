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
kubectl_runner = importlib.import_module("ingestion.kubectl_runner")

Node = models.Node
Edge = models.Edge
NetworkXGraphStorage = builder.NetworkXGraphStorage
dijkstra_shortest_path = shortest_path_mod.dijkstra_shortest_path
shortest_path_to_any_sink = shortest_path_mod.shortest_path_to_any_sink
build_cluster_graph_data = kubectl_runner.build_cluster_graph_data


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
		self.assertGreaterEqual(result.explored_edge_count, 2)
		self.assertEqual(result.visited_nodes[0], self.source.node_id)

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

	def test_secret_snooping_penalty_increases_path_cost(self) -> None:
		safe_payload = _minimal_secret_access_payload(
			namespace="vulnerable-ns",
			pod_name="frontend-webapp",
			sa_name="overly-permissive-sa",
			role_name="dangerous-secret-reader",
			rule={"resources": ["secrets"], "verbs": ["get"], "resourceNames": ["prod-db-credentials"]},
		)
		risky_payload = _minimal_secret_access_payload(
			namespace="vulnerable-ns",
			pod_name="frontend-webapp",
			sa_name="overly-permissive-sa",
			role_name="dangerous-secret-reader",
			rule={"resources": ["secrets"], "verbs": ["get", "list"]},
		)

		safe_storage = NetworkXGraphStorage.from_cluster_graph_data(build_cluster_graph_data(safe_payload))
		risky_storage = NetworkXGraphStorage.from_cluster_graph_data(build_cluster_graph_data(risky_payload))

		source = "Pod:vulnerable-ns:frontend-webapp"
		target = "Secret:vulnerable-ns:prod-db-credentials"

		safe_result = dijkstra_shortest_path(safe_storage, source, target)
		risky_result = dijkstra_shortest_path(risky_storage, source, target)

		self.assertIsNotNone(safe_result)
		self.assertIsNotNone(risky_result)
		assert safe_result is not None
		assert risky_result is not None
		self.assertAlmostEqual(risky_result.total_cost - safe_result.total_cost, 3.0, places=3)

	def test_god_mode_wildcard_penalty_increases_path_cost(self) -> None:
		non_wild_payload = _minimal_secret_access_payload(
			namespace="vulnerable-ns",
			pod_name="frontend-webapp",
			sa_name="overly-permissive-sa",
			role_name="god-role",
			rule={"resources": ["secrets"], "verbs": ["get"], "resourceNames": ["prod-db-credentials"]},
		)
		wild_payload = _minimal_secret_access_payload(
			namespace="vulnerable-ns",
			pod_name="frontend-webapp",
			sa_name="overly-permissive-sa",
			role_name="god-role",
			rule={"resources": ["*"], "verbs": ["get"], "resourceNames": ["prod-db-credentials"]},
		)

		non_wild_storage = NetworkXGraphStorage.from_cluster_graph_data(build_cluster_graph_data(non_wild_payload))
		wild_storage = NetworkXGraphStorage.from_cluster_graph_data(build_cluster_graph_data(wild_payload))

		source = "Pod:vulnerable-ns:frontend-webapp"
		target = "Secret:vulnerable-ns:prod-db-credentials"

		non_wild_result = dijkstra_shortest_path(non_wild_storage, source, target)
		wild_result = dijkstra_shortest_path(wild_storage, source, target)

		self.assertIsNotNone(non_wild_result)
		self.assertIsNotNone(wild_result)
		assert non_wild_result is not None
		assert wild_result is not None
		self.assertAlmostEqual(wild_result.total_cost - non_wild_result.total_cost, 5.0, places=3)

	def test_vulnerable_namespace_has_path_secure_namespace_does_not(self) -> None:
		vulnerable_payload = _minimal_secret_access_payload(
			namespace="vulnerable-ns",
			pod_name="frontend-webapp-vulnerable",
			sa_name="overly-permissive-sa",
			role_name="dangerous-secret-reader",
			rule={"resources": ["secrets"], "verbs": ["get", "list"]},
		)
		secure_payload = {
			"pods": {
				"items": [
					{
						"metadata": {
							"name": "frontend-webapp-secure",
							"namespace": "secure-ns",
							"labels": {"public": "true"},
							"annotations": {"security.hack2future.io/source": "true"},
						},
						"spec": {
							"serviceAccountName": "webapp-sa",
							"automountServiceAccountToken": False,
							"containers": [],
						},
					}
				]
			},
			"serviceaccounts": {"items": [{"metadata": {"name": "webapp-sa", "namespace": "secure-ns"}}]},
			"roles": {
				"items": [
					{
						"metadata": {"name": "config-reader", "namespace": "secure-ns"},
						"rules": [{"resources": ["configmaps"], "verbs": ["get", "list"]}],
					}
				]
			},
			"rolebindings": {
				"items": [
					{
						"metadata": {"name": "config-reader-binding", "namespace": "secure-ns"},
						"roleRef": {"kind": "Role", "name": "config-reader"},
						"subjects": [
							{
								"kind": "ServiceAccount",
								"name": "webapp-sa",
								"namespace": "secure-ns",
							}
						],
					}
				]
			},
			"clusterrolebindings": {"items": []},
			"secrets": {
				"items": [
					{
						"metadata": {
							"name": "prod-db-credentials",
							"namespace": "secure-ns",
							"labels": {"crown-jewel": "true", "sensitivity": "critical"},
						}
					}
				]
			},
			"configmaps": {"items": [{"metadata": {"name": "app-config", "namespace": "secure-ns"}}]},
		}

		vuln_storage = NetworkXGraphStorage.from_cluster_graph_data(build_cluster_graph_data(vulnerable_payload))
		secure_storage = NetworkXGraphStorage.from_cluster_graph_data(build_cluster_graph_data(secure_payload))

		vuln_result = dijkstra_shortest_path(
			vuln_storage,
			"Pod:vulnerable-ns:frontend-webapp-vulnerable",
			"Secret:vulnerable-ns:prod-db-credentials",
		)
		secure_result = dijkstra_shortest_path(
			secure_storage,
			"Pod:secure-ns:frontend-webapp-secure",
			"Secret:secure-ns:prod-db-credentials",
		)

		self.assertIsNotNone(vuln_result)
		self.assertIsNone(secure_result)


def _minimal_secret_access_payload(
	*,
	namespace: str,
	pod_name: str,
	sa_name: str,
	role_name: str,
	rule: dict[str, object],
) -> dict[str, object]:
	return {
		"pods": {
			"items": [
				{
					"metadata": {
						"name": pod_name,
						"namespace": namespace,
						"labels": {"public": "true"},
						"annotations": {"security.hack2future.io/source": "true"},
					},
					"spec": {
						"serviceAccountName": sa_name,
						"automountServiceAccountToken": False,
						"containers": [],
					},
				}
			]
		},
		"serviceaccounts": {"items": [{"metadata": {"name": sa_name, "namespace": namespace}}]},
		"roles": {"items": [{"metadata": {"name": role_name, "namespace": namespace}, "rules": [rule]}]},
		"rolebindings": {
			"items": [
				{
					"metadata": {"name": f"{role_name}-binding", "namespace": namespace},
					"roleRef": {"kind": "Role", "name": role_name},
					"subjects": [
						{"kind": "ServiceAccount", "name": sa_name, "namespace": namespace},
					],
				}
			]
		},
		"clusterrolebindings": {"items": []},
		"secrets": {
			"items": [
				{
					"metadata": {
						"name": "prod-db-credentials",
						"namespace": namespace,
						"labels": {"crown-jewel": "true", "sensitivity": "critical"},
					}
				}
			]
		},
		"configmaps": {"items": []},
	}


if __name__ == "__main__":
	unittest.main()
