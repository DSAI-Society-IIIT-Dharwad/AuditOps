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
builder_mod = importlib.import_module("graph.networkx_builder")
mock_parser_mod = importlib.import_module("ingestion.mock_parser")
shortest_path_mod = importlib.import_module("analysis.shortest_path")
main_mod = importlib.import_module("main")

Node = models.Node
Edge = models.Edge
NetworkXGraphStorage = builder_mod.NetworkXGraphStorage
MockDataIngestor = mock_parser_mod.MockDataIngestor
dijkstra_shortest_path = shortest_path_mod.dijkstra_shortest_path


class TestDijkstraRubricCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture_path = ROOT.parent / "tests" / "mock-cluster-graph.json"
        graph_data = MockDataIngestor(file_path=fixture_path).ingest()
        cls.storage = NetworkXGraphStorage.from_cluster_graph_data(graph_data)

    def test_dijk_1_dev1_to_db_production_expected_path_and_cost(self) -> None:
        result = dijkstra_shortest_path(
            self.storage,
            "User:default:dev-1",
            "Database:data:production-db",
            include_node_risk=False,
        )

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(
            result.path,
            [
                "User:default:dev-1",
                "Pod:default:web-frontend",
                "ServiceAccount:default:sa-webapp",
                "Role:default:secret-reader",
                "Secret:default:db-credentials",
                "Database:data:production-db",
            ],
        )
        self.assertEqual(result.hops, 5)
        self.assertAlmostEqual(result.total_cost, 24.1, delta=0.05)

    def test_dijk_2_internet_to_ns_kube_system_expected_path_and_cost(self) -> None:
        result = dijkstra_shortest_path(
            self.storage,
            "ExternalActor:external:internet",
            "Namespace:cluster:kube-system",
            include_node_risk=False,
        )

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(
            result.path,
            [
                "ExternalActor:external:internet",
                "Pod:default:web-frontend",
                "ServiceAccount:default:default",
                "ClusterRole:cluster:cluster-admin",
                "Secret:kube-system:admin-token",
                "Namespace:cluster:kube-system",
            ],
        )
        self.assertEqual(result.hops, 5)
        self.assertAlmostEqual(result.total_cost, 32.0, delta=0.05)

    def test_fixture_style_alias_source_target_resolve_to_canonical_ids(self) -> None:
        source_id = main_mod._resolve_source_id(self.storage, "user-dev1", namespace=None)
        target_ids = main_mod._resolve_sink_ids(self.storage, "db-production", namespace=None)

        self.assertEqual(source_id, "User:default:dev-1")
        self.assertEqual(target_ids, ["Database:data:production-db"])

    def test_dijk_3_disconnected_nodes_returns_none_without_exception(self) -> None:
        storage = NetworkXGraphStorage()
        source = Node(entity_type="Pod", name="isolated-source", namespace="demo")
        target = Node(entity_type="Secret", name="isolated-target", namespace="demo")
        storage.add_nodes([source, target])

        result = dijkstra_shortest_path(
            storage,
            source.node_id,
            target.node_id,
            include_node_risk=False,
        )
        self.assertIsNone(result)

    def test_dijkstra_uses_edge_weights_not_hop_count(self) -> None:
        storage = NetworkXGraphStorage()
        a = Node(entity_type="Pod", name="a", namespace="demo")
        b = Node(entity_type="Pod", name="b", namespace="demo")
        c = Node(entity_type="Pod", name="c", namespace="demo")
        e = Node(entity_type="Pod", name="e", namespace="demo")
        d = Node(entity_type="Secret", name="d", namespace="demo")
        storage.add_nodes([a, b, c, d, e])
        storage.add_edges(
            [
                Edge(source_id=a.node_id, target_id=b.node_id, relationship_type="to", weight=10.0),
                Edge(source_id=b.node_id, target_id=d.node_id, relationship_type="to", weight=10.0),
                Edge(source_id=a.node_id, target_id=c.node_id, relationship_type="to", weight=1.0),
                Edge(source_id=c.node_id, target_id=e.node_id, relationship_type="to", weight=1.0),
                Edge(source_id=e.node_id, target_id=d.node_id, relationship_type="to", weight=1.0),
            ]
        )

        result = dijkstra_shortest_path(storage, a.node_id, d.node_id, include_node_risk=False)
        self.assertIsNotNone(result)
        assert result is not None

        # The chosen path is longer in hops (3) but cheaper in total edge cost (3.0).
        self.assertEqual(result.path, [a.node_id, c.node_id, e.node_id, d.node_id])
        self.assertEqual(result.hops, 3)
        self.assertAlmostEqual(result.total_cost, 3.0, delta=0.05)


if __name__ == "__main__":
    unittest.main()
