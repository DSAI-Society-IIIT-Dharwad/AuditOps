from __future__ import annotations

import importlib
import tempfile
import unittest
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

core_models = importlib.import_module("core.models")
networkx_builder = importlib.import_module("graph.networkx_builder")
temporal_module = importlib.import_module("services.temporal.snapshot_diff")

ClusterGraphData = core_models.ClusterGraphData
Edge = core_models.Edge
Node = core_models.Node
NetworkXGraphStorage = networkx_builder.NetworkXGraphStorage

build_scope_id = temporal_module.build_scope_id
compute_temporal_analysis = temporal_module.compute_temporal_analysis
load_previous_snapshot = temporal_module.load_previous_snapshot
save_snapshot = temporal_module.save_snapshot


class TestTemporalSnapshotDiff(unittest.TestCase):
    def test_save_and_load_previous_snapshot_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            scope_id = build_scope_id(
                namespace="demo",
                include_cluster_rbac=True,
                ingestor="mock",
                enable_nvd_scoring=False,
                source="cli",
            )
            graph = self._graph_data(has_path=False)

            saved = save_snapshot(
                graph,
                scope_id=scope_id,
                namespace="demo",
                include_cluster_rbac=True,
                ingestor="mock",
                enable_nvd_scoring=False,
                source="cli",
                snapshot_dir=tmp_dir,
                snapshot_timestamp="20260405T000000000000Z",
            )
            loaded = load_previous_snapshot(scope_id, snapshot_dir=tmp_dir)

            self.assertTrue(saved.path.exists())
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(loaded.scope_id, scope_id)
            self.assertEqual(len(loaded.storage.all_nodes()), 3)
            self.assertEqual(len(loaded.storage.all_edges()), 1)

    def test_compute_temporal_analysis_baseline_without_previous_snapshot(self) -> None:
        storage = NetworkXGraphStorage.from_cluster_graph_data(self._graph_data(has_path=False))

        temporal = compute_temporal_analysis(
            current_storage=storage,
            previous_snapshot=None,
            namespace="demo",
            scope_id="scope-demo",
            snapshot_timestamp="20260405T010000000000Z",
        )

        self.assertTrue(temporal["is_first_snapshot"])
        self.assertEqual(temporal["new_attack_paths_count"], 0)
        self.assertEqual(temporal["alerts"], [])

    def test_compute_temporal_analysis_detects_new_attack_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            scope_id = build_scope_id(
                namespace="demo",
                include_cluster_rbac=True,
                ingestor="mock",
                enable_nvd_scoring=False,
                source="cli",
            )

            previous_graph = self._graph_data(has_path=False)
            current_graph = self._graph_data(has_path=True)

            save_snapshot(
                previous_graph,
                scope_id=scope_id,
                namespace="demo",
                include_cluster_rbac=True,
                ingestor="mock",
                enable_nvd_scoring=False,
                source="cli",
                snapshot_dir=tmp_dir,
                snapshot_timestamp="20260405T020000000000Z",
            )
            previous_snapshot = load_previous_snapshot(scope_id, snapshot_dir=tmp_dir)
            self.assertIsNotNone(previous_snapshot)

            temporal = compute_temporal_analysis(
                current_storage=NetworkXGraphStorage.from_cluster_graph_data(current_graph),
                previous_snapshot=previous_snapshot,
                namespace="demo",
                scope_id=scope_id,
                snapshot_timestamp="20260405T030000000000Z",
            )

            self.assertFalse(temporal["is_first_snapshot"])
            self.assertEqual(temporal["new_attack_paths_count"], 1)
            self.assertEqual(temporal["connectivity"]["new_attack_paths_count"], 1)
            self.assertEqual(temporal["edge_changes"]["added_count"], 1)
            self.assertGreaterEqual(len(temporal["alerts"]), 1)
            self.assertEqual(temporal["alerts"][0]["type"], "new-attack-path")

    def _graph_data(self, *, has_path: bool) -> ClusterGraphData:
        source = Node(entity_type="Pod", name="entry", namespace="demo", is_source=True, risk_score=3.0)
        bridge = Node(entity_type="Role", name="bridge", namespace="demo", risk_score=2.0)
        sink = Node(entity_type="Secret", name="db-creds", namespace="demo", is_sink=True, risk_score=8.0)

        edges = [
            Edge(
                source_id=source.node_id,
                target_id=bridge.node_id,
                relationship_type="uses",
                weight=2.0,
            )
        ]
        if has_path:
            edges.append(
                Edge(
                    source_id=bridge.node_id,
                    target_id=sink.node_id,
                    relationship_type="can_read",
                    weight=3.0,
                )
            )

        return ClusterGraphData(nodes=[source, bridge, sink], edges=edges)


if __name__ == "__main__":
    unittest.main()
