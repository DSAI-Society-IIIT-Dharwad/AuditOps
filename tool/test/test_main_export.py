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
main_mod = importlib.import_module("main")

ClusterGraphData = core_models.ClusterGraphData
Edge = core_models.Edge
Node = core_models.Node


class TestMainExport(unittest.TestCase):
    def test_graph_data_to_dict_schema(self) -> None:
        nodes = [
            Node(entity_type="Pod", name="web", namespace="default", risk_score=5.0, is_source=True),
            Node(entity_type="Secret", name="db-creds", namespace="default", risk_score=9.0, is_sink=True),
        ]
        edges = [
            Edge(
                source_id="Pod:default:web",
                target_id="Secret:default:db-creds",
                relationship_type="can_read",
                weight=3.0,
            )
        ]
        payload = main_mod._graph_data_to_dict(ClusterGraphData(nodes=nodes, edges=edges))

        self.assertEqual(payload["schema_version"], "1.0.0")
        self.assertEqual(len(payload["nodes"]), 2)
        self.assertEqual(len(payload["edges"]), 1)
        self.assertIn("node_id", payload["nodes"][0])
        self.assertIn("relationship_type", payload["edges"][0])

    def test_export_graph_data_writes_file(self) -> None:
        graph = ClusterGraphData(
            nodes=[Node(entity_type="Pod", name="p1", namespace="default")],
            edges=[],
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            out_path = Path(tmp_dir) / "cluster-graph.json"
            main_mod._export_graph_data(graph, str(out_path))

            self.assertTrue(out_path.exists())
            exported = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(exported["schema_version"], "1.0.0")
            self.assertEqual(exported["nodes"][0]["node_id"], "Pod:default:p1")


if __name__ == "__main__":
    unittest.main()
