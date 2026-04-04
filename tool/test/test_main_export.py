from __future__ import annotations

import importlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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
                cve="CVE-2026-1000",
                cvss=8.8,
            )
        ]
        payload = main_mod._graph_data_to_dict(ClusterGraphData(nodes=nodes, edges=edges))

        self.assertEqual(payload["schema_version"], "1.0.0")
        self.assertEqual(len(payload["nodes"]), 2)
        self.assertEqual(len(payload["edges"]), 1)
        self.assertIn("node_id", payload["nodes"][0])
        self.assertIn("relationship_type", payload["edges"][0])
        self.assertEqual(payload["edges"][0]["cve"], "CVE-2026-1000")
        self.assertEqual(payload["edges"][0]["cvss"], 8.8)

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

    def test_main_uses_graph_in_artifact_without_invoking_ingestors(self) -> None:
        payload = {
            "schema_version": "1.0.0",
            "nodes": [
                {
                    "node_id": "Pod:default:web",
                    "entity_type": "Pod",
                    "name": "web",
                    "namespace": "default",
                    "risk_score": 3.0,
                    "is_source": True,
                    "is_sink": False,
                },
                {
                    "node_id": "Secret:default:db-creds",
                    "entity_type": "Secret",
                    "name": "db-creds",
                    "namespace": "default",
                    "risk_score": 8.0,
                    "is_source": False,
                    "is_sink": True,
                },
            ],
            "edges": [
                {
                    "source_id": "Pod:default:web",
                    "target_id": "Secret:default:db-creds",
                    "relationship_type": "can_read",
                    "weight": 2.0,
                }
            ],
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            graph_in = Path(tmp_dir) / "in.json"
            graph_out = Path(tmp_dir) / "out.json"
            graph_in.write_text(json.dumps(payload), encoding="utf-8")

            with patch.object(
                main_mod,
                "KubectlDataIngestor",
                side_effect=AssertionError("kubectl ingestor should not be used when --graph-in is set"),
            ), patch.object(
                main_mod,
                "MockDataIngestor",
                side_effect=AssertionError("mock ingestor should not be used when --graph-in is set"),
            ), patch.object(
                main_mod,
                "render_cli_report",
                return_value="ok\n",
            ), patch.object(
                sys,
                "argv",
                [
                    "main.py",
                    "--graph-in",
                    str(graph_in),
                    "--graph-out",
                    str(graph_out),
                ],
            ), patch.object(main_mod.sys, "stdout", new=io.StringIO()):
                code = main_mod.main()

            self.assertEqual(code, 0)
            self.assertTrue(graph_out.exists())
            exported = json.loads(graph_out.read_text(encoding="utf-8"))
            self.assertEqual(exported["schema_version"], "1.0.0")
            self.assertEqual(len(exported["nodes"]), 2)
            self.assertEqual(len(exported["edges"]), 1)

    def test_main_writes_pdf_artifact_when_pdf_out_set(self) -> None:
        payload = {
            "schema_version": "1.0.0",
            "nodes": [
                {
                    "node_id": "Pod:default:web",
                    "entity_type": "Pod",
                    "name": "web",
                    "namespace": "default",
                    "risk_score": 3.0,
                    "is_source": True,
                    "is_sink": False,
                },
                {
                    "node_id": "Secret:default:db-creds",
                    "entity_type": "Secret",
                    "name": "db-creds",
                    "namespace": "default",
                    "risk_score": 8.0,
                    "is_source": False,
                    "is_sink": True,
                },
            ],
            "edges": [
                {
                    "source_id": "Pod:default:web",
                    "target_id": "Secret:default:db-creds",
                    "relationship_type": "can_read",
                    "weight": 2.0,
                }
            ],
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            graph_in = Path(tmp_dir) / "in.json"
            graph_out = Path(tmp_dir) / "out.json"
            pdf_out = Path(tmp_dir) / "report.pdf"
            graph_in.write_text(json.dumps(payload), encoding="utf-8")

            with patch.object(
                sys,
                "argv",
                [
                    "main.py",
                    "--graph-in",
                    str(graph_in),
                    "--graph-out",
                    str(graph_out),
                    "--pdf-out",
                    str(pdf_out),
                ],
            ), patch.object(main_mod.sys, "stdout", new=io.StringIO()):
                code = main_mod.main()

            self.assertEqual(code, 0)
            self.assertTrue(pdf_out.exists())
            pdf_bytes = pdf_out.read_bytes()
            self.assertTrue(pdf_bytes.startswith(b"%PDF-1.4"))

    def test_main_passes_include_cluster_rbac_flag_to_kubectl_ingestor(self) -> None:
        source = Node(entity_type="Pod", name="web", namespace="demo", is_source=True)
        sink = Node(entity_type="Secret", name="db-creds", namespace="demo", is_sink=True)
        graph = ClusterGraphData(
            nodes=[source, sink],
            edges=[
                Edge(
                    source_id=source.node_id,
                    target_id=sink.node_id,
                    relationship_type="can_read",
                    weight=1.0,
                )
            ],
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            graph_out = Path(tmp_dir) / "out.json"

            with patch.object(main_mod, "KubectlDataIngestor") as kubectl_ingestor_cls, patch.object(
                sys,
                "argv",
                [
                    "main.py",
                    "--ingestor",
                    "kubectl",
                    "--namespace",
                    "demo",
                    "--include-cluster-rbac",
                    "false",
                    "--graph-out",
                    str(graph_out),
                ],
            ), patch.object(main_mod.sys, "stdout", new=io.StringIO()):
                kubectl_ingestor_cls.return_value.ingest.return_value = graph
                code = main_mod.main()

            self.assertEqual(code, 0)
            kubectl_ingestor_cls.assert_called_once_with(
                fallback_file=None,
                namespace="demo",
                include_cluster_rbac=False,
            )


if __name__ == "__main__":
    unittest.main()
