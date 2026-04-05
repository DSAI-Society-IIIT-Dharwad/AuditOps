from __future__ import annotations

import importlib
import unittest
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

builder_mod = importlib.import_module("graph.networkx_builder")
formatter_mod = importlib.import_module("reporting.cli_formatter")
main_mod = importlib.import_module("main")
mock_parser_mod = importlib.import_module("ingestion.mock_parser")

CliFormatter = formatter_mod.CliFormatter
MockDataIngestor = mock_parser_mod.MockDataIngestor
NetworkXGraphStorage = builder_mod.NetworkXGraphStorage


class TestAttackPathAccuracy(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture_path = ROOT.parent / "tests" / "mock-cluster-graph.json"
        graph_data = MockDataIngestor(file_path=fixture_path).ingest()
        cls.storage = NetworkXGraphStorage.from_cluster_graph_data(graph_data)
        cls.source_ids = main_mod._resolve_source_ids(cls.storage, None, namespace=None)
        cls.sink_ids = main_mod._resolve_sink_ids(cls.storage, None, namespace=None)
        cls.attack_paths = main_mod._enumerate_best_attack_paths(
            cls.storage,
            source_ids=cls.source_ids,
            sink_ids=cls.sink_ids,
        )

    def test_paths_are_sorted_by_risk_score_ascending(self) -> None:
        risk_scores = [float(row["risk_score"]) for row in self.attack_paths]
        self.assertEqual(risk_scores, sorted(risk_scores))

    def test_each_path_has_correct_hops_and_risk_sum(self) -> None:
        self.assertGreater(len(self.attack_paths), 0)
        for row in self.attack_paths:
            path_nodes = [str(node_id) for node_id in row.get("path", [])]
            edges = row.get("edges", [])

            expected_hops = max(0, len(path_nodes) - 1)
            self.assertEqual(int(row.get("hops", -1)), expected_hops)

            summed_weight = round(sum(float(edge.get("weight", 0.0)) for edge in edges), 1)
            self.assertAlmostEqual(float(row.get("risk_score", 0.0)), summed_weight, places=1)

    def test_expected_mock_chain_exists_with_correct_metrics(self) -> None:
        expected_path = [
            "User:default:dev-1",
            "Pod:default:web-frontend",
            "ServiceAccount:default:sa-webapp",
            "Role:default:secret-reader",
            "Secret:default:db-credentials",
            "Database:data:production-db",
        ]

        matching = [row for row in self.attack_paths if row.get("path") == expected_path]
        self.assertEqual(len(matching), 1)

        row = matching[0]
        self.assertEqual(int(row.get("hops", -1)), 5)
        self.assertAlmostEqual(float(row.get("risk_score", 0.0)), 24.1, places=1)

        first_edge = row.get("edges", [])[0]
        self.assertEqual(first_edge.get("cve"), "CVE-2024-1234")
        self.assertAlmostEqual(float(first_edge.get("cvss", 0.0)), 8.1, places=1)

    def test_formatter_shows_cve_annotations_for_cve_edges(self) -> None:
        cve_edge_count = sum(
            1
            for row in self.attack_paths
            for edge in row.get("edges", [])
            if edge.get("cve")
        )
        self.assertGreater(cve_edge_count, 0)

        report = {
            "metadata": {
                "generated_at": "2026-04-05 00:00:00",
                "nodes": len(self.storage.all_nodes()),
                "edges": len(self.storage.all_edges()),
            },
            "attack_paths": self.attack_paths,
            "blast_radius_by_source": [],
            "cycles": [],
            "baseline_attack_paths": 0,
            "critical_nodes": [],
            "summary": {
                "attack_paths_found": len(self.attack_paths),
                "cycles_found": 0,
                "blast_nodes_exposed": 0,
                "critical_node": "none",
            },
        }

        rendered = CliFormatter().format_report(report)
        self.assertIn("[CVE-2024-1234, CVSS 8.1]", rendered)
        self.assertGreaterEqual(rendered.count("CVE-"), cve_edge_count)


if __name__ == "__main__":
    unittest.main()
