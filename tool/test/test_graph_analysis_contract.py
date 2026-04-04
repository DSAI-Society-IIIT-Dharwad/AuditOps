from __future__ import annotations

import importlib
import unittest
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

Node = importlib.import_module("core.models").Node
build_nodes = importlib.import_module("services.contracts.graph_analysis_contract").build_nodes


class TestGraphAnalysisContract(unittest.TestCase):
    def test_build_nodes_includes_nvd_enrichment_fields(self) -> None:
        nodes = [
            Node(
                entity_type="Pod",
                name="web",
                namespace="demo",
                risk_score=13.5,
                nvd_enriched=True,
                nvd_source="nvd",
                nvd_max_cvss=8.7,
                nvd_cve_ids=("CVE-2024-1111", "CVE-2024-2222"),
                nvd_image_refs=("nginx:1.25.3",),
            )
        ]

        rows = build_nodes(nodes)

        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertTrue(row["nvd_enriched"])
        self.assertEqual(row["nvd_source"], "nvd")
        self.assertEqual(row["nvd_max_cvss"], 8.7)
        self.assertEqual(row["nvd_cve_ids"], ["CVE-2024-1111", "CVE-2024-2222"])
        self.assertEqual(row["nvd_image_refs"], ["nginx:1.25.3"])
        self.assertIn("nvd-enriched", row["tags"])

    def test_build_nodes_defaults_nvd_fields_for_non_enriched_nodes(self) -> None:
        rows = build_nodes([Node(entity_type="Secret", name="db", namespace="demo", is_sink=True)])

        self.assertEqual(rows[0]["nvd_enriched"], False)
        self.assertEqual(rows[0]["nvd_source"], None)
        self.assertEqual(rows[0]["nvd_max_cvss"], None)
        self.assertEqual(rows[0]["nvd_cve_ids"], [])
        self.assertEqual(rows[0]["nvd_image_refs"], [])
        self.assertEqual(rows[0]["temporal_status"], None)
        self.assertEqual(rows[0]["risk_delta"], None)

    def test_build_nodes_includes_temporal_fields_when_present(self) -> None:
        node = Node(entity_type="Pod", name="web", namespace="demo", risk_score=7.0)

        rows = build_nodes(
            [node],
            temporal_node_by_id={
                node.node_id: {
                    "status": "risk_changed",
                    "risk_delta": 2.5,
                }
            },
        )

        self.assertEqual(rows[0]["temporal_status"], "risk_changed")
        self.assertEqual(rows[0]["risk_delta"], 2.5)
        self.assertIn("temporal-risk_changed", rows[0]["tags"])


if __name__ == "__main__":
    unittest.main()
