from __future__ import annotations

import importlib
import unittest
from unittest.mock import patch
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from fastapi.testclient import TestClient

create_app = importlib.import_module("api.app").create_app
KubectlIngestError = importlib.import_module("ingestion.kubectl_runner").KubectlIngestError


class TestGraphAnalysisApi(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(create_app())

    @patch("api.routes.graph_analysis.get_graph_analysis")
    def test_graph_analysis_returns_payload(self, get_graph_analysis_mock) -> None:
        get_graph_analysis_mock.return_value = {
            "schema_version": "1.0.0",
            "generated_at": "2026-04-04T00:00:00Z",
            "context": {"cluster": "kind-hack2future", "namespace": "demo", "directed": True},
            "summary": {"node_count": 1, "edge_count": 0, "source_count": 1, "sink_count": 0},
            "nodes": [],
            "edges": [],
            "analysis": {
                "attack_path": {
                    "source": "Pod:demo:web",
                    "target": "Secret:demo:db",
                    "path_node_ids": [],
                    "path_edge_ids": [],
                    "hops": 0,
                    "risk_score": 0.0,
                    "severity": "LOW",
                },
                "blast_radius": {
                    "source": "Pod:demo:web",
                    "max_hops": 3,
                    "reachable_node_ids": [],
                    "hops_by_node": {},
                },
                "cycles": {"count": 0, "items": []},
                "critical_node": {},
                "recommendations": [],
            },
        }

        response = self.client.get("/api/v1/graph-analysis?namespace=demo")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["schema_version"], "1.0.0")
        self.assertIn("analysis", payload)
        get_graph_analysis_mock.assert_called_once_with(
            namespace="demo",
            include_cluster_rbac=True,
            enable_nvd_scoring=False,
            max_hops=3,
            max_depth=8,
        )

    @patch("api.routes.graph_analysis.get_graph_analysis", side_effect=KubectlIngestError("kubectl unavailable"))
    def test_graph_analysis_returns_503_when_ingestion_fails(self, _get_graph_analysis_mock) -> None:
        response = self.client.get("/api/v1/graph-analysis")
        self.assertEqual(response.status_code, 503)
        self.assertIn("kubectl unavailable", response.json().get("detail", ""))


if __name__ == "__main__":
    unittest.main()
