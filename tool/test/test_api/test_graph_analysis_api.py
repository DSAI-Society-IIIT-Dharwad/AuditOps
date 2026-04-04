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
            "temporal": {
                "enabled": True,
                "is_first_snapshot": True,
                "new_attack_paths_count": 0,
            },
        }

        response = self.client.get("/api/v1/graph-analysis?namespace=demo")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["schema_version"], "1.0.0")
        self.assertIn("analysis", payload)
        self.assertIn("temporal", payload)
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

    @patch("api.routes.graph_analysis.get_graph_analysis_from_payload")
    def test_graph_analysis_ingest_accepts_json_content(self, get_graph_analysis_from_payload_mock) -> None:
        get_graph_analysis_from_payload_mock.return_value = {
            "schema_version": "1.0.0",
            "generated_at": "2026-04-05T00:00:00Z",
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
            "temporal": {"enabled": True, "is_first_snapshot": True, "new_attack_paths_count": 0},
        }

        response = self.client.post(
            "/api/v1/graph-analysis/ingest",
            json={
                "format": "json",
                "namespace": "demo",
                "content": '{"nodes": [], "edges": []}',
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["schema_version"], "1.0.0")
        get_graph_analysis_from_payload_mock.assert_called_once_with(
            graph_payload={"nodes": [], "edges": []},
            namespace="demo",
            include_cluster_rbac=True,
            enable_nvd_scoring=False,
            max_hops=3,
            max_depth=8,
        )

    @patch("api.routes.graph_analysis.get_graph_analysis_from_payload")
    def test_graph_analysis_ingest_accepts_yaml_manifest_content(self, get_graph_analysis_from_payload_mock) -> None:
        get_graph_analysis_from_payload_mock.return_value = {
            "schema_version": "1.0.0",
            "generated_at": "2026-04-05T00:00:00Z",
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
            "temporal": {"enabled": True, "is_first_snapshot": True, "new_attack_paths_count": 0},
        }

        yaml_content = """
apiVersion: v1
kind: Pod
metadata:
  name: web
  namespace: demo
spec:
  containers:
    - name: web
      image: nginx:1.25.3
""".strip()

        response = self.client.post(
            "/api/v1/graph-analysis/ingest",
            json={
                "format": "yaml",
                "namespace": "demo",
                "content": yaml_content,
            },
        )

        self.assertEqual(response.status_code, 200)
        called_kwargs = get_graph_analysis_from_payload_mock.call_args.kwargs
        self.assertEqual(called_kwargs["namespace"], "demo")
        self.assertIn("pods", called_kwargs["graph_payload"])
        self.assertEqual(len(called_kwargs["graph_payload"]["pods"]["items"]), 1)

    def test_graph_analysis_ingest_rejects_invalid_content(self) -> None:
        response = self.client.post(
            "/api/v1/graph-analysis/ingest",
            json={
                "format": "json",
                "namespace": "demo",
                "content": "{invalid-json}",
            },
        )

        self.assertEqual(response.status_code, 422)
        self.assertIn("Invalid JSON payload", response.json().get("detail", ""))


if __name__ == "__main__":
    unittest.main()
