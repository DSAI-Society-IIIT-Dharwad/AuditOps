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

    @patch("api.routes.graph_analysis.list_snapshots")
    def test_graph_analysis_snapshots_returns_items(self, list_snapshots_mock) -> None:
        list_snapshots_mock.return_value = [
            {
                "scope_id": "api__kubectl__demo__cluster-rbac__nvd-off",
                "snapshot_timestamp": "20260405T120000000000Z",
                "namespace": "demo",
                "include_cluster_rbac": True,
                "ingestor": "kubectl",
                "enable_nvd_scoring": False,
                "source": "api",
                "node_count": 5,
                "edge_count": 4,
                "file_name": "snapshot-20260405T120000000000Z.json",
                "file_path": "/tmp/snapshot.json",
                "rolled_back_from": None,
            }
        ]

        response = self.client.get("/api/v1/snapshots?namespace=demo")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("items", payload)
        self.assertEqual(len(payload["items"]), 1)
        self.assertEqual(payload["items"][0]["namespace"], "demo")
        list_snapshots_mock.assert_called_once_with(limit=200)

    @patch("api.routes.graph_analysis.load_snapshot_payload")
    def test_graph_analysis_snapshot_detail_returns_payload(self, load_snapshot_payload_mock) -> None:
        load_snapshot_payload_mock.return_value = {
            "schema_version": "1.0.0",
            "nodes": [],
            "edges": [],
            "temporal": {
                "snapshot_timestamp": "20260405T121500000000Z",
                "scope_id": "api__kubectl__demo__cluster-rbac__nvd-off",
            },
        }

        response = self.client.get("/api/v1/snapshots/api__kubectl__demo__cluster-rbac__nvd-off/20260405T121500000000Z")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["scope_id"], "api__kubectl__demo__cluster-rbac__nvd-off")
        self.assertEqual(payload["snapshot_timestamp"], "20260405T121500000000Z")
        self.assertIn("payload", payload)
        load_snapshot_payload_mock.assert_called_once_with(
            "api__kubectl__demo__cluster-rbac__nvd-off",
            "20260405T121500000000Z",
        )

    @patch("api.routes.graph_analysis.rollback_snapshot")
    def test_graph_analysis_snapshot_rollback_promotes_snapshot(self, rollback_snapshot_mock) -> None:
        rollback_snapshot_mock.return_value = {
            "scope_id": "api__kubectl__demo__cluster-rbac__nvd-off",
            "rolled_back_from": "20260405T100000000000Z",
            "snapshot_timestamp": "20260405T122500000000Z",
            "file_path": "/tmp/snapshot-20260405T122500000000Z.json",
        }

        response = self.client.post(
            "/api/v1/snapshots/api__kubectl__demo__cluster-rbac__nvd-off/20260405T100000000000Z/rollback",
            json={"reason": "restore baseline"},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["rolled_back_from"], "20260405T100000000000Z")
        self.assertEqual(payload["snapshot_timestamp"], "20260405T122500000000Z")
        rollback_snapshot_mock.assert_called_once_with(
            "api__kubectl__demo__cluster-rbac__nvd-off",
            "20260405T100000000000Z",
            reason="restore baseline",
            actor="api",
        )


if __name__ == "__main__":
    unittest.main()
