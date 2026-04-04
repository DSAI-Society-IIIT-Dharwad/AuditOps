from __future__ import annotations

import json
import importlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
	sys.path.insert(0, str(SRC))

kubectl_runner = importlib.import_module("ingestion.kubectl_runner")
KubectlDataIngestor = kubectl_runner.KubectlDataIngestor
KubectlIngestError = kubectl_runner.KubectlIngestError
build_cluster_graph_data = kubectl_runner.build_cluster_graph_data


class TestBuildClusterGraphData(unittest.TestCase):
	def test_builds_nodes_edges_for_pod_and_bindings(self) -> None:
		payload = {
			"pods": {
				"items": [
					{
						"metadata": {
							"name": "web",
							"namespace": "default",
							"labels": {"public": "true"},
						},
						"spec": {
							"serviceAccountName": "web-sa",
							"volumes": [
								{"secret": {"secretName": "db-secret"}},
								{"configMap": {"name": "app-config"}},
							],
							"containers": [
								{
									"envFrom": [
										{"secretRef": {"name": "api-secret"}},
										{"configMapRef": {"name": "runtime-config"}},
									]
								}
							],
						},
					}
				]
			},
			"serviceaccounts": {"items": []},
			"roles": {
				"items": [
					{
						"metadata": {"name": "secret-reader", "namespace": "default"},
						"rules": [{"resources": ["secrets"], "resourceNames": ["db-secret"]}],
					}
				]
			},
			"secrets": {"items": []},
			"configmaps": {"items": []},
			"rolebindings": {
				"items": [
					{
						"metadata": {"name": "read-secrets", "namespace": "default"},
						"roleRef": {"kind": "Role", "name": "secret-reader"},
						"subjects": [
							{"kind": "ServiceAccount", "name": "web-sa", "namespace": "default"},
							{"kind": "User", "name": "dev-1"},
						],
					}
				]
			},
			"clusterrolebindings": {
				"items": [
					{
						"metadata": {"name": "cluster-admins"},
						"roleRef": {"name": "cluster-admin"},
						"subjects": [{"kind": "User", "name": "ops-1"}],
					}
				]
			},
		}

		graph = build_cluster_graph_data(payload)
		node_ids = {node.node_id for node in graph.nodes}
		edge_triplets = {(edge.source_id, edge.target_id, edge.relationship_type) for edge in graph.edges}

		self.assertIn("Pod:default:web", node_ids)
		self.assertIn("ServiceAccount:default:web-sa", node_ids)
		self.assertIn("Role:default:secret-reader", node_ids)
		self.assertIn("ClusterRole:cluster:cluster-admin", node_ids)
		self.assertIn("Secret:default:db-secret", node_ids)
		self.assertIn("ConfigMap:default:app-config", node_ids)

		pod_node = next(node for node in graph.nodes if node.node_id == "Pod:default:web")
		self.assertTrue(pod_node.is_source)

		self.assertIn(
			("Pod:default:web", "ServiceAccount:default:web-sa", "uses"),
			edge_triplets,
		)
		self.assertIn(
			("ServiceAccount:default:web-sa", "Role:default:secret-reader", "bound_to"),
			edge_triplets,
		)
		self.assertIn(
			("User:cluster:dev-1", "Role:default:secret-reader", "bound_to"),
			edge_triplets,
		)
		self.assertIn(
			("Role:default:secret-reader", "Secret:default:db-secret", "can_read"),
			edge_triplets,
		)


class TestKubectlDataIngestor(unittest.TestCase):
	@patch("ingestion.kubectl_runner.subprocess.run")
	def test_run_kubectl_get_success(self, run_mock) -> None:
		run_mock.return_value = subprocess.CompletedProcess(
			args=["kubectl"],
			returncode=0,
			stdout='{"items": []}',
			stderr="",
		)
		ingestor = KubectlDataIngestor()

		result = ingestor._run_kubectl_get("pods")
		self.assertEqual(result, {"items": []})

	@patch("ingestion.kubectl_runner.subprocess.run", side_effect=FileNotFoundError())
	def test_run_kubectl_get_missing_binary(self, _run_mock) -> None:
		ingestor = KubectlDataIngestor()
		with self.assertRaises(KubectlIngestError):
			ingestor._run_kubectl_get("pods")

	def test_ingest_uses_fallback_when_kubectl_fails(self) -> None:
		fallback_payload = {
			"pods": {"items": [{"metadata": {"name": "p1", "namespace": "default"}, "spec": {}}]},
			"serviceaccounts": {"items": []},
			"roles": {"items": []},
			"rolebindings": {"items": []},
			"clusterrolebindings": {"items": []},
			"secrets": {"items": []},
			"configmaps": {"items": []},
		}

		with tempfile.TemporaryDirectory() as tmp_dir:
			fallback_file = Path(tmp_dir) / "mock.json"
			fallback_file.write_text(json.dumps(fallback_payload), encoding="utf-8")

			ingestor = KubectlDataIngestor(fallback_file=fallback_file)
			with patch.object(
				ingestor,
				"_run_kubectl_get",
				side_effect=KubectlIngestError("cluster unavailable"),
			):
				graph = ingestor.ingest()

		self.assertGreaterEqual(len(graph.nodes), 2)
		self.assertTrue(any(node.node_id == "Pod:default:p1" for node in graph.nodes))

	def test_ingest_raises_without_fallback(self) -> None:
		ingestor = KubectlDataIngestor()
		with patch.object(
			ingestor,
			"_run_kubectl_get",
			side_effect=KubectlIngestError("cluster unavailable"),
		):
			with self.assertRaises(KubectlIngestError):
				ingestor.ingest()

	def test_pod_cvss_annotation_enriches_risk_score(self) -> None:
		payload = {
			"pods": {
				"items": [
					{
						"metadata": {
							"name": "web",
							"namespace": "default",
							"annotations": {"security.analysis/cvss": "8.1"},
						},
						"spec": {"serviceAccountName": "web-sa"},
					}
				]
			},
			"serviceaccounts": {"items": []},
			"roles": {"items": []},
			"rolebindings": {"items": []},
			"clusterrolebindings": {"items": []},
			"secrets": {"items": []},
			"configmaps": {"items": []},
		}

		graph = build_cluster_graph_data(payload)
		pod = next(node for node in graph.nodes if node.node_id == "Pod:default:web")
		self.assertAlmostEqual(pod.risk_score, 13.1, places=3)

	def test_pod_cve_annotation_adds_default_risk_bonus(self) -> None:
		payload = {
			"pods": {
				"items": [
					{
						"metadata": {
							"name": "web",
							"namespace": "default",
							"annotations": {"security.analysis/cve": "CVE-2024-1234"},
						},
						"spec": {"serviceAccountName": "web-sa"},
					}
				]
			},
			"serviceaccounts": {"items": []},
			"roles": {"items": []},
			"rolebindings": {"items": []},
			"clusterrolebindings": {"items": []},
			"secrets": {"items": []},
			"configmaps": {"items": []},
		}

		graph = build_cluster_graph_data(payload)
		pod = next(node for node in graph.nodes if node.node_id == "Pod:default:web")
		self.assertAlmostEqual(pod.risk_score, 7.0, places=3)


if __name__ == "__main__":
	unittest.main()
