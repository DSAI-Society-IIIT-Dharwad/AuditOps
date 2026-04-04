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

mock_parser = importlib.import_module("ingestion.mock_parser")
MockDataIngestor = mock_parser.MockDataIngestor
MockParserError = mock_parser.MockParserError


class TestMockDataIngestor(unittest.TestCase):
	def test_missing_file_raises(self) -> None:
		ingestor = MockDataIngestor(file_path="does-not-exist.json")
		with self.assertRaises(MockParserError):
			ingestor.ingest()

	def test_invalid_json_raises(self) -> None:
		with tempfile.TemporaryDirectory() as tmp_dir:
			file_path = Path(tmp_dir) / "bad.json"
			file_path.write_text("{bad-json", encoding="utf-8")
			ingestor = MockDataIngestor(file_path=file_path)
			with self.assertRaises(MockParserError):
				ingestor.ingest()

	def test_normalized_payload_parses(self) -> None:
		payload = {
			"nodes": [
				{
					"entity_type": "User",
					"name": "dev-1",
					"namespace": "cluster",
					"risk_score": 5.0,
					"is_source": True,
				},
				{
					"entity_type": "Secret",
					"name": "prod-db-creds",
					"namespace": "prod",
					"risk_score": 9.0,
					"is_sink": True,
				},
			],
			"edges": [
				{
					"source_id": "User:cluster:dev-1",
					"target_id": "Secret:prod:prod-db-creds",
					"relationship_type": "can_read",
					"weight": 2.5,
				}
			],
		}

		with tempfile.TemporaryDirectory() as tmp_dir:
			file_path = Path(tmp_dir) / "graph.json"
			file_path.write_text(json.dumps(payload), encoding="utf-8")
			graph = MockDataIngestor(file_path=file_path).ingest()

		self.assertEqual(len(graph.nodes), 2)
		self.assertEqual(len(graph.edges), 1)
		self.assertEqual(graph.edges[0].relationship_type, "can_read")

	def test_normalized_payload_with_missing_node_reference_fails(self) -> None:
		payload = {
			"nodes": [
				{"entity_type": "User", "name": "dev-1", "namespace": "cluster"},
			],
			"edges": [
				{
					"source_id": "User:cluster:dev-1",
					"target_id": "Secret:prod:db",
					"relationship_type": "can_read",
					"weight": 1.0,
				}
			],
		}
		with tempfile.TemporaryDirectory() as tmp_dir:
			file_path = Path(tmp_dir) / "broken.json"
			file_path.write_text(json.dumps(payload), encoding="utf-8")
			ingestor = MockDataIngestor(file_path=file_path)
			with self.assertRaises(MockParserError):
				ingestor.ingest()

	def test_kubernetes_style_payload_parses_via_normalizer(self) -> None:
		payload = {
			"pods": {
				"items": [
					{
						"metadata": {"name": "web", "namespace": "default"},
						"spec": {"serviceAccountName": "web-sa"},
					}
				]
			},
			"serviceaccounts": {"items": []},
			"rolebindings": {"items": []},
			"clusterrolebindings": {"items": []},
			"secrets": {"items": []},
			"configmaps": {"items": []},
		}
		with tempfile.TemporaryDirectory() as tmp_dir:
			file_path = Path(tmp_dir) / "k8s.json"
			file_path.write_text(json.dumps(payload), encoding="utf-8")
			graph = MockDataIngestor(file_path=file_path).ingest()

		ids = {node.node_id for node in graph.nodes}
		self.assertIn("Pod:default:web", ids)
		self.assertIn("ServiceAccount:default:web-sa", ids)


if __name__ == "__main__":
	unittest.main()
