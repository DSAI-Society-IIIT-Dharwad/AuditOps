from __future__ import annotations

import importlib
import unittest
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
	sys.path.insert(0, str(SRC))

formatter_module = importlib.import_module("reporting.cli_formatter")
CliFormatter = formatter_module.CliFormatter
render_cli_report = formatter_module.render_cli_report


class TestCliFormatter(unittest.TestCase):
	def test_formats_full_report(self) -> None:
		report = {
			"attack_path": {
				"source": "User:cluster:dev-1",
				"target": "Database:prod:production-db",
				"path": [
					"User:cluster:dev-1",
					{"name": "Pod-X", "cve": "CVE-2024-1234", "cvss": 8.1},
					"ServiceAccount:default:webapp",
					"Secret:prod:db-credentials",
					"Database:prod:production-db",
				],
				"risk_score": 24.7,
			},
			"blast_radius": {
				"source": "Pod:default:pod-x",
				"max_hops": 3,
				"reachable_nodes": ["A", "B", "C"],
			},
			"cycles": [["Service-A", "Service-B", "Service-A"]],
			"critical_node": {
				"node_id": "RoleBinding:default:role-x",
				"total_paths_before": 11,
				"total_paths_after": 3,
				"paths_removed": 8,
			},
			"recommendations": ["Remove Role-X binding", "Rotate db credentials"],
		}

		text = CliFormatter().format_report(report)
		self.assertIn("Kubernetes Kill Chain Report", text)
		self.assertIn("⚠ Attack Path Detected", text)
		self.assertIn("Hops: 4 | Risk: 24.7 (CRITICAL)", text)
		self.assertIn("Blast Radius: 3 node(s) within 3 hop(s)", text)
		self.assertIn("Cycles: 1", text)
		self.assertIn("Sample Cycle: Service-A -> Service-B -> Service-A", text)
		self.assertIn("Critical Node: RoleBinding/role-x (default)", text)
		self.assertIn("✓ Recommendations", text)

	def test_render_cli_report_function(self) -> None:
		text = render_cli_report({})
		self.assertIn("✓ No Attack Path Detected", text)

	def test_formats_structured_report_shape(self) -> None:
		report = {
			"metadata": {"generated_at": "2026-04-04 12:00:00", "nodes": 4, "edges": 3},
			"attack_paths": [
				{
					"hops": 2,
					"risk_score": 11.5,
					"path": ["User:default:dev-1", "Pod:default:web", "Secret:default:db"],
					"edges": [
						{
							"source": "User:default:dev-1",
							"target": "Pod:default:web",
							"relationship": "can-exec",
							"cve": "CVE-2026-1000",
							"cvss": 8.1,
						},
						{
							"source": "Pod:default:web",
							"target": "Secret:default:db",
							"relationship": "can-read",
						},
					],
				}
			],
			"blast_radius_by_source": [
				{
					"source": "User:default:dev-1",
					"count": 2,
					"max_hops": 2,
					"hops": {"1": ["Pod:default:web"], "2": ["Secret:default:db"]},
				}
			],
			"cycles": [["A", "B", "A"]],
			"baseline_attack_paths": 3,
			"critical_nodes": [
				{"node_id": "Pod:default:web", "paths_removed": 2},
			],
			"summary": {
				"attack_paths_found": 1,
				"cycles_found": 1,
				"blast_nodes_exposed": 2,
				"critical_node": "Pod:default:web",
			},
		}

		text = CliFormatter().format_report(report)
		self.assertIn("[ SECTION 1 — ATTACK PATH DETECTION (Dijkstra) ]", text)
		self.assertIn("Path #1", text)
		self.assertIn("[ SECTION 2 — BLAST RADIUS ANALYSIS (BFS, depth=3) ]", text)
		self.assertIn("[ SECTION 4 — CRITICAL NODE ANALYSIS ]", text)
		self.assertIn("SUMMARY", text)


if __name__ == "__main__":
	unittest.main()
