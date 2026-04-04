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


if __name__ == "__main__":
	unittest.main()
