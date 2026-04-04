from __future__ import annotations

import importlib
import tempfile
import unittest
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

formatter_module = importlib.import_module("reporting.cli_formatter")
pdf_module = importlib.import_module("reporting.pdf_generator")

render_cli_report = formatter_module.render_cli_report
generate_pdf_report = pdf_module.generate_pdf_report


class TestPdfGenerator(unittest.TestCase):
    def test_generates_pdf_file(self) -> None:
        report = {
            "attack_path": {
                "source": "Pod:default:web",
                "target": "Secret:default:db-creds",
                "path": ["Pod:default:web", "Secret:default:db-creds"],
                "risk_score": 11.2,
            },
            "blast_radius": {
                "source": "Pod:default:web",
                "max_hops": 2,
                "reachable_nodes": ["ServiceAccount:default:web-sa"],
                "count": 1,
            },
            "cycles": [],
            "critical_node": {
                "node_id": "RoleBinding:default:rb",
                "total_paths_before": 3,
                "total_paths_after": 1,
                "paths_removed": 2,
            },
            "recommendations": ["Rotate db credentials"],
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            pdf_path = Path(tmp_dir) / "report.pdf"
            generate_pdf_report(report, str(pdf_path))

            self.assertTrue(pdf_path.exists())
            pdf_bytes = pdf_path.read_bytes()
            self.assertTrue(pdf_bytes.startswith(b"%PDF-1.4"))

    def test_pdf_contains_core_report_tokens(self) -> None:
        report = {
            "attack_path": {
                "source": "Pod:default:web",
                "target": "Secret:default:db-creds",
                "path": ["Pod:default:web", "Secret:default:db-creds"],
                "risk_score": 11.2,
            },
            "blast_radius": {
                "source": "Pod:default:web",
                "max_hops": 2,
                "reachable_nodes": ["ServiceAccount:default:web-sa"],
                "count": 1,
            },
            "cycles": [["Role:default:a", "Role:default:b", "Role:default:a"]],
            "critical_node": {
                "node_id": "RoleBinding:default:rb",
                "total_paths_before": 3,
                "total_paths_after": 1,
                "paths_removed": 2,
            },
            "recommendations": ["Rotate db credentials"],
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            pdf_path = Path(tmp_dir) / "report.pdf"
            generate_pdf_report(report, str(pdf_path))
            pdf_text = pdf_path.read_bytes().decode("latin-1", errors="ignore")

        self.assertIn("Kubernetes Kill Chain Report", pdf_text)
        self.assertIn("Attack Path Detected", pdf_text)
        self.assertIn("Blast Radius", pdf_text)
        self.assertIn("Cycles", pdf_text)
        self.assertIn("Critical Node", pdf_text)

    def test_pdf_has_cli_section_parity(self) -> None:
        report = {
            "attack_path": {
                "source": "Pod:default:web",
                "target": "Secret:default:db-creds",
                "path": ["Pod:default:web", "Secret:default:db-creds"],
                "risk_score": 11.2,
            },
            "blast_radius": {
                "source": "Pod:default:web",
                "max_hops": 2,
                "reachable_nodes": ["ServiceAccount:default:web-sa"],
                "count": 1,
            },
            "cycles": [],
            "critical_node": {
                "node_id": "RoleBinding:default:rb",
                "total_paths_before": 3,
                "total_paths_after": 1,
                "paths_removed": 2,
            },
            "recommendations": ["Rotate db credentials"],
        }

        cli_text = render_cli_report(report)
        parity_tokens = [
            "Kubernetes Kill Chain Report",
            "Attack Path Detected",
            "Blast Radius",
            "Cycles",
            "Critical Node",
            "Recommendations",
        ]

        with tempfile.TemporaryDirectory() as tmp_dir:
            pdf_path = Path(tmp_dir) / "report.pdf"
            generate_pdf_report(report, str(pdf_path))
            pdf_text = pdf_path.read_bytes().decode("latin-1", errors="ignore")

        self.assertIn("Kubernetes Kill Chain Report", cli_text)
        for token in parity_tokens:
            self.assertIn(token, pdf_text)


if __name__ == "__main__":
    unittest.main()
