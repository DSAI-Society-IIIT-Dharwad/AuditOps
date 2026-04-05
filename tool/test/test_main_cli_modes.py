from __future__ import annotations

import importlib
import io
import json
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

main_mod = importlib.import_module("main")


class TestMainCliModes(unittest.TestCase):
    def test_selected_report_modes_defaults_to_full_report(self) -> None:
        args = SimpleNamespace(
            full_report=False,
            attack_path=False,
            blast_radius=False,
            cycles=False,
            critical_node=False,
            source=None,
            target=None,
        )

        modes = main_mod._selected_report_modes(args)

        self.assertTrue(modes["full_report"])
        self.assertFalse(modes["attack_path"])
        self.assertFalse(modes["blast_radius"])
        self.assertFalse(modes["cycles"])
        self.assertFalse(modes["critical_node"])

    def test_selected_report_modes_enables_attack_path_when_source_or_target_set(self) -> None:
        args = SimpleNamespace(
            full_report=False,
            attack_path=False,
            blast_radius=False,
            cycles=False,
            critical_node=False,
            source="Pod:demo:web",
            target=None,
        )

        modes = main_mod._selected_report_modes(args)

        self.assertFalse(modes["full_report"])
        self.assertTrue(modes["attack_path"])

    def test_select_report_view_returns_subset_when_mode_is_focused(self) -> None:
        full_report = {
            "attack_path": {"source": "a", "target": "b", "path": ["a", "b"], "risk_score": 1.0},
            "blast_radius": {"source": "a", "reachable_nodes": ["b"]},
            "cycles": [["x", "y", "x"]],
            "critical_node": {"node_id": "x", "paths_removed": 2},
            "recommendations": ["do thing"],
            "metadata": {"generated_at": "2026-04-05 00:00:00"},
        }
        modes = {
            "full_report": False,
            "attack_path": False,
            "blast_radius": True,
            "cycles": True,
            "critical_node": False,
        }

        selected = main_mod._select_report_view(full_report, modes)

        self.assertIn("blast_radius", selected)
        self.assertIn("cycles", selected)
        self.assertIn("recommendations", selected)
        self.assertNotIn("attack_path", selected)
        self.assertNotIn("critical_node", selected)
        self.assertNotIn("metadata", selected)

    def test_main_attack_path_mode_renders_focused_report(self) -> None:
        report = self._run_main_and_capture_report(["--attack-path"])

        self.assertEqual(set(report.keys()), {"attack_path", "recommendations", "temporal"})
        self.assertGreaterEqual(int(report["attack_path"].get("hops", 0)), 1)

    def test_main_blast_radius_mode_renders_focused_report(self) -> None:
        report = self._run_main_and_capture_report(["--blast-radius"])

        self.assertEqual(set(report.keys()), {"blast_radius", "recommendations", "temporal"})
        self.assertGreaterEqual(int(report["blast_radius"].get("count", 0)), 1)

    def test_main_cycles_mode_renders_focused_report(self) -> None:
        report = self._run_main_and_capture_report(["--cycles"])

        self.assertEqual(set(report.keys()), {"cycles", "recommendations", "temporal"})
        self.assertTrue(len(report["cycles"]) >= 1)

    def test_main_critical_node_mode_renders_focused_report(self) -> None:
        report = self._run_main_and_capture_report(["--critical-node"])

        self.assertEqual(set(report.keys()), {"critical_node", "recommendations", "temporal"})
        self.assertIn("node_id", report["critical_node"])

    def test_main_source_target_without_mode_enables_attack_path_focus(self) -> None:
        report = self._run_main_and_capture_report(
            [
                "--source",
                "Pod:demo:entry",
                "--target",
                "Secret:demo:crown",
            ]
        )

        self.assertEqual(set(report.keys()), {"attack_path", "recommendations", "temporal"})

    def test_cli_entrypoint_unknown_node_returns_non_zero_and_human_readable_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            graph_in = root / "in.json"
            graph_out = root / "out.json"
            graph_in.write_text(json.dumps(self._graph_fixture_payload()), encoding="utf-8")

            argv = [
                "main.py",
                "--graph-in",
                str(graph_in),
                "--graph-out",
                str(graph_out),
                "--source",
                "Pod:demo:not-real",
                "--target",
                "Secret:demo:crown",
            ]
            stderr_stream = io.StringIO()

            with patch.object(sys, "argv", argv), patch.object(
                main_mod.sys,
                "stdout",
                new=io.StringIO(),
            ), patch.object(main_mod.sys, "stderr", new=stderr_stream):
                code = main_mod._run_cli_entrypoint()

        self.assertNotEqual(code, 0)
        self.assertIn("Error: source node not found: Pod:demo:not-real", stderr_stream.getvalue())
        self.assertNotIn("Traceback", stderr_stream.getvalue())

    def _run_main_and_capture_report(self, extra_args: list[str]) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            graph_in = root / "in.json"
            graph_out = root / "out.json"
            graph_in.write_text(json.dumps(self._graph_fixture_payload()), encoding="utf-8")

            captured: list[dict[str, object]] = []

            def _capture(report: dict[str, object]) -> str:
                captured.append(report)
                return "ok\n"

            argv = [
                "main.py",
                "--graph-in",
                str(graph_in),
                "--graph-out",
                str(graph_out),
                "--snapshot-dir",
                str(root / "snapshots"),
                *extra_args,
            ]

            with patch.object(main_mod, "render_cli_report", side_effect=_capture), patch.object(
                sys,
                "argv",
                argv,
            ), patch.object(main_mod.sys, "stdout", new=io.StringIO()):
                code = main_mod.main()

            self.assertEqual(code, 0)
            self.assertTrue(graph_out.exists())
            self.assertEqual(len(captured), 1)
            return captured[0]

    def _graph_fixture_payload(self) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "nodes": [
                {
                    "node_id": "Pod:demo:entry",
                    "entity_type": "Pod",
                    "name": "entry",
                    "namespace": "demo",
                    "risk_score": 3.0,
                    "is_source": True,
                    "is_sink": False,
                },
                {
                    "node_id": "Role:demo:bridge",
                    "entity_type": "Role",
                    "name": "bridge",
                    "namespace": "demo",
                    "risk_score": 2.0,
                    "is_source": False,
                    "is_sink": False,
                },
                {
                    "node_id": "Secret:demo:crown",
                    "entity_type": "Secret",
                    "name": "crown",
                    "namespace": "demo",
                    "risk_score": 9.0,
                    "is_source": False,
                    "is_sink": True,
                },
                {
                    "node_id": "Service:demo:service-a",
                    "entity_type": "Service",
                    "name": "service-a",
                    "namespace": "demo",
                    "risk_score": 1.0,
                    "is_source": False,
                    "is_sink": False,
                },
                {
                    "node_id": "Service:demo:service-b",
                    "entity_type": "Service",
                    "name": "service-b",
                    "namespace": "demo",
                    "risk_score": 1.0,
                    "is_source": False,
                    "is_sink": False,
                },
            ],
            "edges": [
                {
                    "source_id": "Pod:demo:entry",
                    "target_id": "Role:demo:bridge",
                    "relationship_type": "uses",
                    "weight": 2.0,
                },
                {
                    "source_id": "Role:demo:bridge",
                    "target_id": "Secret:demo:crown",
                    "relationship_type": "can_read",
                    "weight": 3.0,
                },
                {
                    "source_id": "Service:demo:service-a",
                    "target_id": "Service:demo:service-b",
                    "relationship_type": "admin-grant",
                    "weight": 1.0,
                },
                {
                    "source_id": "Service:demo:service-b",
                    "target_id": "Service:demo:service-a",
                    "relationship_type": "admin-grant",
                    "weight": 1.0,
                },
            ],
        }


if __name__ == "__main__":
    unittest.main()
