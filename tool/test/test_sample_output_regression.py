from __future__ import annotations

import importlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

main_mod = importlib.import_module("main")


class TestSampleOutputRegression(unittest.TestCase):
    def test_mock_full_report_matches_sample_output(self) -> None:
        fixtures_dir = ROOT.parent / "tests"
        mock_file = fixtures_dir / "mock-cluster-graph.json"
        sample_file = fixtures_dir / "sample-output.txt"
        expected_output = sample_file.read_text(encoding="utf-8")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_root = Path(tmp_dir)
            graph_out = tmp_root / "cluster-graph.json"
            snapshot_dir = tmp_root / "snapshots"
            argv = [
                "main.py",
                "--ingestor",
                "mock",
                "--mock-file",
                str(mock_file),
                "--graph-out",
                str(graph_out),
                "--snapshot-dir",
                str(snapshot_dir),
            ]

            stdout_stream = io.StringIO()
            stderr_stream = io.StringIO()
            with patch.object(sys, "argv", argv), patch.object(
                main_mod.sys,
                "stdout",
                new=stdout_stream,
            ), patch.object(main_mod.sys, "stderr", new=stderr_stream):
                exit_code = main_mod._run_cli_entrypoint()

        self.assertEqual(exit_code, 0, msg=stderr_stream.getvalue())
        self.assertEqual(stdout_stream.getvalue(), expected_output)


if __name__ == "__main__":
    unittest.main()
