from __future__ import annotations

import importlib
import unittest
from unittest.mock import patch
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

NVDCveScorer = importlib.import_module("services.cve.nvd_scorer").NVDCveScorer
_parse_image_ref = importlib.import_module("services.cve.nvd_scorer")._parse_image_ref


class _FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def read(self) -> bytes:
        import json

        return json.dumps(self._payload).encode("utf-8")


class TestNVDCveScorer(unittest.TestCase):
    def test_parse_image_ref_extracts_product_and_version(self) -> None:
        product, version = _parse_image_ref("ghcr.io/demo/nginx:v1.25.3")
        self.assertEqual(product, "nginx")
        self.assertEqual(version, "v1.25.3")

    @patch("services.cve.nvd_scorer.urlopen")
    def test_score_image_uses_cache(self, open_mock) -> None:
        def _mock_open(request, timeout=0):
            _ = timeout
            url = request.full_url
            if "cpes" in url:
                return _FakeResponse(
                    {
                        "products": [
                            {
                                "cpe": {
                                    "deprecated": False,
                                    "cpeName": "cpe:2.3:a:nginx:nginx:1.25.3:*:*:*:*:*:*:*",
                                }
                            }
                        ]
                    }
                )
            return _FakeResponse(
                {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": "CVE-2024-0001",
                                "metrics": {
                                    "cvssMetricV31": [
                                        {"type": "Primary", "cvssData": {"baseScore": 8.2}}
                                    ]
                                },
                            }
                        }
                    ]
                }
            )

        open_mock.side_effect = _mock_open

        scorer = NVDCveScorer(timeout=5)
        first = scorer.score_image("nginx:1.25.3")
        second = scorer.score_image("nginx:1.25.3")

        self.assertEqual(first.max_cvss, 8.2)
        self.assertEqual(first.cve_ids, ("CVE-2024-0001",))
        self.assertEqual(second.max_cvss, 8.2)
        self.assertEqual(open_mock.call_count, 2)

    @patch("services.cve.nvd_scorer.urlopen", side_effect=TimeoutError("timed out"))
    def test_score_image_returns_empty_on_http_failure(self, _open_mock) -> None:
        scorer = NVDCveScorer(timeout=1)
        result = scorer.score_image("nginx:1.25.3")

        self.assertEqual(result.max_cvss, 0.0)
        self.assertEqual(result.cve_ids, ())
        self.assertTrue(result.error)


if __name__ == "__main__":
    unittest.main()
