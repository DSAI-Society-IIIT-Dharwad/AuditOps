from __future__ import annotations

from dataclasses import replace
import json
import os
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from services.cve.models import CVEQueryResult


class NVDCveScorer:
    """Resolve CVE and CVSS data from NVD for container image references."""

    _NVD_CPES_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    _NVD_CVES_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        timeout: float = 10.0,
        max_cpe_candidates: int = 3,
    ) -> None:
        self._api_key = (api_key or os.getenv("NVD_API_KEY") or "").strip() or None
        self._timeout = max(1.0, float(timeout))
        self._max_cpe_candidates = max(1, int(max_cpe_candidates))
        self._cache: dict[str, CVEQueryResult] = {}

    def score_image(self, image_ref: str) -> CVEQueryResult:
        image_key = str(image_ref or "").strip()
        if not image_key:
            return CVEQueryResult(image_ref="", error="empty image reference")

        cached = self._cache.get(image_key)
        if cached is not None:
            return cached

        product, version = _parse_image_ref(image_key)
        if not product or not version:
            result = CVEQueryResult(image_ref=image_key, error="image tag missing or unsupported")
            self._cache[image_key] = result
            return result

        try:
            cpe_candidates = self._lookup_cpe_candidates(product=product, version=version)
            if not cpe_candidates:
                result = CVEQueryResult(image_ref=image_key, error="no CPE match found")
                self._cache[image_key] = result
                return result

            all_cves: set[str] = set()
            best = CVEQueryResult(image_ref=image_key)

            for cpe_name in cpe_candidates:
                cve_ids, max_cvss = self._lookup_cves(cpe_name)
                all_cves.update(cve_ids)
                if max_cvss > best.max_cvss:
                    best = CVEQueryResult(
                        image_ref=image_key,
                        cpe_name=cpe_name,
                        cve_ids=tuple(sorted(all_cves)),
                        max_cvss=min(10.0, max_cvss),
                    )

            if best.max_cvss > 0:
                best = replace(best, cve_ids=tuple(sorted(all_cves)))
            else:
                best = CVEQueryResult(
                    image_ref=image_key,
                    cpe_name=cpe_candidates[0],
                    cve_ids=tuple(sorted(all_cves)),
                    max_cvss=0.0,
                    error="no CVE records found",
                )
        except Exception as exc:
            best = CVEQueryResult(image_ref=image_key, error=str(exc))

        self._cache[image_key] = best
        return best

    def _lookup_cpe_candidates(self, *, product: str, version: str) -> list[str]:
        payload = self._get_json(
            self._NVD_CPES_URL,
            params={
                "keywordSearch": product,
                "resultsPerPage": 50,
            },
        )

        products = payload.get("products", []) if isinstance(payload, dict) else []
        if not isinstance(products, list):
            return []

        version_tokens = _version_candidates(version)
        exact: list[str] = []
        wildcard: list[str] = []

        for row in products:
            if not isinstance(row, dict):
                continue
            cpe_row = row.get("cpe", {})
            if not isinstance(cpe_row, dict) or cpe_row.get("deprecated"):
                continue
            cpe_name = str(cpe_row.get("cpeName") or "").strip()
            if not cpe_name:
                continue

            cpe_parts = cpe_name.split(":")
            if len(cpe_parts) < 6:
                continue

            cpe_product = str(cpe_parts[4]).strip().lower()
            cpe_version = str(cpe_parts[5]).strip().lower()
            if cpe_product != product.lower():
                continue

            if cpe_version in version_tokens:
                exact.append(cpe_name)
            elif cpe_version == "*":
                wildcard.append(cpe_name)

        candidates = exact + wildcard
        if candidates:
            return candidates[: self._max_cpe_candidates]

        # Best-effort fallback when product exists but no matching dictionary row was returned.
        fallback = f"cpe:2.3:a:{product}:{product}:{version}:*:*:*:*:*:*:*"
        return [fallback]

    def _lookup_cves(self, cpe_name: str) -> tuple[list[str], float]:
        payload = self._get_json(
            self._NVD_CVES_URL,
            params={
                "cpeName": cpe_name,
                "resultsPerPage": 200,
            },
        )

        vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
        if not isinstance(vulnerabilities, list):
            return [], 0.0

        cve_ids: list[str] = []
        max_cvss = 0.0

        for row in vulnerabilities:
            if not isinstance(row, dict):
                continue
            cve = row.get("cve", {})
            if not isinstance(cve, dict):
                continue

            cve_id = str(cve.get("id") or "").strip()
            if cve_id:
                cve_ids.append(cve_id)

            score = _extract_cvss(cve.get("metrics"))
            if score > max_cvss:
                max_cvss = score

        return cve_ids, min(10.0, max_cvss)

    def _get_json(self, url: str, *, params: dict[str, Any]) -> dict[str, Any]:
        headers: dict[str, str] = {}
        if self._api_key:
            headers["apiKey"] = self._api_key

        query = urlencode(params)
        request_url = f"{url}?{query}" if query else url
        request = Request(request_url, headers=headers)
        with urlopen(request, timeout=self._timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("NVD response payload must be a JSON object")
        return payload


def _parse_image_ref(image_ref: str) -> tuple[str | None, str | None]:
    value = str(image_ref or "").strip()
    if not value:
        return None, None

    # Remove digest suffix (e.g., repo@sha256:abcd...).
    value = value.split("@", 1)[0]
    if "/" in value:
        repo_part = value.rsplit("/", 1)[1]
    else:
        repo_part = value

    if ":" not in repo_part:
        return repo_part.lower() or None, None

    product, version = repo_part.rsplit(":", 1)
    product = product.strip().lower()
    version = version.strip().lower()

    if not product or not version or version == "latest":
        return product or None, None
    return product, version


def _version_candidates(version: str) -> set[str]:
    raw = str(version or "").strip().lower()
    if not raw:
        return set()

    candidates = {raw}
    if raw.startswith("v") and len(raw) > 1:
        candidates.add(raw[1:])
    if "-" in raw:
        candidates.add(raw.split("-", 1)[0])
    return {candidate for candidate in candidates if candidate}


def _extract_cvss(metrics: Any) -> float:
    if not isinstance(metrics, dict):
        return 0.0

    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(metric_key)
        if not isinstance(rows, list):
            continue

        best = 0.0
        for row in rows:
            if not isinstance(row, dict):
                continue
            cvss_data = row.get("cvssData", {})
            if not isinstance(cvss_data, dict):
                continue
            try:
                score = float(cvss_data.get("baseScore", 0.0))
            except (TypeError, ValueError):
                continue
            if score > best:
                best = score

        if best > 0:
            return best

    return 0.0
