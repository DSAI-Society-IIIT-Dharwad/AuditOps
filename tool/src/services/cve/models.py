from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class CVEQueryResult:
    """Container image CVE lookup result used for Pod risk enrichment."""

    image_ref: str
    cpe_name: str | None = None
    cve_ids: tuple[str, ...] = ()
    max_cvss: float = 0.0
    error: str | None = None
