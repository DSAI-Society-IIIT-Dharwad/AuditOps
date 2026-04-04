from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class GraphAnalysisResponse(BaseModel):
    schema_version: str
    generated_at: str
    context: dict[str, Any]
    summary: dict[str, Any]
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    analysis: dict[str, Any]
    temporal: dict[str, Any] = Field(default_factory=dict)
    report: dict[str, Any] = Field(default_factory=dict)
