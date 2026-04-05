from __future__ import annotations

from typing import Literal
from typing import Any

from pydantic import BaseModel, Field


class GraphAnalysisIngestRequest(BaseModel):
    content: str = Field(min_length=1)
    format: Literal["auto", "json", "yaml"] = "auto"
    namespace: str | None = None
    include_cluster_rbac: bool = True
    enable_nvd_scoring: bool = False
    max_hops: int = Field(default=3, ge=0, le=10)
    max_depth: int = Field(default=8, ge=1, le=20)


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


class SnapshotListItem(BaseModel):
    scope_id: str
    snapshot_timestamp: str
    namespace: str
    include_cluster_rbac: bool
    ingestor: str
    enable_nvd_scoring: bool
    source: str
    node_count: int
    edge_count: int
    file_name: str
    rolled_back_from: str | None = None


class SnapshotListResponse(BaseModel):
    items: list[SnapshotListItem] = Field(default_factory=list)


class SnapshotDetailResponse(BaseModel):
    scope_id: str
    snapshot_timestamp: str
    payload: dict[str, Any]


class SnapshotRollbackRequest(BaseModel):
    reason: str | None = None


class SnapshotRollbackResponse(BaseModel):
    scope_id: str
    rolled_back_from: str
    snapshot_timestamp: str
    file_path: str
