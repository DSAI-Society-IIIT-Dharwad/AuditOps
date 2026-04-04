from __future__ import annotations

import json
from collections.abc import Mapping

from fastapi import APIRouter, HTTPException, Query
import yaml

from api.schemas.graph_analysis import GraphAnalysisIngestRequest, GraphAnalysisResponse
from ingestion.kubectl_runner import KubectlIngestError
from ingestion.mock_parser import MockParserError
from services.analysis.graph_analysis_service import get_graph_analysis, get_graph_analysis_from_payload

router = APIRouter(tags=["graph-analysis"])

_KIND_TO_RESOURCE = {
    "Pod": "pods",
    "ServiceAccount": "serviceaccounts",
    "Role": "roles",
    "RoleBinding": "rolebindings",
    "ClusterRoleBinding": "clusterrolebindings",
    "Secret": "secrets",
    "ConfigMap": "configmaps",
}


@router.get("/graph-analysis", response_model=GraphAnalysisResponse)
def graph_analysis(
    namespace: str | None = Query(default=None),
    include_cluster_rbac: bool = Query(default=True),
    enable_nvd_scoring: bool = Query(default=False),
    max_hops: int = Query(default=3, ge=0, le=10),
    max_depth: int = Query(default=8, ge=1, le=20),
) -> GraphAnalysisResponse:
    try:
        payload = get_graph_analysis(
            namespace=namespace,
            include_cluster_rbac=include_cluster_rbac,
            enable_nvd_scoring=enable_nvd_scoring,
            max_hops=max_hops,
            max_depth=max_depth,
        )
    except KubectlIngestError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail="Unexpected analysis error") from exc

    return GraphAnalysisResponse.model_validate(payload)


@router.post("/graph-analysis/ingest", response_model=GraphAnalysisResponse)
def graph_analysis_ingest(request: GraphAnalysisIngestRequest) -> GraphAnalysisResponse:
    try:
        parsed_payload = _parse_content_payload(request.content, request.format)
        payload = get_graph_analysis_from_payload(
            graph_payload=parsed_payload,
            namespace=request.namespace,
            include_cluster_rbac=request.include_cluster_rbac,
            enable_nvd_scoring=request.enable_nvd_scoring,
            max_hops=request.max_hops,
            max_depth=request.max_depth,
        )
    except MockParserError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail="Unexpected analysis error") from exc

    return GraphAnalysisResponse.model_validate(payload)


def _parse_content_payload(content: str, content_format: str) -> dict[str, object]:
    text = content.strip()
    if not text:
        raise ValueError("content cannot be empty")

    requested = content_format.strip().lower()
    if requested not in {"auto", "json", "yaml"}:
        raise ValueError("format must be one of: auto, json, yaml")

    if requested in {"auto", "json"}:
        try:
            parsed_json = json.loads(text)
        except json.JSONDecodeError:
            parsed_json = None
        if isinstance(parsed_json, dict):
            return parsed_json
        if requested == "json":
            raise ValueError("Invalid JSON payload. Expected a top-level object.")

    yaml_payload = _parse_yaml_payload(text)
    if yaml_payload:
        return yaml_payload

    raise ValueError("Unable to parse content as YAML/JSON graph input.")


def _parse_yaml_payload(content: str) -> dict[str, object]:
    documents = [doc for doc in yaml.safe_load_all(content) if doc is not None]
    if not documents:
        raise ValueError("YAML payload is empty")

    if len(documents) == 1 and isinstance(documents[0], Mapping):
        first = dict(documents[0])
        if "nodes" in first and "edges" in first:
            return first
        if any(key in first for key in _KIND_TO_RESOURCE.values()):
            return first

    resources: dict[str, list[dict[str, object]]] = {resource: [] for resource in _KIND_TO_RESOURCE.values()}
    for doc in documents:
        _collect_manifest_resource_items(doc, resources)

    total_items = sum(len(items) for items in resources.values())
    if total_items == 0:
        raise ValueError("YAML payload did not include supported Kubernetes resources.")

    return {resource: {"items": items} for resource, items in resources.items()}


def _collect_manifest_resource_items(
    doc: object,
    resources: dict[str, list[dict[str, object]]],
) -> None:
    if not isinstance(doc, Mapping):
        return

    kind = str(doc.get("kind") or "").strip()
    if kind == "List":
        items = doc.get("items")
        if isinstance(items, list):
            for item in items:
                _collect_manifest_resource_items(item, resources)
        return

    resource = _KIND_TO_RESOURCE.get(kind)
    if not resource:
        return
    resources[resource].append(dict(doc))
