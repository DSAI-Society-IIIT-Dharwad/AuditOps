from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from api.schemas.graph_analysis import GraphAnalysisResponse
from ingestion.kubectl_runner import KubectlIngestError
from services.analysis.graph_analysis_service import get_graph_analysis

router = APIRouter(tags=["graph-analysis"])


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
