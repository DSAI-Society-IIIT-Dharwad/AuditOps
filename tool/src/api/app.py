from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes.graph_analysis import router as graph_analysis_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="Hack2Future Graph Analysis API",
        version="0.1.0",
        description="Phase 6 API bridge for graph and risk dashboard pages.",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://localhost:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(graph_analysis_router, prefix="/api/v1")
    return app


app = create_app()
