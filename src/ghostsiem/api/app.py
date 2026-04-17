"""FastAPI application factory for GhostSIEM."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ghostsiem.api.routes import router, set_store
from ghostsiem.storage.store import EventStore


def create_app(
    db_path: str = "ghostsiem.db",
    **kwargs: Any,
) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        db_path: Path to the SQLite database.

    Returns:
        Configured FastAPI application instance.
    """
    store = EventStore(db_path=db_path)

    @asynccontextmanager
    async def lifespan(app: FastAPI):  # noqa: ANN202
        await store.initialize()
        set_store(store)
        yield
        await store.close()

    app = FastAPI(
        title="GhostSIEM API",
        description="REST API for querying security events and alerts",
        version="0.1.0",
        lifespan=lifespan,
    )

    # CORS middleware for dashboard integration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(router, prefix="/api/v1")

    return app
