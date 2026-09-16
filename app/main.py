import os
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from app.api import routes_events, routes_ingestion, routes_parsers, routes_stats
from app.db.database import connect
from app.services.event_store import EventStore
from app.services.processing_service import ProcessingService


@asynccontextmanager
async def lifespan(app: FastAPI):
    connection = connect(os.environ.get("ULPF_DB_PATH") or None) if os.environ.get("ULPF_DB_PATH") else connect()
    app.state.store = EventStore(connection)
    app.state.processor = ProcessingService(app.state.store)
    yield
    connection.close()


app = FastAPI(title="ULPF", version="1.0.0", lifespan=lifespan)
origins = [origin.strip() for origin in os.environ.get("ULPF_CORS_ORIGINS", "").split(",") if origin.strip()]
if origins:
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST"], allow_headers=["Content-Type"])
for router in (routes_events.router, routes_ingestion.router, routes_parsers.router, routes_stats.router):
    app.include_router(router)

frontend_dist = Path(__file__).resolve().parents[1] / "frontend" / "dist"
if (frontend_dist / "index.html").is_file():
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")
else:
    @app.get("/")
    def root():
        return {"service": "ULPF", "phase": 1, "docs": "/docs", "api": "/api/v1",
                "frontend": "Build frontend with npm run build --prefix frontend"}
