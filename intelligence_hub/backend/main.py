from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
from contextlib import asynccontextmanager
import asyncio
from websocket.feed import redis_listener

from config import settings
from database.elastic import init_elasticsearch
from database.postgres import init_postgres
from database.neo4j import init_neo4j
from ingest.receiver import router as ingest_router
from api.events import router as events_router
from api.iocs import router as iocs_router
from api.sessions import router as sessions_router
from api.alerts import router as alerts_router
from websocket.feed import router as ws_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_elasticsearch()
    await init_postgres()
    await init_neo4j()
    # start Redis → WebSocket broadcaster
    asyncio.create_task(redis_listener())
    yield

app = FastAPI(
    title="GenAI Honeypot — Intelligence Hub",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.cors_origin],
    allow_methods=["*"],
    allow_headers=["*"],
)

Instrumentator().instrument(app).expose(app)

app.include_router(ingest_router,   prefix="/ingest",   tags=["ingest"])
app.include_router(events_router,   prefix="/events",   tags=["events"])
app.include_router(iocs_router,     prefix="/iocs",     tags=["iocs"])
app.include_router(sessions_router, prefix="/sessions", tags=["sessions"])
app.include_router(alerts_router,   prefix="/alerts",   tags=["alerts"])
app.include_router(ws_router,                           tags=["websocket"])


@app.get("/health")
async def health():
    return {"status": "ok", "service": "intelligence-hub"}