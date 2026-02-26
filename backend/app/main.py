import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.routes.admin_review import router as admin_review_router
from app.api.routes.analytics import router as analytics_router
from app.api.routes.audit import router as audit_router
from app.api.routes.auth import router as auth_router
from app.api.routes.documents import router as documents_router
from app.api.routes.features import router as features_router
from app.api.routes.system import router as system_router
from app.api.routes.verification import router as verification_router
from app.core.config import settings
from app.core.rate_limiter import limiter
from app.db.session import engine, init_db_schema
from app.services.connections import close_connections, init_connections

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_connections(app)
    if settings.auto_create_schema:
        await init_db_schema()
    yield
    await close_connections(app)
    await engine.dispose()


app = FastAPI(
    title="eKYC Core API",
    version="0.1.0",
    lifespan=lifespan,
)

# Rate limiter
limiter.storage_uri = settings.redis_url
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def performance_timing_middleware(request: Request, call_next) -> Response:
    start = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - start) * 1000
    response.headers["X-Process-Time"] = f"{elapsed_ms:.1f}ms"
    if elapsed_ms > 1000:
        logger.warning("Slow request: %s %s took %.0fms", request.method, request.url.path, elapsed_ms)
    return response


app.include_router(system_router)
app.include_router(auth_router)
app.include_router(features_router)
app.include_router(documents_router)
app.include_router(verification_router)
app.include_router(admin_review_router)
app.include_router(analytics_router)
app.include_router(audit_router)
