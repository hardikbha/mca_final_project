from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.admin_review import router as admin_review_router
from app.api.routes.auth import router as auth_router
from app.api.routes.documents import router as documents_router
from app.api.routes.features import router as features_router
from app.api.routes.system import router as system_router
from app.api.routes.verification import router as verification_router
from app.core.config import settings
from app.db.session import engine, init_db_schema
from app.services.connections import close_connections, init_connections


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

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(system_router)
app.include_router(auth_router)
app.include_router(features_router)
app.include_router(documents_router)
app.include_router(verification_router)
app.include_router(admin_review_router)
