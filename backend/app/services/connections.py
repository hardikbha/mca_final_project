from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI
from motor.motor_asyncio import AsyncIOMotorClient
from redis.asyncio import Redis
from sqlalchemy import text

from app.core.config import settings
from app.db.session import engine


@dataclass
class ConnectionState:
    mongo_client: AsyncIOMotorClient | None = None
    redis_client: Redis | None = None


def get_state(app: FastAPI) -> ConnectionState:
    return app.state.connections


async def init_connections(app: FastAPI) -> None:
    state = ConnectionState()
    state.mongo_client = AsyncIOMotorClient(settings.mongodb_uri)
    state.redis_client = Redis.from_url(settings.redis_url, encoding="utf-8", decode_responses=True)
    app.state.connections = state


async def close_connections(app: FastAPI) -> None:
    state = get_state(app)
    if state.mongo_client is not None:
        state.mongo_client.close()
    if state.redis_client is not None:
        await state.redis_client.aclose()


async def postgres_status(state: ConnectionState) -> dict[str, str]:
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        return {"status": "ok", "detail": "connected"}
    except Exception as exc:  # pragma: no cover - runtime connectivity
        return {"status": "error", "detail": str(exc)}


async def mongodb_status(state: ConnectionState) -> dict[str, str]:
    if state.mongo_client is None:
        return {"status": "error", "detail": "mongodb client not initialized"}
    try:
        await state.mongo_client[settings.mongodb_db].command("ping")
        return {"status": "ok", "detail": "connected"}
    except Exception as exc:  # pragma: no cover - runtime connectivity
        return {"status": "error", "detail": str(exc)}


async def redis_status(state: ConnectionState) -> dict[str, str]:
    if state.redis_client is None:
        return {"status": "error", "detail": "redis client not initialized"}
    try:
        await state.redis_client.ping()
        return {"status": "ok", "detail": "connected"}
    except Exception as exc:  # pragma: no cover - runtime connectivity
        return {"status": "error", "detail": str(exc)}


async def get_system_status(app: FastAPI) -> dict[str, Any]:
    state = get_state(app)
    postgres = await postgres_status(state)
    mongodb = await mongodb_status(state)
    redis = await redis_status(state)
    return {
        "api": "ok",
        "services": {
            "postgresql": postgres,
            "mongodb": mongodb,
            "redis": redis,
        },
    }
