"""Redis caching service — get/set/delete with TTL."""

import json
import logging
from typing import Any

from fastapi import Request

logger = logging.getLogger(__name__)


def _get_redis(request: Request):
    try:
        return request.app.state.connections.redis_client
    except Exception:
        return None


async def cache_get(request: Request, key: str) -> Any | None:
    """Return cached value or None."""
    redis = _get_redis(request)
    if redis is None:
        return None
    try:
        raw = await redis.get(key)
        if raw is None:
            return None
        return json.loads(raw)
    except Exception as exc:
        logger.debug("cache_get(%s) failed: %s", key, exc)
        return None


async def cache_set(request: Request, key: str, value: Any, ttl: int = 300) -> None:
    """Store value with TTL (seconds)."""
    redis = _get_redis(request)
    if redis is None:
        return
    try:
        await redis.set(key, json.dumps(value, default=str), ex=ttl)
    except Exception as exc:
        logger.debug("cache_set(%s) failed: %s", key, exc)


async def cache_delete(request: Request, key: str) -> None:
    """Invalidate a cache entry."""
    redis = _get_redis(request)
    if redis is None:
        return
    try:
        await redis.delete(key)
    except Exception as exc:
        logger.debug("cache_delete(%s) failed: %s", key, exc)
