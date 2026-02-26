"""Audit logging service — writes to MongoDB audit_logs collection."""

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastapi import Request

logger = logging.getLogger(__name__)


async def log_audit_event(
    request: Request,
    action: str,
    user_id: UUID | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Write an audit event to MongoDB. Fails silently if MongoDB is unavailable."""
    try:
        state = request.app.state.connections
        if state.mongo_client is None:
            return
        from app.core.config import settings

        db = state.mongo_client[settings.mongodb_db]
        collection = db["audit_logs"]
        doc = {
            "user_id": str(user_id) if user_id else None,
            "action": action,
            "ip_address": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
            "timestamp": datetime.now(timezone.utc),
            "details": details or {},
        }
        await collection.insert_one(doc)
    except Exception as exc:
        logger.warning("Audit log write failed: %s", exc)
