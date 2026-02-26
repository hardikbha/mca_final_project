"""Admin endpoint for viewing audit logs from MongoDB."""

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query, Request

from app.core.config import settings
from app.deps import get_current_reviewer_or_admin
from app.models.user import User

router = APIRouter(prefix="/api/v1/admin/audit-logs", tags=["audit"])


@router.get("", response_model=list[dict[str, Any]])
async def list_audit_logs(
    request: Request,
    user_id: str | None = Query(default=None),
    action: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    _: User = Depends(get_current_reviewer_or_admin),
) -> list[dict[str, Any]]:
    """Query audit logs from MongoDB with optional filters."""
    state = request.app.state.connections
    if state.mongo_client is None:
        return []

    db = state.mongo_client[settings.mongodb_db]
    collection = db["audit_logs"]

    query: dict[str, Any] = {}
    if user_id:
        query["user_id"] = user_id
    if action:
        query["action"] = action

    cursor = collection.find(query).sort("timestamp", -1).limit(limit)
    results = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        if isinstance(doc.get("timestamp"), datetime):
            doc["timestamp"] = doc["timestamp"].isoformat()
        results.append(doc)
    return results
