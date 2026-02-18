from datetime import datetime, timezone

from fastapi import APIRouter, Request

from app.services.connections import get_system_status

router = APIRouter(tags=["system"])


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/api/v1/system/status")
async def system_status(request: Request) -> dict[str, object]:
    status = await get_system_status(request.app)
    return {
        **status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
