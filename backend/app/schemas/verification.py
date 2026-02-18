from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.models.enums import AuthenticityLabel, VerificationStatus


class VerificationSessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    session_id: UUID
    user_id: UUID
    selfie_image_path: str
    video_path: str | None
    match_score: float | None
    liveness_score: float | None
    deepfake_probability: float | None
    authenticity_label: AuthenticityLabel | None
    quality_checks: dict | None
    timestamp: datetime
    status: VerificationStatus
    admin_reviewed: bool


class VerificationCreateResponse(BaseModel):
    message: str
    session: VerificationSessionResponse
