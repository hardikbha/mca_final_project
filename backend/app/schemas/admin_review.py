from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, model_validator

from app.models.enums import KYCStatus, ReviewDecision
from app.schemas.verification import VerificationSessionResponse


class AdminQueueUserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    user_id: UUID
    full_name: str
    email: str
    phone: str
    kyc_status: KYCStatus
    is_verified: bool


class AdminReviewResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    review_id: UUID
    session_id: UUID
    admin_id: UUID | None
    review_decision: ReviewDecision
    rejection_reason: str | None
    review_timestamp: datetime


class AdminReviewQueueItemResponse(BaseModel):
    session: VerificationSessionResponse
    user: AdminQueueUserResponse


class ReviewDecisionRequest(BaseModel):
    review_decision: ReviewDecision
    rejection_reason: str | None = None

    @model_validator(mode="after")
    def validate_rejection_reason(self) -> "ReviewDecisionRequest":
        reason = (self.rejection_reason or "").strip()
        if self.review_decision in {ReviewDecision.rejected, ReviewDecision.request_reupload}:
            if not reason:
                raise ValueError(
                    "rejection_reason is required for rejected/request_reupload decisions"
                )
            self.rejection_reason = reason
        elif reason:
            raise ValueError("rejection_reason must be empty when decision is approved")
        else:
            self.rejection_reason = None
        return self


class AdminDecisionResponse(BaseModel):
    message: str
    session: VerificationSessionResponse
    review: AdminReviewResponse
    user: AdminQueueUserResponse
