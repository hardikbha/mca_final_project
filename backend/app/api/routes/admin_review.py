from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db_session
from app.deps import get_current_reviewer_or_admin
from app.models.admin_review import AdminReview
from app.models.enums import KYCStatus, ReviewDecision, VerificationStatus
from app.models.user import User
from app.models.verification_session import VerificationSession
from app.schemas.admin_review import (
    AdminDecisionResponse,
    AdminQueueUserResponse,
    AdminReviewQueueItemResponse,
    AdminReviewResponse,
    ReviewDecisionRequest,
)
from app.schemas.verification import VerificationSessionResponse
from app.services.audit_service import log_audit_event

router = APIRouter(prefix="/api/v1/admin/reviews", tags=["admin-review"])


@router.get("/queue", response_model=list[AdminReviewQueueItemResponse])
async def list_flagged_sessions_for_review(
    include_reviewed: bool = Query(default=False),
    db: AsyncSession = Depends(get_db_session),
    _: User = Depends(get_current_reviewer_or_admin),
) -> list[AdminReviewQueueItemResponse]:
    query = (
        select(VerificationSession, User)
        .join(User, User.user_id == VerificationSession.user_id)
        .where(VerificationSession.status == VerificationStatus.flagged)
    )
    if not include_reviewed:
        query = query.where(VerificationSession.admin_reviewed.is_(False))
    query = query.order_by(VerificationSession.timestamp.asc())

    rows = await db.execute(query)
    items: list[AdminReviewQueueItemResponse] = []
    for session, user in rows.all():
        items.append(
            AdminReviewQueueItemResponse(
                session=VerificationSessionResponse.model_validate(session),
                user=AdminQueueUserResponse.model_validate(user),
            )
        )
    return items


@router.post("/{session_id}/decision", response_model=AdminDecisionResponse)
async def decide_flagged_session(
    session_id: UUID,
    payload: ReviewDecisionRequest,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_reviewer_or_admin),
) -> AdminDecisionResponse:
    session = await db.get(VerificationSession, session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Verification session not found",
        )

    if session.status != VerificationStatus.flagged:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Only flagged sessions can be reviewed",
        )

    existing_review = await db.scalar(
        select(AdminReview).where(AdminReview.session_id == session.session_id)
    )
    if existing_review is not None or session.admin_reviewed:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Session is already reviewed",
        )

    target_user = await db.get(User, session.user_id)
    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session owner not found",
        )

    if payload.review_decision == ReviewDecision.approved:
        session.status = VerificationStatus.approved
        target_user.kyc_status = KYCStatus.approved
        target_user.is_verified = True
        message = "Session approved and user KYC marked approved"
    elif payload.review_decision == ReviewDecision.rejected:
        session.status = VerificationStatus.rejected
        target_user.kyc_status = KYCStatus.rejected
        target_user.is_verified = False
        message = "Session rejected and user KYC marked rejected"
    else:
        session.status = VerificationStatus.flagged
        target_user.kyc_status = KYCStatus.under_review
        target_user.is_verified = False
        message = "Re-upload requested and user KYC marked under_review"

    session.admin_reviewed = True

    review = AdminReview(
        session_id=session.session_id,
        admin_id=current_user.user_id,
        review_decision=payload.review_decision,
        rejection_reason=payload.rejection_reason,
    )
    db.add(review)

    await db.commit()
    await db.refresh(session)
    await db.refresh(review)
    await db.refresh(target_user)

    await log_audit_event(
        request, "admin_review",
        user_id=current_user.user_id,
        details={"session_id": str(session_id), "decision": payload.review_decision.value},
    )

    return AdminDecisionResponse(
        message=message,
        session=VerificationSessionResponse.model_validate(session),
        review=AdminReviewResponse.model_validate(review),
        user=AdminQueueUserResponse.model_validate(target_user),
    )
