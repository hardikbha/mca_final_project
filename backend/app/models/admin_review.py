import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Enum, ForeignKey, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.enums import ReviewDecision


class AdminReview(Base):
    __tablename__ = "admin_reviews"
    __table_args__ = (
        CheckConstraint(
            "review_decision != 'rejected' OR rejection_reason IS NOT NULL",
            name="ck_rejected_requires_reason",
        ),
    )

    review_id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("verification_sessions.session_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    admin_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.user_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    review_decision: Mapped[ReviewDecision] = mapped_column(
        Enum(ReviewDecision, name="review_decision_enum"), nullable=False
    )
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    review_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    session = relationship("VerificationSession", back_populates="admin_review")
