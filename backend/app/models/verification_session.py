import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    JSON,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.enums import AuthenticityLabel, VerificationStatus


class VerificationSession(Base):
    __tablename__ = "verification_sessions"
    __table_args__ = (
        CheckConstraint("match_score BETWEEN 0 AND 100", name="ck_match_score_range"),
        CheckConstraint("liveness_score BETWEEN 0 AND 100", name="ck_liveness_score_range"),
        CheckConstraint("deepfake_probability BETWEEN 0 AND 100", name="ck_deepfake_prob_range"),
    )

    session_id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False, index=True
    )
    selfie_image_path: Mapped[str] = mapped_column(String(500), nullable=False)
    video_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    id_face_embedding: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    selfie_face_embedding: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    match_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    liveness_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    deepfake_probability: Mapped[float | None] = mapped_column(Float, nullable=True)
    authenticity_label: Mapped[AuthenticityLabel | None] = mapped_column(
        Enum(AuthenticityLabel, name="authenticity_label_enum"),
        nullable=True,
    )
    quality_checks: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    status: Mapped[VerificationStatus] = mapped_column(
        Enum(VerificationStatus, name="verification_status_enum"),
        nullable=False,
        default=VerificationStatus.pending,
        server_default=VerificationStatus.pending.value,
    )
    admin_reviewed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    user = relationship("User", back_populates="sessions")
    admin_review = relationship("AdminReview", back_populates="session", uselist=False)
