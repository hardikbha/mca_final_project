"""Initial schema for foundation modules

Revision ID: 20260218_0001
Revises:
Create Date: 2026-02-18 00:00:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "20260218_0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("user_id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("phone", sa.String(length=15), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("is_verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "kyc_status",
            sa.Enum("pending", "approved", "rejected", "under_review", name="kyc_status_enum"),
            nullable=False,
            server_default="pending",
        ),
        sa.Column(
            "role",
            sa.Enum("user", "admin", "reviewer", name="role_enum"),
            nullable=False,
            server_default="user",
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("email", name="uq_users_email"),
        sa.UniqueConstraint("phone", name="uq_users_phone"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=False)
    op.create_index("ix_users_phone", "users", ["phone"], unique=False)

    op.create_table(
        "documents",
        sa.Column("document_id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column(
            "document_type",
            sa.Enum(
                "aadhaar",
                "pan",
                "passport",
                "driving_license",
                "voter_id",
                "bank_statement",
                "utility_bill",
                name="document_type_enum",
            ),
            nullable=False,
        ),
        sa.Column("document_number", sa.String(length=50), nullable=True),
        sa.Column("file_path", sa.String(length=500), nullable=False),
        sa.Column("ocr_extracted_data", sa.JSON(), nullable=True),
        sa.Column("upload_timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("is_verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.ForeignKeyConstraint(["user_id"], ["users.user_id"], ondelete="CASCADE"),
    )
    op.create_index("ix_documents_user_id", "documents", ["user_id"], unique=False)

    op.create_table(
        "verification_sessions",
        sa.Column("session_id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("selfie_image_path", sa.String(length=500), nullable=False),
        sa.Column("video_path", sa.String(length=500), nullable=True),
        sa.Column("id_face_embedding", sa.JSON(), nullable=True),
        sa.Column("selfie_face_embedding", sa.JSON(), nullable=True),
        sa.Column("match_score", sa.Float(), nullable=True),
        sa.Column("liveness_score", sa.Float(), nullable=True),
        sa.Column("deepfake_probability", sa.Float(), nullable=True),
        sa.Column(
            "authenticity_label",
            sa.Enum("real", "fake", name="authenticity_label_enum"),
            nullable=True,
        ),
        sa.Column("quality_checks", sa.JSON(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column(
            "status",
            sa.Enum("pending", "approved", "rejected", "flagged", name="verification_status_enum"),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("admin_reviewed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.CheckConstraint("match_score BETWEEN 0 AND 100", name="ck_match_score_range"),
        sa.CheckConstraint("liveness_score BETWEEN 0 AND 100", name="ck_liveness_score_range"),
        sa.CheckConstraint("deepfake_probability BETWEEN 0 AND 100", name="ck_deepfake_prob_range"),
        sa.ForeignKeyConstraint(["user_id"], ["users.user_id"], ondelete="CASCADE"),
    )
    op.create_index("ix_verification_sessions_user_id", "verification_sessions", ["user_id"], unique=False)

    op.create_table(
        "admin_reviews",
        sa.Column("review_id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("session_id", sa.Uuid(), nullable=False),
        sa.Column("admin_id", sa.Uuid(), nullable=True),
        sa.Column(
            "review_decision",
            sa.Enum("approved", "rejected", "request_reupload", name="review_decision_enum"),
            nullable=False,
        ),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column("review_timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "review_decision != 'rejected' OR rejection_reason IS NOT NULL",
            name="ck_rejected_requires_reason",
        ),
        sa.ForeignKeyConstraint(["session_id"], ["verification_sessions.session_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["admin_id"], ["users.user_id"], ondelete="SET NULL"),
    )
    op.create_index("ix_admin_reviews_admin_id", "admin_reviews", ["admin_id"], unique=False)
    op.create_index("ix_admin_reviews_session_id", "admin_reviews", ["session_id"], unique=False)

    op.create_table(
        "audit_logs",
        sa.Column("log_id", sa.Uuid(), primary_key=True, nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("additional_data", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.user_id"], ondelete="SET NULL"),
    )
    op.create_index("idx_audit_timestamp", "audit_logs", ["timestamp"], unique=False)
    op.create_index("idx_audit_user", "audit_logs", ["user_id"], unique=False)
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_audit_logs_user_id", table_name="audit_logs")
    op.drop_index("idx_audit_user", table_name="audit_logs")
    op.drop_index("idx_audit_timestamp", table_name="audit_logs")
    op.drop_table("audit_logs")

    op.drop_index("ix_admin_reviews_session_id", table_name="admin_reviews")
    op.drop_index("ix_admin_reviews_admin_id", table_name="admin_reviews")
    op.drop_table("admin_reviews")

    op.drop_index("ix_verification_sessions_user_id", table_name="verification_sessions")
    op.drop_table("verification_sessions")

    op.drop_index("ix_documents_user_id", table_name="documents")
    op.drop_table("documents")

    op.drop_index("ix_users_phone", table_name="users")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")

    op.execute("DROP TYPE IF EXISTS review_decision_enum")
    op.execute("DROP TYPE IF EXISTS verification_status_enum")
    op.execute("DROP TYPE IF EXISTS authenticity_label_enum")
    op.execute("DROP TYPE IF EXISTS document_type_enum")
    op.execute("DROP TYPE IF EXISTS role_enum")
    op.execute("DROP TYPE IF EXISTS kyc_status_enum")
