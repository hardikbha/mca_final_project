from pathlib import Path
from uuid import UUID
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import get_db_session
from app.deps import get_current_user
from app.models.document import Document
from app.models.user import User
from app.models.verification_session import VerificationSession
from app.schemas.verification import VerificationCreateResponse, VerificationSessionResponse
from app.services.verification_scoring import run_placeholder_verification

router = APIRouter(prefix="/api/v1/verification-sessions", tags=["verification"])

ALLOWED_SELFIE_MIME_TYPES = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
}
ALLOWED_VIDEO_MIME_TYPES = {
    "video/mp4": ".mp4",
    "video/quicktime": ".mov",
    "video/x-msvideo": ".avi",
}


def _validate_selfie(file: UploadFile, size: int) -> str:
    if size <= 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Selfie file is empty")
    if size > settings.max_upload_size_mb * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Selfie file exceeds {settings.max_upload_size_mb}MB limit",
        )
    if file.content_type not in ALLOWED_SELFIE_MIME_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only JPG/JPEG/PNG are allowed for selfie",
        )

    original_name = (file.filename or "").lower()
    expected_suffix = ALLOWED_SELFIE_MIME_TYPES[file.content_type]
    if not original_name.endswith(expected_suffix) and not (
        expected_suffix == ".jpg" and original_name.endswith(".jpeg")
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Selfie extension does not match MIME type {file.content_type}",
        )
    if expected_suffix == ".jpg" and original_name.endswith(".jpeg"):
        return ".jpeg"
    return expected_suffix


def _validate_video(file: UploadFile, size: int) -> str:
    if size <= 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Video file is empty")
    if size > settings.max_video_size_mb * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Video file exceeds {settings.max_video_size_mb}MB limit",
        )
    if file.content_type not in ALLOWED_VIDEO_MIME_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only MP4/MOV/AVI are allowed for liveness video",
        )

    original_name = (file.filename or "").lower()
    expected_suffix = ALLOWED_VIDEO_MIME_TYPES[file.content_type]
    if not original_name.endswith(expected_suffix):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Video extension does not match MIME type {file.content_type}",
        )
    return expected_suffix


async def _find_reference_document(
    db: AsyncSession,
    user_id: UUID,
    reference_document_id: UUID | None,
) -> Document | None:
    if reference_document_id is None:
        return None
    document = await db.scalar(
        select(Document).where(
            Document.document_id == reference_document_id,
            Document.user_id == user_id,
        )
    )
    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Reference document not found",
        )
    return document


@router.post("/upload", response_model=VerificationCreateResponse)
async def upload_verification_session(
    selfie_file: UploadFile = File(...),
    video_file: UploadFile | None = File(default=None),
    reference_document_id: UUID | None = Form(default=None),
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
) -> VerificationCreateResponse:
    selfie_content = await selfie_file.read()
    selfie_suffix = _validate_selfie(selfie_file, len(selfie_content))

    video_content: bytes | None = None
    video_suffix: str | None = None
    if video_file is not None:
        video_content = await video_file.read()
        video_suffix = _validate_video(video_file, len(video_content))

    reference_document = await _find_reference_document(db, current_user.user_id, reference_document_id)
    score_result = run_placeholder_verification(
        selfie_bytes=selfie_content,
        video_bytes=video_content,
        reference_document=reference_document,
    )

    user_dir = Path(settings.upload_root) / "verification" / str(current_user.user_id)
    user_dir.mkdir(parents=True, exist_ok=True)

    selfie_stored_path = user_dir / f"selfie_{uuid4()}{selfie_suffix}"
    selfie_stored_path.write_bytes(selfie_content)

    video_stored_path: Path | None = None
    if video_content is not None and video_suffix is not None:
        video_stored_path = user_dir / f"video_{uuid4()}{video_suffix}"
        video_stored_path.write_bytes(video_content)

    session = VerificationSession(
        user_id=current_user.user_id,
        selfie_image_path=str(selfie_stored_path),
        video_path=str(video_stored_path) if video_stored_path else None,
        id_face_embedding={
            "source": "document_placeholder" if reference_document else "none",
            "reference_document_id": str(reference_document.document_id) if reference_document else None,
        },
        selfie_face_embedding={
            "source": "selfie_placeholder",
            "hash_preview": uuid4().hex[:16],
        },
        match_score=score_result["match_score"],
        liveness_score=score_result["liveness_score"],
        deepfake_probability=score_result["deepfake_probability"],
        authenticity_label=score_result["authenticity_label"],
        quality_checks=score_result["quality_checks"],
        status=score_result["status"],
        admin_reviewed=False,
    )
    db.add(session)
    await db.commit()
    await db.refresh(session)

    return VerificationCreateResponse(
        message="Verification session created",
        session=VerificationSessionResponse.model_validate(session),
    )


@router.get("/my", response_model=list[VerificationSessionResponse])
async def list_my_verification_sessions(
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
) -> list[VerificationSessionResponse]:
    rows = await db.scalars(
        select(VerificationSession)
        .where(VerificationSession.user_id == current_user.user_id)
        .order_by(VerificationSession.timestamp.desc())
    )
    return [VerificationSessionResponse.model_validate(item) for item in rows.all()]


@router.get("/{session_id}", response_model=VerificationSessionResponse)
async def get_verification_session(
    session_id: UUID,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
) -> VerificationSessionResponse:
    session = await db.scalar(
        select(VerificationSession).where(
            VerificationSession.session_id == session_id,
            VerificationSession.user_id == current_user.user_id,
        )
    )
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Verification session not found",
        )
    return VerificationSessionResponse.model_validate(session)
