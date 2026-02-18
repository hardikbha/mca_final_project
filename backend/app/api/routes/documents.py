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
from app.models.enums import DocumentType
from app.models.user import User
from app.schemas.document import DocumentProcessResponse, DocumentResponse, DocumentUploadResponse
from app.services.document_processing import run_document_processing

router = APIRouter(prefix="/api/v1/documents", tags=["documents"])

ALLOWED_MIME_TYPES = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "application/pdf": ".pdf",
}


def _validate_upload(file: UploadFile, size: int) -> str:
    if size <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty",
        )

    max_size_bytes = settings.max_upload_size_mb * 1024 * 1024
    if size > max_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File size exceeds {settings.max_upload_size_mb}MB limit",
        )

    if file.content_type not in ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only JPEG, PNG, and PDF files are allowed",
        )

    original_name = (file.filename or "").lower()
    expected_suffix = ALLOWED_MIME_TYPES[file.content_type]
    if not original_name.endswith(expected_suffix) and not (
        expected_suffix == ".jpg" and original_name.endswith(".jpeg")
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File extension does not match MIME type {file.content_type}",
        )

    if expected_suffix == ".jpg" and original_name.endswith(".jpeg"):
        return ".jpeg"
    return expected_suffix


@router.post("/upload", response_model=DocumentUploadResponse)
async def upload_document(
    document_type: DocumentType = Form(...),
    document_number: str | None = Form(default=None),
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
) -> DocumentUploadResponse:
    content = await file.read()
    suffix = _validate_upload(file, len(content))

    user_dir = Path(settings.upload_root) / str(current_user.user_id)
    user_dir.mkdir(parents=True, exist_ok=True)
    stored_name = f"{uuid4()}{suffix}"
    stored_path = user_dir / stored_name
    stored_path.write_bytes(content)

    document = Document(
        user_id=current_user.user_id,
        document_type=document_type,
        document_number=document_number.strip() if document_number else None,
        file_path=str(stored_path),
        is_verified=False,
    )
    db.add(document)
    await db.commit()
    await db.refresh(document)

    return DocumentUploadResponse(
        message="Document uploaded successfully",
        document=DocumentResponse.model_validate(document),
    )


async def _get_user_document(
    db: AsyncSession, document_id: UUID, current_user: User
) -> Document:
    document = await db.scalar(
        select(Document).where(
            Document.document_id == document_id, Document.user_id == current_user.user_id
        )
    )
    if document is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
    return document


@router.get("/my", response_model=list[DocumentResponse])
async def list_my_documents(
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
) -> list[DocumentResponse]:
    rows = await db.scalars(
        select(Document)
        .where(Document.user_id == current_user.user_id)
        .order_by(Document.upload_timestamp.desc())
    )
    return [DocumentResponse.model_validate(item) for item in rows.all()]


@router.get("/{document_id}", response_model=DocumentResponse)
async def get_document_details(
    document_id: UUID,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
) -> DocumentResponse:
    document = await _get_user_document(db, document_id, current_user)
    return DocumentResponse.model_validate(document)


@router.post("/{document_id}/process", response_model=DocumentProcessResponse)
async def process_document(
    document_id: UUID,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
) -> DocumentProcessResponse:
    document = await _get_user_document(db, document_id, current_user)
    file_path = Path(document.file_path)
    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document file missing in storage",
        )

    document.ocr_extracted_data = run_document_processing(document)
    await db.commit()
    await db.refresh(document)

    return DocumentProcessResponse(
        message="OCR and validation completed",
        document=DocumentResponse.model_validate(document),
    )
