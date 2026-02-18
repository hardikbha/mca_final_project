from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.models.enums import DocumentType


class DocumentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    document_id: UUID
    user_id: UUID
    document_type: DocumentType
    document_number: str | None
    file_path: str
    upload_timestamp: datetime
    is_verified: bool
    ocr_extracted_data: dict | None


class DocumentUploadResponse(BaseModel):
    message: str
    document: DocumentResponse


class DocumentProcessResponse(BaseModel):
    message: str
    document: DocumentResponse
