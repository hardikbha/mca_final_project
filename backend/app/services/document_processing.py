import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.models.document import Document
from app.models.enums import DocumentType

PAN_PATTERN = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
AADHAAR_PATTERN = re.compile(r"\b[0-9]{4}\s?[0-9]{4}\s?[0-9]{4}\b")
PASSPORT_PATTERN = re.compile(r"\b[A-PR-WY][1-9][0-9]{6}\b")
DL_PATTERN = re.compile(r"\b[A-Z]{2}[0-9]{2}\s?[0-9]{11}\b")
VOTER_ID_PATTERN = re.compile(r"\b[A-Z]{3}[0-9]{7}\b")
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_PATTERN = re.compile(r"\b[6-9][0-9]{9}\b")

VALIDATION_RULES: dict[DocumentType, re.Pattern[str]] = {
    DocumentType.pan: re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]$"),
    DocumentType.aadhaar: re.compile(r"^[0-9]{12}$"),
    DocumentType.passport: re.compile(r"^[A-PR-WY][1-9][0-9]{6}$"),
    DocumentType.driving_license: re.compile(r"^[A-Z]{2}[0-9]{2}[0-9]{11}$"),
    DocumentType.voter_id: re.compile(r"^[A-Z]{3}[0-9]{7}$"),
}


def _read_text_from_file(file_path: Path) -> tuple[str, str]:
    if file_path.suffix.lower() == ".pdf":
        try:
            from pypdf import PdfReader

            reader = PdfReader(str(file_path))
            pages = [page.extract_text() or "" for page in reader.pages]
            joined = "\n".join(pages).strip()
            if joined:
                return joined, "pypdf"
        except Exception:
            pass

    raw_bytes = file_path.read_bytes()
    decoded = raw_bytes.decode("utf-8", errors="ignore").strip()
    if decoded:
        return decoded, "utf8_decode_fallback"
    return "", "no_text_detected"


def _normalize_candidate(document_type: DocumentType, value: str | None) -> str | None:
    if not value:
        return None
    normalized = value.strip().upper()
    if not normalized:
        return None

    if document_type == DocumentType.aadhaar:
        return re.sub(r"\D", "", normalized)
    if document_type in {DocumentType.driving_license, DocumentType.voter_id}:
        return re.sub(r"[^A-Z0-9]", "", normalized)
    return normalized.replace(" ", "")


def _extract_candidates(text: str) -> dict[str, str | None]:
    upper_text = text.upper()

    def first(pattern: re.Pattern[str]) -> str | None:
        match = pattern.search(upper_text)
        return match.group(0) if match else None

    return {
        "pan": first(PAN_PATTERN),
        "aadhaar": first(AADHAAR_PATTERN),
        "passport": first(PASSPORT_PATTERN),
        "driving_license": first(DL_PATTERN),
        "voter_id": first(VOTER_ID_PATTERN),
        "email": first(EMAIL_PATTERN),
        "phone": first(PHONE_PATTERN),
    }


def _determine_validation(
    document_type: DocumentType,
    document_number: str | None,
    candidates: dict[str, str | None],
    text: str,
) -> dict[str, Any]:
    declared = _normalize_candidate(document_type, document_number)
    extracted = _normalize_candidate(document_type, candidates.get(document_type.value))

    selected = declared or extracted
    source = "declared_document_number" if declared else "ocr_extraction"

    if document_type not in VALIDATION_RULES:
        return {
            "document_type": document_type.value,
            "declared_document_number": document_number,
            "normalized_document_number": selected,
            "is_valid": bool(selected or len(text.strip()) > 30),
            "source": source if selected else "text_presence",
            "reason": "No strict format rule for this document type in v1",
        }

    if not selected:
        return {
            "document_type": document_type.value,
            "declared_document_number": document_number,
            "normalized_document_number": None,
            "is_valid": False,
            "source": "none",
            "reason": "Document number not found in input or extracted text",
        }

    pattern = VALIDATION_RULES[document_type]
    is_valid = bool(pattern.match(selected))
    reason = "Format matched expected pattern" if is_valid else "Format did not match rule"
    return {
        "document_type": document_type.value,
        "declared_document_number": document_number,
        "normalized_document_number": selected,
        "is_valid": is_valid,
        "source": source,
        "reason": reason,
    }


def _compute_quality(file_path: Path, text: str) -> dict[str, Any]:
    file_size = file_path.stat().st_size
    suffix = file_path.suffix.lower()
    warnings: list[str] = []
    score = 100

    if file_size < 15 * 1024:
        score -= 20
        warnings.append("File size is very small; image/PDF may be unclear")
    if file_size > 4 * 1024 * 1024:
        score -= 10
        warnings.append("Large file size; optimize before production upload")
    if len(text.strip()) < 20:
        score -= 35
        warnings.append("Low readable text; OCR confidence expected to be weak")
    if suffix not in {".jpg", ".jpeg", ".png", ".pdf"}:
        score -= 30
        warnings.append("Unexpected file extension for OCR pipeline")

    score = max(0, min(score, 100))
    if score >= 75:
        status = "good"
    elif score >= 45:
        status = "moderate"
    else:
        status = "poor"

    return {
        "file_size_bytes": file_size,
        "file_extension": suffix,
        "text_length": len(text),
        "score": score,
        "status": status,
        "warnings": warnings,
    }


def run_document_processing(document: Document) -> dict[str, Any]:
    file_path = Path(document.file_path)
    extracted_text, engine = _read_text_from_file(file_path)
    candidates = _extract_candidates(extracted_text)
    validation = _determine_validation(
        document_type=document.document_type,
        document_number=document.document_number,
        candidates=candidates,
        text=extracted_text,
    )
    quality = _compute_quality(file_path=file_path, text=extracted_text)

    next_action = "continue_to_face_verification"
    if not validation.get("is_valid", False) or quality["status"] == "poor":
        next_action = "manual_review_required"

    return {
        "engine": engine,
        "processed_at": datetime.now(timezone.utc).isoformat(),
        "raw_text_sample": extracted_text[:1200],
        "extracted_fields": candidates,
        "validation": validation,
        "quality": quality,
        "next_action": next_action,
    }
