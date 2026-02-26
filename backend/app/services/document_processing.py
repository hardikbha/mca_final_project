import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.models.document import Document
from app.models.enums import DocumentType

logger = logging.getLogger(__name__)

PAN_PATTERN = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
AADHAAR_PATTERN = re.compile(r"\b[0-9]{4}\s?[0-9]{4}\s?[0-9]{4}\b")
PASSPORT_PATTERN = re.compile(r"\b[A-PR-WY][1-9][0-9]{6}\b")
DL_PATTERN = re.compile(r"\b[A-Z]{2}[0-9]{2}\s?[0-9]{11}\b")
VOTER_ID_PATTERN = re.compile(r"\b[A-Z]{3}[0-9]{7}\b")
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_PATTERN = re.compile(r"\b[6-9][0-9]{9}\b")
NAME_PATTERN = re.compile(r"\b([A-Z][a-z]+(?: [A-Z][a-z]+){1,3})\b")
DOB_PATTERN = re.compile(r"\b(\d{2}[/\-\.]\d{2}[/\-\.]\d{4})\b")

VALIDATION_RULES: dict[DocumentType, re.Pattern[str]] = {
    DocumentType.pan: re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]$"),
    DocumentType.aadhaar: re.compile(r"^[0-9]{12}$"),
    DocumentType.passport: re.compile(r"^[A-PR-WY][1-9][0-9]{6}$"),
    DocumentType.driving_license: re.compile(r"^[A-Z]{2}[0-9]{2}[0-9]{11}$"),
    DocumentType.voter_id: re.compile(r"^[A-Z]{3}[0-9]{7}$"),
}

EXTRACTION_PROMPT = (
    "You are an OCR engine. Extract ALL text visible in this document image. "
    "Include document numbers (Aadhaar, PAN, Passport, Driving License, Voter ID), "
    "full name, date of birth, address, and any other printed text. "
    "Return only the extracted text, nothing else. Preserve the original layout as much as possible."
)

# Lazy Gemini client singleton
_gemini_client = None


def _get_gemini_client():
    """Lazy-initialize the Gemini genai client."""
    global _gemini_client
    if _gemini_client is None:
        from app.core.config import settings
        if not settings.gemini_api_key:
            logger.warning("GEMINI_API_KEY not set. OCR will use fallback only.")
            return None
        try:
            from google import genai
            _gemini_client = genai.Client(api_key=settings.gemini_api_key)
            logger.info("Gemini client initialized")
        except Exception as exc:
            logger.warning("Gemini client init failed: %s", exc)
            return None
    return _gemini_client


def _read_text_with_gemini(file_path: Path) -> tuple[str, float] | None:
    """Use Gemini 2.5 Flash Lite to extract text from an image."""
    client = _get_gemini_client()
    if client is None:
        return None
    try:
        import PIL.Image
        image = PIL.Image.open(file_path)
        response = client.models.generate_content(
            model="gemini-2.5-flash-lite",
            contents=[EXTRACTION_PROMPT, image],
        )
        text = (response.text or "").strip()
        if text:
            return text, 0.92
    except Exception as exc:
        logger.warning("Gemini OCR failed for %s: %s", file_path.name, exc)
    return None


def _read_text_from_file(file_path: Path) -> tuple[str, str, float]:
    """Extract text from file using Gemini Vision for images, PyPDF for PDFs.
    Returns (text, engine_name, avg_confidence).
    """
    suffix = file_path.suffix.lower()

    # For PDFs, try PyPDF first
    if suffix == ".pdf":
        try:
            from pypdf import PdfReader
            reader = PdfReader(str(file_path))
            pages = [page.extract_text() or "" for page in reader.pages]
            joined = "\n".join(pages).strip()
            if joined and len(joined) > 20:
                return joined, "pypdf", 0.85
        except Exception:
            pass

    # For images (or PDFs with sparse text), use Gemini Vision
    if suffix in {".jpg", ".jpeg", ".png", ".webp", ".pdf"}:
        result = _read_text_with_gemini(file_path)
        if result is not None:
            text, confidence = result
            return text, "gemini-2.5-flash-lite", confidence

    # Last-resort fallback: try decoding raw bytes
    raw_bytes = file_path.read_bytes()
    decoded = raw_bytes.decode("utf-8", errors="ignore").strip()
    if decoded:
        return decoded, "utf8_decode_fallback", 0.3
    return "", "no_text_detected", 0.0


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

    # Name and DOB use original text (mixed case)
    name_match = NAME_PATTERN.search(text)
    dob_match = DOB_PATTERN.search(text)

    return {
        "pan": first(PAN_PATTERN),
        "aadhaar": first(AADHAAR_PATTERN),
        "passport": first(PASSPORT_PATTERN),
        "driving_license": first(DL_PATTERN),
        "voter_id": first(VOTER_ID_PATTERN),
        "email": first(EMAIL_PATTERN),
        "phone": first(PHONE_PATTERN),
        "name": name_match.group(1) if name_match else None,
        "date_of_birth": dob_match.group(1) if dob_match else None,
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
    extracted_text, engine, ocr_confidence = _read_text_from_file(file_path)
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
        "ocr_confidence": round(ocr_confidence, 3),
        "processed_at": datetime.now(timezone.utc).isoformat(),
        "raw_text_sample": extracted_text[:1200],
        "extracted_fields": candidates,
        "validation": validation,
        "quality": quality,
        "next_action": next_action,
    }
