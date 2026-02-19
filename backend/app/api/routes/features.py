import random
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app.core.config import settings
from app.deps import get_current_user
from app.models.user import User

router = APIRouter(prefix="/api/v1/features", tags=["features"])

BACKEND_ROOT = Path(__file__).resolve().parents[3]
UPLOAD_ROOT = BACKEND_ROOT / settings.upload_root
REPORT_ROOT = BACKEND_ROOT / settings.report_root
ALLOWED_DOCUMENT_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".webp"}
ALLOWED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

PIPELINE_STATE: dict[str, dict[str, Any]] = {}


class FinalReportRequest(BaseModel):
    email: str = Field(min_length=5, max_length=255)


def _get_user_state(user: User) -> dict[str, Any]:
    key = str(user.user_id)
    if key not in PIPELINE_STATE:
        PIPELINE_STATE[key] = {}
    return PIPELINE_STATE[key]


async def _save_file(
    uploaded_file: UploadFile,
    *,
    user_id: str,
    step: str,
    allowed_extensions: set[str],
    max_size_mb: int,
) -> tuple[Path, int]:
    suffix = Path(uploaded_file.filename or "").suffix.lower()
    if suffix not in allowed_extensions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file format. Allowed: {', '.join(sorted(allowed_extensions))}",
        )

    content = await uploaded_file.read()
    size_bytes = len(content)
    max_bytes = max_size_mb * 1024 * 1024
    if size_bytes > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large. Max allowed size is {max_size_mb} MB.",
        )
    if size_bytes == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )

    destination_dir = UPLOAD_ROOT / user_id / step
    destination_dir.mkdir(parents=True, exist_ok=True)
    file_path = destination_dir / f"{uuid.uuid4()}{suffix}"
    file_path.write_bytes(content)
    return file_path, size_bytes


def _generate_pdf(report_path: Path, payload: dict[str, Any]) -> None:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except Exception as exc:  # pragma: no cover - dependency/runtime guard
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"PDF engine unavailable: {exc}",
        ) from exc

    report_path.parent.mkdir(parents=True, exist_ok=True)
    page_width, page_height = A4
    pdf = canvas.Canvas(str(report_path), pagesize=A4)
    y = page_height - 50

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(40, y, "AI-Based Real-Time eKYC Verification Report")
    y -= 30

    pdf.setFont("Helvetica", 10)
    lines = [
        f"Report ID: {payload['report_id']}",
        f"Generated At (UTC): {payload['generated_at']}",
        f"User: {payload['user_name']}",
        f"Email Destination: {payload['email']}",
        "",
        "Scores",
        f"  Document Forgery Score (risk): {payload['scores']['document_forgery_score']}",
        f"  Face Match Score: {payload['scores']['face_match_score']}",
        f"  Deepfake Score (risk): {payload['scores']['deepfake_score']}",
        f"  Liveness Score: {payload['scores']['liveness_score']}",
        f"  Final Score: {payload['scores']['final_score']}",
        "",
        f"Final Decision: {payload['decision'].upper()}",
    ]
    for line in lines:
        pdf.drawString(40, y, line)
        y -= 16
        if y < 70:
            pdf.showPage()
            pdf.setFont("Helvetica", 10)
            y = page_height - 50
    pdf.save()


@router.get("/catalog")
async def get_feature_catalog(current_user: User = Depends(get_current_user)) -> dict[str, Any]:
    state = _get_user_state(current_user)
    return {
        "message": f"Welcome {current_user.full_name}",
        "features": [
            {"key": "document_ocr", "title": "Document OCR + Forgery"},
            {"key": "face_match", "title": "Face Match"},
            {"key": "deepfake_detection", "title": "Deepfake Detection"},
            {"key": "liveness_check", "title": "Liveness Check"},
            {"key": "final_decision", "title": "Final Decision + PDF Report"},
        ],
        "progress": {
            "document_done": "document" in state,
            "face_match_done": "face_match" in state,
            "deepfake_done": "deepfake" in state,
            "liveness_done": "liveness" in state,
        },
    }


@router.post("/document-ocr")
async def run_document_ocr(
    document_type: str = Form("aadhaar"),
    document: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    user_id = str(current_user.user_id)
    file_path, size_bytes = await _save_file(
        document,
        user_id=user_id,
        step="document",
        allowed_extensions=ALLOWED_DOCUMENT_EXTENSIONS,
        max_size_mb=settings.max_upload_size_mb,
    )

    forgery_score = round(random.uniform(8.0, 46.0), 2)
    ocr_confidence = round(random.uniform(0.82, 0.98), 2)
    reference_face_id = str(uuid.uuid4())

    extracted_fields = {
        "name": current_user.full_name.title(),
        "document_type": document_type,
        "document_number": f"{document_type[:3].upper()}-{random.randint(100000, 999999)}",
    }
    response = {
        "stage": "document_ocr",
        "file_name": file_path.name,
        "file_size_bytes": size_bytes,
        "document_type": document_type,
        "ocr_confidence": ocr_confidence,
        "document_forgery_score": forgery_score,
        "extracted_face_available": True,
        "reference_face_id": reference_face_id,
        "ocr_preview": [
            f"Name: {extracted_fields['name']}",
            f"Doc No: {extracted_fields['document_number']}",
            "Address: Dummy address extracted for UI testing",
        ],
        "extracted_fields": extracted_fields,
        "accepted_formats": sorted(ALLOWED_DOCUMENT_EXTENSIONS),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    state = _get_user_state(current_user)
    state["document"] = {
        "file_path": str(file_path),
        "reference_face_id": reference_face_id,
        "document_forgery_score": forgery_score,
        "document_type": document_type,
        "result": response,
    }
    return response


@router.post("/face-match")
async def run_face_match(
    live_face: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    state = _get_user_state(current_user)
    if "document" not in state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Run document OCR first so the document face can be used as reference.",
        )

    user_id = str(current_user.user_id)
    file_path, size_bytes = await _save_file(
        live_face,
        user_id=user_id,
        step="face_match",
        allowed_extensions=ALLOWED_IMAGE_EXTENSIONS,
        max_size_mb=settings.max_upload_size_mb,
    )
    match_score = round(random.uniform(58.0, 96.5), 2)
    result = "match_passed" if match_score >= 75 else "low_match_manual_review"
    response = {
        "stage": "face_match",
        "reference_face_id": state["document"]["reference_face_id"],
        "reference_document_type": state["document"]["document_type"],
        "live_image_name": file_path.name,
        "file_size_bytes": size_bytes,
        "face_match_score": match_score,
        "result": result,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    state["face_match"] = {
        "file_path": str(file_path),
        "face_match_score": match_score,
        "result": response,
    }
    return response


@router.post("/deepfake")
async def run_deepfake_detection(
    live_image: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    user_id = str(current_user.user_id)
    file_path, size_bytes = await _save_file(
        live_image,
        user_id=user_id,
        step="deepfake",
        allowed_extensions=ALLOWED_IMAGE_EXTENSIONS,
        max_size_mb=settings.max_upload_size_mb,
    )
    deepfake_score = round(random.uniform(6.0, 55.0), 2)
    authenticity_confidence = round(100.0 - deepfake_score, 2)
    label = "real_likely" if deepfake_score < 35 else "suspicious_manual_review"
    response = {
        "stage": "deepfake_detection",
        "live_image_name": file_path.name,
        "file_size_bytes": size_bytes,
        "deepfake_score": deepfake_score,
        "authenticity_confidence": authenticity_confidence,
        "label": label,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    state = _get_user_state(current_user)
    state["deepfake"] = {
        "file_path": str(file_path),
        "deepfake_score": deepfake_score,
        "result": response,
    }
    return response


@router.post("/liveness")
async def run_liveness_check(
    single_image: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    user_id = str(current_user.user_id)
    file_path, size_bytes = await _save_file(
        single_image,
        user_id=user_id,
        step="liveness",
        allowed_extensions=ALLOWED_IMAGE_EXTENSIONS,
        max_size_mb=settings.max_upload_size_mb,
    )
    liveness_score = round(random.uniform(52.0, 98.0), 2)
    status_label = "live_person_detected" if liveness_score >= 65 else "retry_or_manual_review"
    response = {
        "stage": "liveness_check",
        "image_name": file_path.name,
        "file_size_bytes": size_bytes,
        "liveness_score": liveness_score,
        "status": status_label,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    state = _get_user_state(current_user)
    state["liveness"] = {
        "file_path": str(file_path),
        "liveness_score": liveness_score,
        "result": response,
    }
    return response


@router.post("/final-report")
async def generate_final_report(
    payload: FinalReportRequest,
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    email = payload.email.strip().lower()
    if not EMAIL_REGEX.match(email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide a valid destination email address.",
        )

    state = _get_user_state(current_user)
    required_steps = ["document", "face_match", "deepfake", "liveness"]
    missing_steps = [step for step in required_steps if step not in state]
    if missing_steps:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Complete all steps first. Missing: {', '.join(missing_steps)}",
        )

    document_forgery_score = float(state["document"]["document_forgery_score"])
    face_match_score = float(state["face_match"]["face_match_score"])
    deepfake_score = float(state["deepfake"]["deepfake_score"])
    liveness_score = float(state["liveness"]["liveness_score"])

    document_authenticity = 100.0 - document_forgery_score
    deepfake_authenticity = 100.0 - deepfake_score
    final_score = round(
        (document_authenticity + face_match_score + deepfake_authenticity + liveness_score) / 4.0,
        2,
    )
    decision = (
        "approved"
        if (
            document_forgery_score <= 45
            and face_match_score >= 70
            and deepfake_score <= 40
            and liveness_score >= 65
            and final_score >= 70
        )
        else "manual_review"
    )

    report_id = f"KYC-{datetime.now(timezone.utc):%Y%m%d}-{uuid.uuid4().hex[:8]}"
    report_path = REPORT_ROOT / f"{report_id}.pdf"
    generated_at = datetime.now(timezone.utc).isoformat()

    report_payload = {
        "report_id": report_id,
        "generated_at": generated_at,
        "user_name": current_user.full_name,
        "email": email,
        "scores": {
            "document_forgery_score": document_forgery_score,
            "face_match_score": face_match_score,
            "deepfake_score": deepfake_score,
            "liveness_score": liveness_score,
            "final_score": final_score,
        },
        "decision": decision,
    }
    _generate_pdf(report_path, report_payload)

    response = {
        "stage": "final_decision",
        "scores": report_payload["scores"],
        "decision": decision,
        "report_id": report_id,
        "report_download_url": f"/api/v1/features/reports/{report_id}",
        "email_delivery": {
            "to": email,
            "status": "queued_dummy",
            "note": "Email delivery is mocked for now. Real provider can be plugged later.",
        },
        "generated_at": generated_at,
    }
    state["final_report"] = {
        "report_id": report_id,
        "path": str(report_path),
        "email": email,
        "result": response,
    }
    return response


@router.get("/reports/{report_id}")
async def download_report(report_id: str, current_user: User = Depends(get_current_user)) -> FileResponse:
    state = _get_user_state(current_user)
    final_report = state.get("final_report")
    if not final_report or final_report.get("report_id") != report_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found for current user.",
        )

    report_path = Path(final_report["path"])
    if not report_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report file does not exist.",
        )

    return FileResponse(
        path=report_path,
        media_type="application/pdf",
        filename=f"{report_id}.pdf",
    )


@router.get("/state")
async def get_pipeline_state(current_user: User = Depends(get_current_user)) -> dict[str, Any]:
    state = _get_user_state(current_user)
    return {
        "has_document": "document" in state,
        "has_face_match": "face_match" in state,
        "has_deepfake": "deepfake" in state,
        "has_liveness": "liveness" in state,
        "has_final_report": "final_report" in state,
    }
