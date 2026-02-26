import mimetypes
import random
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app.core.config import settings
from app.deps import get_current_user
from app.models.user import User
from app.services.email_service import send_email
from app.services.deepfake_inference import DeepfakeInferenceError, run_deepfake_inference
from app.services.document_face_extraction import DocumentFaceExtractionError, extract_document_face
from app.services.gradio_face_services import (
    FaceSimilarityError,
    LivenessDetectionError,
    run_face_similarity,
    run_liveness_detection,
)

router = APIRouter(prefix="/api/v1/features", tags=["features"])

BACKEND_ROOT = Path(__file__).resolve().parents[3]
UPLOAD_ROOT = BACKEND_ROOT / settings.upload_root
REPORT_ROOT = BACKEND_ROOT / settings.report_root
ALLOWED_DOCUMENT_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".webp"}
ALLOWED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

PIPELINE_STATE: dict[str, dict[str, Any]] = {}
PIPELINE_IMAGE_KEY_TO_STATE_PATH: dict[str, tuple[str, str]] = {
    "document_original": ("document", "file_path"),
    "document_face": ("document", "reference_face_path"),
    "face_live": ("face_match", "file_path"),
    "face_live_cropped": ("face_match", "live_face_crop_path"),
    "deepfake_live": ("deepfake", "file_path"),
    "liveness_live": ("liveness", "file_path"),
}


class FinalReportRequest(BaseModel):
    email: str = Field(min_length=5, max_length=255)


def _get_user_state(user: User) -> dict[str, Any]:
    key = str(user.user_id)
    if key not in PIPELINE_STATE:
        PIPELINE_STATE[key] = {}
    return PIPELINE_STATE[key]


def _build_preview_url(image_key: str) -> str:
    return f"/api/v1/features/images/{image_key}"


def _resolve_pipeline_image_path(current_user: User, image_key: str) -> Path:
    mapping = PIPELINE_IMAGE_KEY_TO_STATE_PATH.get(image_key)
    if mapping is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unsupported preview key: {image_key}",
        )

    state = _get_user_state(current_user)
    state_section, path_key = mapping
    section_data = state.get(state_section)
    if not isinstance(section_data, dict):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No preview available for {image_key}. Run the related pipeline step first.",
        )

    raw_path = section_data.get(path_key)
    if not isinstance(raw_path, str) or not raw_path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Preview path missing for {image_key}.",
        )

    file_path = Path(raw_path).resolve()
    upload_root_resolved = UPLOAD_ROOT.resolve()
    if not file_path.is_relative_to(upload_root_resolved):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid preview file path.",
        )
    return file_path


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

    try:
        extraction = await run_in_threadpool(
            extract_document_face,
            file_path,
            output_dir=UPLOAD_ROOT / user_id / "document_face",
            model_path=BACKEND_ROOT / settings.face_landmark_model_path,
            model_url=settings.face_landmark_model_url,
            crop_padding_ratio=settings.face_crop_padding_ratio,
            timeout_seconds=settings.external_api_timeout_seconds,
        )
    except DocumentFaceExtractionError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Document face extraction failed: {exc}",
        ) from exc

    reference_face_id = str(extraction["reference_face_id"])
    reference_face_path = str(extraction["reference_face_path"])
    landmarks_count = int(extraction["landmarks_count"])
    crop_boundary = extraction["crop_boundary"]
    crop_area = int(crop_boundary["width"]) * int(crop_boundary["height"])
    image_area = int(extraction["image_width"]) * int(extraction["image_height"])
    # A simple quality-based proxy for document authenticity risk in absence of a full forgery model.
    coverage_ratio = crop_area / float(max(1, image_area))
    forgery_risk = 26.0
    if landmarks_count >= 81:
        forgery_risk -= 8.0
    elif landmarks_count >= 68:
        forgery_risk -= 4.0
    if coverage_ratio > 0.004:
        forgery_risk -= 3.0
    forgery_score = round(max(6.0, min(forgery_risk, 55.0)), 2)
    ocr_confidence = round(min(0.99, 0.78 + (landmarks_count / 400.0)), 2)

    extracted_fields = {
        "name": current_user.full_name.title(),
        "document_type": document_type,
        "document_number": f"{document_type[:3].upper()}-{random.randint(100000, 999999)}",
    }
    response = {
        "stage": "document_ocr",
        "file_name": file_path.name,
        "document_image_url": _build_preview_url("document_original"),
        "file_size_bytes": size_bytes,
        "document_type": document_type,
        "ocr_confidence": ocr_confidence,
        "document_forgery_score": forgery_score,
        "extracted_face_available": True,
        "reference_face_id": reference_face_id,
        "reference_face_image_name": Path(reference_face_path).name,
        "reference_face_image_url": _build_preview_url("document_face"),
        "reference_face_landmarks_count": extraction["landmarks_count"],
        "reference_face_crop_boundary": extraction["crop_boundary"],
        "reference_face_padding_ratio": extraction["padding_ratio"],
        "reference_face_detector": extraction["detector"],
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
        "reference_face_path": reference_face_path,
        "reference_face_landmarks_count": extraction["landmarks_count"],
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

    try:
        live_face_extraction = await run_in_threadpool(
            extract_document_face,
            file_path,
            output_dir=UPLOAD_ROOT / user_id / "face_match_face",
            model_path=BACKEND_ROOT / settings.face_landmark_model_path,
            model_url=settings.face_landmark_model_url,
            crop_padding_ratio=settings.face_crop_padding_ratio,
            timeout_seconds=settings.external_api_timeout_seconds,
        )
    except DocumentFaceExtractionError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Live selfie face extraction failed: {exc}",
        ) from exc

    live_face_crop_path = Path(str(live_face_extraction["reference_face_path"]))
    if not live_face_crop_path.exists():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Live selfie face crop could not be created. Please upload a clear face image.",
        )

    reference_face_path_raw = state["document"].get("reference_face_path")
    if not isinstance(reference_face_path_raw, str) or not reference_face_path_raw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No extracted document face available. Re-run document OCR with a clear ID card image.",
        )
    reference_face_path = Path(reference_face_path_raw)
    if not reference_face_path.exists():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Extracted document face file not found. Re-run document OCR.",
        )

    try:
        inference = await run_in_threadpool(
            run_face_similarity,
            document_face_path=reference_face_path,
            live_face_path=live_face_crop_path,
            space_url=settings.face_similarity_space_url,
            api_name=settings.face_similarity_api_name,
            timeout_seconds=settings.external_api_timeout_seconds,
            pass_threshold=settings.face_match_pass_threshold,
        )
    except FaceSimilarityError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Face similarity inference failed: {exc}",
        ) from exc

    match_score = float(inference["face_match_score"])
    result = str(inference["result"])
    response = {
        "stage": "face_match",
        "reference_face_id": state["document"]["reference_face_id"],
        "reference_document_type": state["document"]["document_type"],
        "reference_face_image_url": _build_preview_url("document_face"),
        "live_image_name": file_path.name,
        "live_image_url": _build_preview_url("face_live"),
        "live_face_crop_image_name": live_face_crop_path.name,
        "live_face_crop_image_url": _build_preview_url("face_live_cropped"),
        "live_face_landmarks_count": live_face_extraction["landmarks_count"],
        "live_face_crop_boundary": live_face_extraction["crop_boundary"],
        "live_face_detector": live_face_extraction["detector"],
        "file_size_bytes": size_bytes,
        "face_match_score": match_score,
        "result": result,
        "raw_output": inference["raw_output"],
        "source": inference["source"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    state["face_match"] = {
        "file_path": str(file_path),
        "live_face_crop_path": str(live_face_crop_path),
        "face_match_score": match_score,
        "result": response,
    }
    return response


@router.post("/deepfake")
async def run_deepfake_detection(
    live_image: UploadFile | None = File(None),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    state = _get_user_state(current_user)
    user_id = str(current_user.user_id)
    input_source = "face_match_live_image"

    if live_image is not None:
        file_path, size_bytes = await _save_file(
            live_image,
            user_id=user_id,
            step="deepfake",
            allowed_extensions=ALLOWED_IMAGE_EXTENSIONS,
            max_size_mb=settings.max_upload_size_mb,
        )
        input_source = "uploaded_for_deepfake"
    else:
        face_match_file_path_raw = state.get("face_match", {}).get("file_path")
        if not isinstance(face_match_file_path_raw, str) or not face_match_file_path_raw:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No selfie/live image found. Run face verification first, or upload an image.",
            )
        file_path = Path(face_match_file_path_raw)
        if not file_path.exists():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Stored selfie/live image is missing. Re-run face verification.",
            )
        size_bytes = file_path.stat().st_size

    try:
        inference = await run_in_threadpool(
            run_deepfake_inference,
            file_path,
            space_url=settings.deepfake_space_url,
            api_name=settings.deepfake_api_name,
            hf_token=settings.deepfake_hf_token,
            timeout_seconds=settings.deepfake_timeout_seconds,
        )
    except DeepfakeInferenceError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Deepfake model inference failed: {exc}",
        ) from exc

    response = {
        "stage": "deepfake_detection",
        "live_image_name": file_path.name,
        "live_image_url": _build_preview_url("deepfake_live"),
        "file_size_bytes": size_bytes,
        "deepfake_score": inference["deepfake_score"],
        "authenticity_confidence": inference["authenticity_confidence"],
        "label": inference["label"],
        "model_label": inference["model_label"],
        "model_confidences": inference["model_confidences"],
        "source": {
            "provider": inference["provider"],
            "model_id": inference["model_id"],
            "api_name": inference["api_name"],
        },
        "input_source": input_source,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    state["deepfake"] = {
        "file_path": str(file_path),
        "deepfake_score": inference["deepfake_score"],
        "result": response,
    }
    return response


@router.post("/liveness")
async def run_liveness_check(
    single_image: UploadFile | None = File(None),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    state = _get_user_state(current_user)
    user_id = str(current_user.user_id)
    input_source = "face_match_live_image"

    if single_image is not None:
        file_path, size_bytes = await _save_file(
            single_image,
            user_id=user_id,
            step="liveness",
            allowed_extensions=ALLOWED_IMAGE_EXTENSIONS,
            max_size_mb=settings.max_upload_size_mb,
        )
        input_source = "uploaded_for_liveness"
    else:
        face_match_file_path_raw = state.get("face_match", {}).get("file_path")
        if not isinstance(face_match_file_path_raw, str) or not face_match_file_path_raw:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No selfie/live image found. Run face verification first, or upload an image.",
            )
        file_path = Path(face_match_file_path_raw)
        if not file_path.exists():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Stored selfie/live image is missing. Re-run face verification.",
            )
        size_bytes = file_path.stat().st_size

    try:
        inference = await run_in_threadpool(
            run_liveness_detection,
            image_path=file_path,
            space_url=settings.liveness_space_url,
            api_name=settings.liveness_api_name,
            timeout_seconds=settings.external_api_timeout_seconds,
            live_threshold=settings.liveness_live_threshold,
        )
    except LivenessDetectionError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Liveness inference failed: {exc}",
        ) from exc

    liveness_score = float(inference["liveness_score"])
    status_label = str(inference["status"])
    response = {
        "stage": "liveness_check",
        "image_name": file_path.name,
        "image_url": _build_preview_url("liveness_live"),
        "file_size_bytes": size_bytes,
        "liveness_score": liveness_score,
        "status": status_label,
        "raw_output": inference["raw_output"],
        "source": inference["source"],
        "input_source": input_source,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    state["liveness"] = {
        "file_path": str(file_path),
        "liveness_score": liveness_score,
        "result": response,
    }
    return response


@router.get("/images/{image_key}")
async def get_pipeline_image(
    image_key: str,
    current_user: User = Depends(get_current_user),
) -> FileResponse:
    file_path = _resolve_pipeline_image_path(current_user, image_key)
    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Preview image not found. Re-run the related pipeline step.",
        )

    media_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
    return FileResponse(
        path=file_path,
        media_type=media_type,
        filename=file_path.name,
    )


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

    email_result = await send_email(
        to=email,
        subject=f"eKYC Verification Report — {report_id}",
        html_body=f"<h2>eKYC Verification Report</h2><p>Report ID: {report_id}</p>"
                  f"<p>Decision: <strong>{decision.upper()}</strong></p>"
                  f"<p>Final Score: {final_score}</p>"
                  f"<p>Please find the detailed PDF report attached.</p>",
        attachment_path=str(report_path),
    )

    response = {
        "stage": "final_decision",
        "scores": report_payload["scores"],
        "decision": decision,
        "report_id": report_id,
        "report_download_url": f"/api/v1/features/reports/{report_id}",
        "email_delivery": {
            "to": email,
            "status": email_result.get("status", "unknown"),
            "note": email_result.get("note", email_result.get("error", "Email processed")),
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
