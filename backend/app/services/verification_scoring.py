import hashlib
from typing import Any

from app.models.document import Document
from app.models.enums import AuthenticityLabel, VerificationStatus


def _seed_value(payload: bytes, start: int = 0, length: int = 10) -> int:
    digest = hashlib.sha256(payload).hexdigest()
    return int(digest[start : start + length], 16)


def _score_between(seed: int, min_score: float, max_score: float) -> float:
    spread = max_score - min_score
    normalized = (seed % 10_000) / 10_000
    return round(min_score + (spread * normalized), 2)


def run_placeholder_verification(
    selfie_bytes: bytes,
    video_bytes: bytes | None,
    reference_document: Document | None,
) -> dict[str, Any]:
    base_payload = selfie_bytes
    if video_bytes:
        base_payload += video_bytes[:2048]
    if reference_document:
        base_payload += str(reference_document.document_id).encode()
        if reference_document.document_number:
            base_payload += reference_document.document_number.encode()

    first = _seed_value(base_payload, 0, 10)
    second = _seed_value(base_payload, 12, 10)
    third = _seed_value(base_payload, 24, 10)

    match_score = _score_between(first, 64, 96)
    liveness_score = _score_between(second, 52, 95)
    deepfake_probability = _score_between(third, 7, 46)

    if video_bytes:
        liveness_score = min(100.0, round(liveness_score + 6, 2))
        deepfake_probability = max(0.0, round(deepfake_probability - 4, 2))

    if reference_document and reference_document.ocr_extracted_data:
        is_doc_valid = bool(
            (reference_document.ocr_extracted_data.get("validation") or {}).get("is_valid")
        )
        if is_doc_valid:
            match_score = min(100.0, round(match_score + 4, 2))

    thresholds = {"match_score": 80.0, "liveness_score": 60.0, "deepfake_probability": 30.0}
    passes = {
        "match_score": match_score >= thresholds["match_score"],
        "liveness_score": liveness_score >= thresholds["liveness_score"],
        "deepfake_probability": deepfake_probability <= thresholds["deepfake_probability"],
    }
    approved = all(passes.values())

    authenticity_label = (
        AuthenticityLabel.real if deepfake_probability <= 35 and liveness_score >= 50 else AuthenticityLabel.fake
    )
    status = VerificationStatus.approved if approved else VerificationStatus.flagged

    quality_checks = {
        "thresholds": thresholds,
        "passes": passes,
        "has_video": bool(video_bytes),
        "reference_document_id": str(reference_document.document_id) if reference_document else None,
        "notes": (
            "Meets auto-approval rule"
            if approved
            else "Requires manual review due to threshold mismatch"
        ),
    }

    return {
        "match_score": match_score,
        "liveness_score": liveness_score,
        "deepfake_probability": deepfake_probability,
        "authenticity_label": authenticity_label,
        "status": status,
        "quality_checks": quality_checks,
    }
