from __future__ import annotations

import uuid
from pathlib import Path
from urllib import request

import dlib
import numpy as np
from PIL import Image, UnidentifiedImageError


class DocumentFaceExtractionError(RuntimeError):
    pass


_FACE_DETECTOR = dlib.get_frontal_face_detector()


def _ensure_landmark_model(model_path: Path, model_url: str, timeout_seconds: float) -> None:
    if model_path.exists() and model_path.stat().st_size > 0:
        return

    model_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = model_path.with_suffix(model_path.suffix + ".part")
    try:
        with request.urlopen(model_url, timeout=timeout_seconds) as response:
            tmp_path.write_bytes(response.read())
    except Exception as exc:  # pragma: no cover - network dependency
        raise DocumentFaceExtractionError(f"Failed to download landmark model: {exc}") from exc

    if tmp_path.stat().st_size < 1_000_000:
        tmp_path.unlink(missing_ok=True)
        raise DocumentFaceExtractionError("Landmark model file download appears incomplete.")
    tmp_path.replace(model_path)


def _pick_largest_face(faces: list[dlib.rectangle]) -> dlib.rectangle:
    return max(faces, key=lambda face: face.width() * face.height())


def extract_document_face(
    document_path: Path,
    *,
    output_dir: Path,
    model_path: Path,
    model_url: str,
    crop_padding_ratio: float,
    timeout_seconds: float,
) -> dict[str, object]:
    try:
        image = Image.open(document_path).convert("RGB")
    except UnidentifiedImageError as exc:
        raise DocumentFaceExtractionError(
            "Document face extraction currently supports image documents only (jpg/jpeg/png/webp)."
        ) from exc
    except Exception as exc:
        raise DocumentFaceExtractionError(f"Failed to read document image: {exc}") from exc

    width, height = image.size
    gray = np.array(image.convert("L"))
    faces = _FACE_DETECTOR(gray, 1)
    if not faces:
        raise DocumentFaceExtractionError("No face detected in the document image.")

    _ensure_landmark_model(model_path=model_path, model_url=model_url, timeout_seconds=timeout_seconds)
    try:
        predictor = dlib.shape_predictor(str(model_path))
    except Exception as exc:
        raise DocumentFaceExtractionError(f"Failed to load 81-landmark predictor: {exc}") from exc

    face = _pick_largest_face(list(faces))
    shape = predictor(gray, face)
    landmarks = [(shape.part(index).x, shape.part(index).y) for index in range(shape.num_parts)]
    if len(landmarks) < 68:
        raise DocumentFaceExtractionError(
            f"Landmark detector returned {len(landmarks)} points; expected at least 68."
        )

    xs = [point[0] for point in landmarks]
    ys = [point[1] for point in landmarks]
    min_x, max_x = min(xs), max(xs)
    min_y, max_y = min(ys), max(ys)
    pad_x = int((max_x - min_x) * crop_padding_ratio)
    # Add extra forehead margin for document photos.
    pad_y_top = int((max_y - min_y) * (crop_padding_ratio + 0.15))
    pad_y_bottom = int((max_y - min_y) * crop_padding_ratio)

    left = max(0, min_x - pad_x)
    top = max(0, min_y - pad_y_top)
    right = min(width, max_x + pad_x)
    bottom = min(height, max_y + pad_y_bottom)

    if right - left < 20 or bottom - top < 20:
        raise DocumentFaceExtractionError("Calculated face crop boundary is too small.")

    cropped = image.crop((left, top, right, bottom))
    output_dir.mkdir(parents=True, exist_ok=True)
    face_id = str(uuid.uuid4())
    cropped_path = output_dir / f"{face_id}.jpg"
    cropped.save(cropped_path, format="JPEG", quality=95)

    return {
        "reference_face_id": face_id,
        "reference_face_path": str(cropped_path),
        "landmarks_count": len(landmarks),
        "image_width": width,
        "image_height": height,
        "crop_boundary": {
            "left": left,
            "top": top,
            "right": right,
            "bottom": bottom,
            "width": right - left,
            "height": bottom - top,
        },
        "padding_ratio": crop_padding_ratio,
        "detector": "dlib_81_landmarks",
    }
