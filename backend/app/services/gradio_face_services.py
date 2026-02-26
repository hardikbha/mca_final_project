from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import httpx


class FaceSimilarityError(RuntimeError):
    pass


class LivenessDetectionError(RuntimeError):
    pass


def _normalize_api_name(api_name: str) -> str:
    if not api_name:
        return "/predict"
    return api_name if api_name.startswith("/") else f"/{api_name}"


def _normalize_base_url(space_url: str) -> str:
    return space_url.rstrip("/")


def _upload_file(client: httpx.Client, base_url: str, file_path: Path) -> str:
    with file_path.open("rb") as file_obj:
        response = client.post(
            f"{base_url}/gradio_api/upload",
            files={"files": (file_path.name, file_obj, "application/octet-stream")},
        )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, list) or not payload or not isinstance(payload[0], str):
        raise RuntimeError("Unexpected upload response from Gradio API.")
    return payload[0]


def _extract_event_data(response_text: str) -> Any:
    lines = response_text.splitlines()
    event_type = ""
    data_lines: list[str] = []

    for raw_line in lines:
        line = raw_line.strip()
        if line.startswith("event:"):
            event_type = line.replace("event:", "", 1).strip()
        if line.startswith("data:"):
            data_lines.append(line.replace("data:", "", 1).strip())

    if event_type == "error":
        raise RuntimeError("Gradio API returned error event.")
    if not data_lines:
        raise RuntimeError("No data returned from Gradio API event stream.")

    last_data = data_lines[-1]
    if last_data == "null":
        raise RuntimeError("Gradio API event payload was null.")
    return json.loads(last_data)


def _call_gradio_predict(
    *,
    space_url: str,
    api_name: str,
    image_paths: list[Path],
    timeout_seconds: float,
) -> Any:
    base_url = _normalize_base_url(space_url)
    normalized_api = _normalize_api_name(api_name)

    try:
        with httpx.Client(timeout=timeout_seconds) as client:
            uploaded_paths = [_upload_file(client, base_url, path) for path in image_paths]
            data = [{"path": uploaded_path, "meta": {"_type": "gradio.FileData"}} for uploaded_path in uploaded_paths]
            start_response = client.post(f"{base_url}/gradio_api/call{normalized_api}", json={"data": data})
            start_response.raise_for_status()
            event_id = start_response.json().get("event_id")
            if not event_id:
                raise RuntimeError("Missing event_id in Gradio API response.")

            result_response = client.get(f"{base_url}/gradio_api/call{normalized_api}/{event_id}")
            result_response.raise_for_status()
            return _extract_event_data(result_response.text)
    except Exception as exc:  # pragma: no cover - network dependency
        raise RuntimeError(f"Gradio API call failed: {exc}") from exc


def _coerce_single_text(payload: Any) -> str:
    if isinstance(payload, list) and payload and isinstance(payload[0], str):
        return payload[0]
    if isinstance(payload, str):
        return payload
    raise RuntimeError("Unexpected Gradio response payload type.")


def _normalize_percentage(value: float) -> float:
    return round(max(0.0, min(value, 100.0)), 2)


def run_face_similarity(
    *,
    document_face_path: Path,
    live_face_path: Path,
    space_url: str,
    api_name: str,
    timeout_seconds: float,
    pass_threshold: float,
) -> dict[str, Any]:
    try:
        payload = _call_gradio_predict(
            space_url=space_url,
            api_name=api_name,
            image_paths=[document_face_path, live_face_path],
            timeout_seconds=timeout_seconds,
        )
        output_text = _coerce_single_text(payload).strip()
    except Exception as exc:
        raise FaceSimilarityError(str(exc)) from exc

    score_match = re.search(r"Similarity\s*Score\s*:\s*([0-9]*\.?[0-9]+)", output_text, flags=re.IGNORECASE)
    if score_match:
        raw_score = float(score_match.group(1))
        normalized_score = raw_score * 100.0 if raw_score <= 1.0 else raw_score
    elif "no faces detected" in output_text.lower():
        normalized_score = 0.0
    else:
        raise FaceSimilarityError(f"Unable to parse similarity score from response: {output_text}")

    face_match_score = _normalize_percentage(normalized_score)
    result = "match_passed" if face_match_score >= pass_threshold else "low_match_manual_review"

    return {
        "face_match_score": face_match_score,
        "result": result,
        "raw_output": output_text,
        "source": {
            "provider": "gradio_space",
            "space_url": _normalize_base_url(space_url),
            "api_name": _normalize_api_name(api_name),
        },
    }


def run_liveness_detection(
    *,
    image_path: Path,
    space_url: str,
    api_name: str,
    timeout_seconds: float,
    live_threshold: float,
) -> dict[str, Any]:
    try:
        payload = _call_gradio_predict(
            space_url=space_url,
            api_name=api_name,
            image_paths=[image_path],
            timeout_seconds=timeout_seconds,
        )
        output_text = _coerce_single_text(payload).strip()
    except Exception as exc:
        raise LivenessDetectionError(str(exc)) from exc

    label_match = re.search(r"Liveness\s*:\s*([a-zA-Z_ -]+)", output_text, flags=re.IGNORECASE)
    confidence_match = re.search(r"Confidence\s*:\s*([0-9]*\.?[0-9]+)", output_text, flags=re.IGNORECASE)

    normalized_label = label_match.group(1).strip().lower() if label_match else ""
    if confidence_match:
        raw_confidence = float(confidence_match.group(1))
        normalized_score = raw_confidence * 100.0 if raw_confidence <= 1.0 else raw_confidence
    elif "live" in normalized_label:
        normalized_score = live_threshold
    else:
        normalized_score = max(0.0, live_threshold - 25.0)

    liveness_score = _normalize_percentage(normalized_score)
    is_live = "live" in normalized_label and "not" not in normalized_label
    status_label = (
        "live_person_detected" if is_live and liveness_score >= live_threshold else "retry_or_manual_review"
    )

    return {
        "liveness_score": liveness_score,
        "status": status_label,
        "raw_output": output_text,
        "source": {
            "provider": "gradio_space",
            "space_url": _normalize_base_url(space_url),
            "api_name": _normalize_api_name(api_name),
        },
    }
