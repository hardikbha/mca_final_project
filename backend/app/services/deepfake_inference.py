from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from gradio_client import Client, handle_file

FAKE_LABEL_HINTS = (
    "fake",
    "deepfake",
    "generated",
    "manipulated",
    "spoof",
    "artificial",
    "synthetic",
    "ai",
)
REAL_LABEL_HINTS = ("real", "authentic", "genuine", "original", "human", "natural")


class DeepfakeInferenceError(RuntimeError):
    pass


CONFIDENCE_REGEXES = (
    re.compile(r"confidence(?:\s*score)?\s*[:=]\s*(\d+(?:\.\d+)?)\s*%?", re.IGNORECASE),
    re.compile(r"\(\s*confidence\s*[:=]\s*(\d+(?:\.\d+)?)\s*%\s*\)", re.IGNORECASE),
    re.compile(r"(\d+(?:\.\d+)?)\s*%", re.IGNORECASE),
)


def _normalize_confidence(value: Any) -> float | None:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return None
    if confidence < 0:
        return 0.0
    if confidence > 1:
        if confidence <= 100:
            confidence = confidence / 100.0
        else:
            return 1.0
    if confidence > 1:
        return 1.0
    return confidence


def _extract_confidence_from_text(text: str) -> float | None:
    for regex in CONFIDENCE_REGEXES:
        match = regex.search(text)
        if not match:
            continue
        return _normalize_confidence(match.group(1))
    return None


def _is_fake_label(label: str) -> bool:
    return any(hint in label for hint in FAKE_LABEL_HINTS)


def _is_real_label(label: str) -> bool:
    return any(hint in label for hint in REAL_LABEL_HINTS)


def _parse_prediction_text(raw_result: Any) -> tuple[float, str, list[dict[str, Any]], str]:
    text = str(raw_result or "").strip()
    if not text:
        raise DeepfakeInferenceError("Deepfake model returned an empty response.")

    normalized_text = text.lower()
    confidence = _extract_confidence_from_text(text)
    fake_detected = _is_fake_label(normalized_text)
    real_detected = _is_real_label(normalized_text)

    if fake_detected and not real_detected:
        fake_probability = confidence if confidence is not None else 1.0
        model_label = "ai_generated"
    elif real_detected and not fake_detected:
        real_probability = confidence if confidence is not None else 1.0
        fake_probability = round(1.0 - real_probability, 6)
        model_label = "human_created"
    elif fake_detected and real_detected:
        # Prefer explicit human-vs-ai phrasing when both hint groups appear in one sentence.
        if "human" in normalized_text and ("ai-generated" in normalized_text or "ai generated" in normalized_text):
            if normalized_text.index("human") < normalized_text.index("ai"):
                real_probability = confidence if confidence is not None else 1.0
                fake_probability = round(1.0 - real_probability, 6)
                model_label = "human_created"
            else:
                fake_probability = confidence if confidence is not None else 1.0
                model_label = "ai_generated"
        else:
            raise DeepfakeInferenceError(f"Ambiguous prediction text: {text}")
    else:
        raise DeepfakeInferenceError(f"Could not identify prediction label from response: {text}")

    if fake_probability < 0 or fake_probability > 1:
        raise DeepfakeInferenceError(f"Invalid fake probability parsed from response: {text}")

    confidences = [
        {"label": "ai_generated", "confidence": round(fake_probability, 6)},
        {"label": "human_created", "confidence": round(1.0 - fake_probability, 6)},
    ]
    return fake_probability, model_label, confidences, text


def _candidate_api_names(configured_api_name: str) -> list[str]:
    candidates = [configured_api_name, "/predict_3", "/predict_2"]
    deduped: list[str] = []
    for candidate in candidates:
        candidate = candidate.strip()
        if not candidate or candidate in deduped:
            continue
        deduped.append(candidate)
    return deduped


def run_deepfake_inference(
    image_path: Path,
    *,
    space_url: str,
    api_name: str,
    hf_token: str | None,
    timeout_seconds: float,
) -> dict[str, Any]:
    if not image_path.exists():
        raise DeepfakeInferenceError(f"Image file does not exist: {image_path}")

    try:
        auth_token = hf_token.strip() if isinstance(hf_token, str) and hf_token.strip() else None
        client = Client(
            space_url,
            token=auth_token,
            verbose=False,
            httpx_kwargs={"timeout": timeout_seconds},
            download_files=False,
        )
    except Exception as exc:  # pragma: no cover - network dependency
        raise DeepfakeInferenceError(f"Could not initialize Gradio client for deepfake space: {exc}") from exc

    endpoint_errors: list[str] = []
    prediction_payload = handle_file(str(image_path))
    for endpoint_name in _candidate_api_names(api_name):
        try:
            raw_result = client.predict(prediction_payload, api_name=endpoint_name)
            fake_probability, model_label, model_confidences, raw_text = _parse_prediction_text(raw_result)
        except Exception as exc:  # pragma: no cover - network dependency
            endpoint_errors.append(f"{endpoint_name}: {exc}")
            continue

        deepfake_score = round(fake_probability * 100.0, 2)
        authenticity_confidence = round(100.0 - deepfake_score, 2)
        label = "real_likely" if deepfake_score < 35 else "suspicious_manual_review"

        return {
            "deepfake_score": deepfake_score,
            "authenticity_confidence": authenticity_confidence,
            "label": label,
            "provider": "gradio_space",
            "model_id": space_url,
            "api_name": endpoint_name,
            "model_label": model_label,
            "model_confidences": model_confidences,
            "raw_output": raw_text,
        }

    joined_errors = " | ".join(endpoint_errors) if endpoint_errors else "No endpoint attempts were made."
    raise DeepfakeInferenceError(f"Deepfake prediction failed for all endpoints. Details: {joined_errors}")
