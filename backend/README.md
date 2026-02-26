# Backend (FastAPI)

## Local run

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Default app DB for local run is SQLite (`APP_DB_DSN=sqlite+aiosqlite:///./ekyc_local.db`).
If you want PostgreSQL for app tables, set `APP_DB_DSN` explicitly.

## Endpoints

- `GET /health`
- `GET /api/v1/system/status`
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `GET /api/v1/auth/me` (Bearer token required)
- `GET /api/v1/features/catalog` (Bearer token required)
- `POST /api/v1/features/document-ocr` (Bearer token required, multipart)
- `POST /api/v1/features/face-match` (Bearer token required, multipart)
- `POST /api/v1/features/deepfake` (Bearer token required, multipart)
- `POST /api/v1/features/liveness` (Bearer token required, multipart)
- `POST /api/v1/features/final-report` (Bearer token required, JSON)
- `GET /api/v1/features/reports/{report_id}` (Bearer token required)
- `GET /api/v1/admin/reviews/queue` (Reviewer/Admin token required)
- `POST /api/v1/admin/reviews/{session_id}/decision` (Reviewer/Admin token required)

Fixed admin login shortcut:

- identifier: `hardik`
- password: `1234`

Notes:

- Document OCR still uses placeholder OCR/forgery values, but document face extraction is real:
  - Extracts face using dlib 81 landmarks (`shape_predictor_81_face_landmarks.dat`)
  - Expands boundary with configurable padding and saves cropped reference face
- Face match is real and calls Gradio Space API `cvdetectors/humandetector`.
- Liveness is real and calls Gradio Space API `cvdetectors/liveness-detector`.
- Deepfake detection calls Gradio Space `Dharshaneshwaran/deepfake` using image endpoint API.
- Optional face extraction + face/liveness config env vars:
  - `FACE_LANDMARK_MODEL_PATH`
  - `FACE_LANDMARK_MODEL_URL`
  - `FACE_CROP_PADDING_RATIO`
  - `FACE_SIMILARITY_SPACE_URL`
  - `FACE_SIMILARITY_API_NAME`
  - `FACE_MATCH_PASS_THRESHOLD`
  - `LIVENESS_SPACE_URL`
  - `LIVENESS_API_NAME`
  - `LIVENESS_LIVE_THRESHOLD`
  - `EXTERNAL_API_TIMEOUT_SECONDS`
- Optional deepfake config env vars:
  - `DEEPFAKE_SPACE_URL` (default: `Dharshaneshwaran/deepfake`)
  - `DEEPFAKE_API_NAME` (default: `/predict_3`, falls back to `/predict_2` automatically)
  - `DEEPFAKE_HF_TOKEN` (optional for gated/private Space access)
  - `DEEPFAKE_TIMEOUT_SECONDS` (default: `90`)
- Final report email status is mocked and can be replaced with actual email provider integration.

## Demo seeding

```bash
python scripts/seed_demo_data.py
```
