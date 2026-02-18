# MCA Final Project (Foundation Setup)

This repository currently contains Phase 1 foundation:

- `backend/` FastAPI service
- `frontend/` React TypeScript dashboard (status + auth + document OCR + face verification panel)
- `docker-compose.yml` for PostgreSQL, MongoDB, Redis, backend, frontend

## Quick start

```bash
docker compose up -d --build
```

Open:

- Frontend: `http://localhost:5173`
- Backend docs: `http://localhost:8000/docs`
- Backend health: `http://localhost:8000/health`

Status API:

- `GET http://localhost:8000/api/v1/system/status`
- `POST http://localhost:8000/api/v1/auth/register`
- `POST http://localhost:8000/api/v1/auth/login`
- `GET http://localhost:8000/api/v1/auth/me`
- `POST http://localhost:8000/api/v1/documents/upload`
- `GET http://localhost:8000/api/v1/documents/my`
- `POST http://localhost:8000/api/v1/documents/{document_id}/process`
- `POST http://localhost:8000/api/v1/verification-sessions/upload`
- `GET http://localhost:8000/api/v1/verification-sessions/my`
- `GET http://localhost:8000/api/v1/verification-sessions/{session_id}`

Document upload constraints:

- Allowed file types: `jpg`, `jpeg`, `png`, `pdf`
- Max file size: `10 MB`

Verification upload constraints:

- Selfie allowed types: `jpg`, `jpeg`, `png` (max `10 MB`)
- Liveness video allowed types: `mp4`, `mov`, `avi` (optional, max `30 MB`)

Step 4/5 processing output (stored per document):

- OCR engine metadata
- extracted fields (`pan`, `aadhaar`, `passport`, etc.)
- validation result with rule status
- quality score and warnings
- next action (`continue_to_face_verification` or `manual_review_required`)

Step 6 verification output (stored per verification session):

- `match_score`
- `liveness_score`
- `deepfake_probability`
- `authenticity_label` (`real` / `fake`)
- `status` (`approved` / `flagged`) using threshold rule:
  - `match >= 80`, `liveness >= 60`, `deepfake_probability <= 30`

Seed demo users:

```bash
docker compose exec backend python scripts/seed_demo_data.py
```

## Stop

```bash
docker compose down
```
