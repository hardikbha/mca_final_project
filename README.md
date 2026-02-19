# MCA Final Project (Foundation Setup)

This repository currently contains a working Phase 1 prototype:

- `backend/` FastAPI service
- `frontend/` React TypeScript app shell (login/register + polished taskbar + stage-wise workflow)
- `docker-compose.yml` for PostgreSQL, MongoDB, Redis, backend, frontend

## Local run (without Docker)

## Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Frontend

```bash
cd frontend
npm install
npm run dev -- --host 0.0.0.0 --port 5173
```

Default local DB for backend auth is SQLite (`APP_DB_DSN=sqlite+aiosqlite:///./ekyc_local.db`), so local run works even if PostgreSQL is not running.

## Quick start

```bash
docker compose up -d --build
```

Open:

- Frontend: `http://localhost:5173`
- Backend docs: `http://localhost:8000/docs`
- Backend health: `http://localhost:8000/health`

Core APIs:

- `GET http://localhost:8000/api/v1/system/status`
- `POST http://localhost:8000/api/v1/auth/register`
- `POST http://localhost:8000/api/v1/auth/login`
- `GET http://localhost:8000/api/v1/auth/me`
- `GET http://localhost:8000/api/v1/features/catalog`
- `POST http://localhost:8000/api/v1/features/document-ocr`
- `POST http://localhost:8000/api/v1/features/face-match`
- `POST http://localhost:8000/api/v1/features/deepfake`
- `POST http://localhost:8000/api/v1/features/liveness`
- `POST http://localhost:8000/api/v1/features/final-report`
- `GET http://localhost:8000/api/v1/features/reports/{report_id}`
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

Fixed admin login shortcut:

- Login ID: `hardik`
- Password: `1234`

Current behavior:

- Scores are currently dummy/random for fast UI-backend integration.
- Final decision combines all four scores:
  - document forgery
  - face match
  - deepfake
  - liveness
- Final output is generated as a downloadable PDF.
- Email delivery field is mocked (`queued_dummy`) until real provider integration.

## Stop

```bash
docker compose down
```
