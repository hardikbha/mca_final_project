# MCA Final Project (Foundation Setup)

This repository currently contains Phase 1 foundation:

- `backend/` FastAPI service
- `frontend/` React TypeScript dashboard (system status + auth + document upload test panel)
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

Document upload constraints:

- Allowed file types: `jpg`, `jpeg`, `png`, `pdf`
- Max file size: `10 MB`

Step 4/5 processing output (stored per document):

- OCR engine metadata
- extracted fields (`pan`, `aadhaar`, `passport`, etc.)
- validation result with rule status
- quality score and warnings
- next action (`continue_to_face_verification` or `manual_review_required`)

Seed demo users:

```bash
docker compose exec backend python scripts/seed_demo_data.py
```

## Stop

```bash
docker compose down
```
