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

- For now, feature scores are generated as dummy/random values.
- Final report email status is mocked and can be replaced with actual email provider integration.

## Demo seeding

```bash
python scripts/seed_demo_data.py
```
