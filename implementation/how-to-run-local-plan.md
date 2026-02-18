# Local Run Plan (Development)

This file defines how the project should be run locally once scaffolding is created.

## 1) Prerequisites

- `Python 3.11+`
- `Node.js 20+` and `npm`
- `PostgreSQL 15+`
- `MongoDB 6+`
- `Redis 7+`
- `Tesseract OCR`
- Optional for ML speed: CUDA-compatible NVIDIA GPU

## 2) Planned folder layout

```bash
final_project/
  backend/
  frontend/
  ml/
  storage/
  docs/
  docker-compose.yml
```

## 3) Environment configuration

Create these env files:

- `backend/.env`
- `frontend/.env`
- `ml/.env`

Minimum backend env keys:

```env
APP_ENV=dev
JWT_SECRET=change_me
POSTGRES_DSN=postgresql+asyncpg://ekyc:ekyc@localhost:5432/ekyc
MONGODB_URI=mongodb://localhost:27017
MONGODB_DB=ekyc
REDIS_URL=redis://localhost:6379/0
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=1440
AUTO_CREATE_SCHEMA=true
```

## 4) Local service startup order

1. Start databases (`PostgreSQL`, `MongoDB`, `Redis`)
2. Run backend migrations
3. Start backend API
4. Start frontend
5. Start ML worker/service

## 5) Planned run commands

## Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Frontend

```bash
cd frontend
npm install
npm run dev
```

## ML service

```bash
cd ml
echo "ML service will be added in Phase 2"
```

## 6) Basic verification checklist after startup

1. Open API docs at `http://localhost:8000/docs`
2. Open app UI (usually `http://localhost:5173`)
3. Test auth APIs:
   - `POST /api/v1/auth/register`
   - `POST /api/v1/auth/login`
   - `GET /api/v1/auth/me` with Bearer token
4. Test connectivity API:
   - `GET /api/v1/system/status`
5. Optional demo seeding:
   - `python scripts/seed_demo_data.py`

## 7) Known first-phase simplifications

- OTP can be mocked in dev mode.
- SMS/email can use log-based mock adapters.
- Deepfake model can start with a baseline checkpoint and improve later.
