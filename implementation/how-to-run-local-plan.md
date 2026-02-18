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
  infra/
  storage/
  docs/
```

## 3) Environment configuration

Create these env files:

- `backend/.env`
- `frontend/.env`
- `ml/.env`

Minimum backend env keys:

```env
APP_ENV=dev
APP_PORT=8000
JWT_SECRET=change_me
POSTGRES_DSN=postgresql+psycopg://postgres:postgres@localhost:5432/ekyc
MONGO_URI=mongodb://localhost:27017/ekyc
REDIS_URL=redis://localhost:6379/0
UPLOAD_DIR=../storage/uploads
REPORT_DIR=../storage/reports
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
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m app.worker
```

## 6) Basic verification checklist after startup

1. Open API docs at `http://localhost:8000/docs`
2. Open app UI (usually `http://localhost:5173`)
3. Test one full flow:
   - register/login,
   - upload document,
   - upload selfie/video,
   - see decision status,
   - review as admin.

## 7) Known first-phase simplifications

- OTP can be mocked in dev mode.
- SMS/email can use log-based mock adapters.
- Deepfake model can start with a baseline checkpoint and improve later.
