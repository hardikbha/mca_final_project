# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Full-stack **eKYC (electronic Know Your Customer)** verification system. Five-stage pipeline: Document OCR → Face Match → Deepfake Detection → Liveness Check → Final PDF Report. FastAPI backend + React/TypeScript frontend, orchestrated with Docker Compose.

## Commands

### Backend
```bash
cd backend
source .venv312/bin/activate            # existing virtualenv (Python 3.12)
set -a && source .env && set +a         # load env vars (.env not auto-loaded)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend
```bash
cd frontend
npm run dev                             # Vite dev server on :5173
npm run build                           # production build to dist/
```

### Tests
```bash
# Frontend (Vitest) — 10 tests across 3 files
cd frontend && npx vitest run

# Backend (pytest + pytest-asyncio)
cd backend && pytest                    # all tests
pytest tests/test_auth.py -v            # single file
pytest -k "test_register" -v            # single test by name
```

### Docker (full stack: postgres, mongodb, redis, backend, frontend)
```bash
docker compose up -d --build            # start everything
docker compose down                     # stop
```

### Database Migrations
```bash
cd backend
alembic upgrade head                    # apply migrations
alembic revision --autogenerate -m "description"  # generate new migration
```

## Architecture

### Backend (`backend/app/`)

**Layered pattern:** `api/routes/` → `services/` → `models/` ↔ `db/session`

- **Entry point:** `main.py` — FastAPI app with CORS, rate limiting (slowapi+Redis), performance timing middleware
- **Config:** `core/config.py` — frozen dataclass reading `os.getenv()`. Backend does NOT auto-load `.env`; you must `source .env` or pass vars explicitly
- **Auth:** JWT (HS256) via `core/security.py`, dependency injection via `deps.py` (`get_current_user`, `get_current_reviewer_or_admin`)
- **Database:** SQLAlchemy 2.0 async. Default local: SQLite (`ekyc_local.db`). Docker: PostgreSQL. Audit logs: MongoDB (Motor). Cache: Redis
- **`AUTO_CREATE_SCHEMA=true`** creates tables on startup without migrations (dev convenience)

**API routes** (all under `/api/v1/`):
| Prefix | File | Purpose |
|---|---|---|
| `/auth` | `auth.py` | register, login, /me |
| `/features` | `features.py` | Main pipeline: document-ocr, face-match, deepfake, liveness, final-report, report download |
| `/documents` | `documents.py` | Document upload + OCR processing |
| `/verification-sessions` | `verification.py` | Selfie/video upload + session management |
| `/admin/reviews` | `admin_review.py` | Flagged session queue + review decisions (admin/reviewer only) |
| `/analytics` | `analytics.py` | Overview, trends, latency metrics (admin only) |
| `/admin/audit-logs` | `audit.py` | MongoDB audit log queries (admin only) |
| `/system` | `system.py` | Health/status checks |

**Key services:**
- `document_processing.py` — Gemini 2.5 Flash Lite Vision OCR, regex field extraction (PAN/Aadhaar/Passport/DL/Voter ID), validation, quality scoring
- `document_face_extraction.py` — dlib 81-point landmarks, face crop from document image
- `gradio_face_services.py` — Face similarity + liveness via Gradio Space APIs (SSE streaming)
- `deepfake_inference.py` — HuggingFace Inference API (`umm-maybe/AI-image-detector`)
- `email_service.py` — Console logging stub (no external provider; ready for SendGrid/SES/Resend)
- `audit_service.py` — MongoDB writes (silent failure if unavailable)
- `cache_service.py` — Redis get/set/delete with TTL

### Frontend (`frontend/src/`)

- **Build:** Vite 5 + TypeScript 5.6
- **State:** `useAuth()` hook (token + user in localStorage), `ToastContext` for notifications, component-level `useState`
- **API client:** `services/api.ts` — fetch-based, all functions return `{ data, error }`. Backend URL from `VITE_API_BASE_URL` (default `http://localhost:8000`)
- **Layout:** Single long scrollable page (no tab switching). Sticky header, pipeline stepper (5 steps), scoreboard bar, then sections 1-5 with collapsible JSON output
- **Components:** `auth/` (login/register), `pipeline/` (5 stage tabs), `dashboard/` (scoreboard + analytics charts), `layout/` (header, stepper), `shared/` (ScoreCard, FileUpload, LoadingSkeleton, Toast)
- **Types:** All in `types/index.ts` — DocumentResult, FaceMatchResult, DeepfakeResult, LivenessResult, FinalReportResult, etc.

### Database Models (SQLAlchemy)
- **User** — UUID PK, email/phone unique, password_hash, role (user/admin/reviewer), kyc_status
- **Document** — user FK, document_type enum, file_path, ocr_extracted_data JSON
- **VerificationSession** — user FK, scores (match/liveness/deepfake as floats 0-100), status enum
- **AdminReview** — session FK, admin FK, decision enum, rejection_reason
- **AuditLog** — user FK, action, IP, user_agent, additional_data JSON

## External Services

| Service | Config Var | Notes |
|---|---|---|
| Google Gemini 2.5 Flash Lite | `GEMINI_API_KEY` | OCR via `google-genai` SDK |
| HuggingFace Inference | `DEEPFAKE_MODEL_ID`, `DEEPFAKE_HF_TOKEN` | Deepfake detection |
| Gradio Spaces | `FACE_SIMILARITY_SPACE_URL`, `LIVENESS_SPACE_URL` | Face match + liveness |

## Demo Login

Admin shortcut: identifier `hardik`, password `1234`. New users register then login with email/phone.

## Key Decisions

- Backend `.env` must be sourced manually (`set -a && source .env && set +a`) before running uvicorn — no python-dotenv auto-load
- Local dev uses SQLite (no Postgres needed); MongoDB/Redis fail silently if unavailable
- Document forgery scoring is a placeholder (coverage-ratio heuristic), not real ML
- The `features.py` route handles the entire 5-stage pipeline; `documents.py` and `verification.py` are lower-level CRUD alternatives
- Frontend uses raw CSS (`styles.css`), no CSS framework
