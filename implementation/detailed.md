# Detailed Walkthrough: Phase 1 (Foundation Before AI Models)

This walkthrough defines the execution order for building your MCA project exactly as a staged software system.

## Goal of Phase 1

Deliver a running full-stack base with:

- Frontend (`React + TypeScript`)
- Backend (`FastAPI`)
- Databases (`PostgreSQL`, `MongoDB`, `Redis`)
- Container orchestration (`Docker Compose`)
- Connection verification API and UI

No model training/inference is included in this phase.

## Step-by-step order

## Step 1: Create baseline architecture and folders

Create core folders:

- `backend/`
- `frontend/`
- `ml/` (placeholder for next phase)
- `storage/`
- `docs/`

Why first:
- Keeps structure aligned with your approved synopsis and future module separation.

## Step 2: Backend bootstrap (FastAPI)

Implement:

1. App startup/shutdown lifecycle
2. Connection manager for:
   - PostgreSQL
   - MongoDB
   - Redis
3. Health endpoints:
   - `GET /health`
   - `GET /api/v1/system/status` (returns DB/server connection status)

Why second:
- This becomes the foundation for every later module (OCR, verification, decision engine).

## Step 3: Frontend bootstrap (React + TS)

Implement:

1. Simple dashboard page
2. Call backend status endpoint
3. Show status cards for:
   - API
   - PostgreSQL
   - MongoDB
   - Redis

Why third:
- Gives immediate end-to-end visibility that infrastructure is connected before building features.

## Step 4: Orchestration with Docker Compose

Bring up services together:

- `postgres`
- `mongodb`
- `redis`
- `backend`
- `frontend`

Why fourth:
- Single command startup is essential for development consistency and viva/demo reliability.

## Step 5: Verify and lock foundation

Acceptance checks:

1. Backend health returns `ok`
2. System status endpoint returns all components
3. Frontend shows live statuses from backend
4. Services restart cleanly without manual patching

Why fifth:
- Prevents unstable base from blocking AI modules later.

## Step 6: Start Module 1 only after foundation is stable

Next phase begins only after Step 5 passes:

- Document upload API
- OCR pipeline integration
- Validation layer

## Execution map after Phase 1

1. Module 1: Document processing and OCR
2. Module 2: Face verification + deepfake + liveness
3. Module 3: Decision engine + admin review + reports
4. Security hardening
5. Testing evidence and viva packaging

## What has been started now

The following first-step implementation has been started in this workspace:

1. Full project scaffold for backend/frontend/services
2. FastAPI connection-check endpoints
3. React status dashboard
4. Docker Compose for all required base services

## Step 2 progress (started)

Implemented backend foundation items:

1. Initial PostgreSQL ORM models (`users`, `documents`, `verification_sessions`, `admin_reviews`, `audit_logs`)
2. Schema auto-initialization on app startup
3. JWT and password-hashing security utilities
4. Auth APIs:
   - `POST /api/v1/auth/register`
   - `POST /api/v1/auth/login`
   - `GET /api/v1/auth/me`

## Step 2 progress (continued)

1. Added Alembic migration setup and initial revision for all foundation tables
2. Added demo data seed script (`backend/scripts/seed_demo_data.py`)
3. Updated backend container startup to run `alembic upgrade head` before API boot

## Step 3 progress (completed)

1. Frontend includes auth test panel:
   - register
   - login
   - get current user (`/me`)
2. Token persistence via `localStorage`
3. Document APIs implemented and connected:
   - `POST /api/v1/documents/upload` (JWT protected)
   - `GET /api/v1/documents/my` (JWT protected)
4. Frontend includes document upload + list panel:
   - document type selection
   - optional document number
   - file upload (`jpg/jpeg/png/pdf`)
   - uploaded documents table for the logged-in user

## Step 4 progress (completed)

1. Added document processing endpoint:
   - `POST /api/v1/documents/{document_id}/process`
2. Added OCR extraction service and pipeline execution for uploaded files.
3. Persisted processing output in `documents.ocr_extracted_data`.

## Step 5 progress (completed)

1. Added rule-based validation for core document types:
   - PAN
   - Aadhaar
   - Passport
   - Driving License
   - Voter ID
2. Added quality scoring and warnings for uploaded files.
3. Frontend now provides processing framework:
   - `Run OCR` action per document
   - validation + quality indicators in list
   - detailed `OCR + Validation Output` view

## Step 6 progress (completed)

1. Added verification session APIs:
   - `POST /api/v1/verification-sessions/upload`
   - `GET /api/v1/verification-sessions/my`
   - `GET /api/v1/verification-sessions/{session_id}`
2. Added placeholder scoring engine for:
   - face match score
   - liveness score
   - deepfake probability
3. Added threshold-based session status:
   - `approved` when `match >= 80`, `liveness >= 60`, `deepfake_probability <= 30`
   - otherwise `flagged`
4. Frontend now includes Step 6 framework:
   - face verification intake panel (selfie + optional video)
   - verification sessions table
   - score cards and decision inspector

## Step 7 progress (completed)

1. Added admin review APIs for reviewer/admin roles:
   - `GET /api/v1/admin/reviews/queue`
   - `POST /api/v1/admin/reviews/{session_id}/decision`
2. Added role guard for reviewer/admin-only routes.
3. Added manual decisions:
   - `approved`
   - `rejected`
   - `request_reupload`
4. Added KYC status updates on decision:
   - `approved` -> user `kyc_status=approved`, `is_verified=true`
   - `rejected` -> user `kyc_status=rejected`, `is_verified=false`
   - `request_reupload` -> user `kyc_status=under_review`, `is_verified=false`
5. Frontend now includes Step 7 admin queue panel:
   - load flagged sessions
   - apply approve/reject/request re-upload actions
   - provide rejection/re-upload reason

## Step 8 progress (current request: local runnable app shell)

1. Implemented required login rule:
   - fixed admin login supported as `hardik` / `1234`
   - all other users must register first, then login
2. Added dedicated dummy-feature backend endpoints:
   - `GET /api/v1/features/catalog`
   - `POST /api/v1/features/run` (token required)
3. Reworked frontend to a clean flow:
   - auth screen (`Login` + `Register`)
   - post-login main app screen
   - top taskbar listing all features
4. Added feature runner UI where each feature:
   - accepts dummy input
   - returns feature-specific dummy output
5. Added local-first DB fallback for development:
   - `APP_DB_DSN=sqlite+aiosqlite:///./ekyc_local.db`
   - avoids blocking local run when PostgreSQL is not available

## Step 9 progress (UI + flow refinement as requested)

1. Upgraded UI to a cleaner, organized post-login dashboard with dedicated feature taskbar.
2. Implemented stage-wise workflow exactly as requested:
   - Document OCR + forgery score (`pdf/png/jpg/jpeg/webp`)
   - Face match using extracted document face as reference
   - Deepfake score on current shared image
   - Liveness score on single image
3. Added final decision endpoint combining all four scores and generating downloadable PDF.
4. Added destination email input in UI for report dispatch target (delivery mocked for now).
5. Kept backend outputs dummy/random for now; can plug real model APIs when provided.
