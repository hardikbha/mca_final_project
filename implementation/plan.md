# AI-Based Real-Time eKYC System: Implementation Plan

## 1) Project baseline (fixed from approved synopsis)

- Title: `AI-Based Real-Time eKYC System for Deepfake-Free Identity Verification`
- Core stack: `FastAPI + React (TypeScript) + PostgreSQL + MongoDB + Redis + PyTorch`
- Core modules (must stay aligned with synopsis):
1. `Document Processing and OCR`
2. `Face Verification and Deepfake Detection`
3. `KYC Decision and Admin Review`
- Target decision thresholds:
  - Auto-approve when `match >= 80`, `liveness >= 60`, `deepfake <= 30`
- Target performance:
  - Image verification pipeline in `< 3 sec` (as claimed)

## 2) IGNOU guideline constraints to satisfy in implementation

1. Cover full SDLC: analysis, design, coding, testing, documentation.
2. Keep project title exactly consistent with approved synopsis.
3. Produce implementation evidence for viva:
  - executable software,
  - test cases + results,
  - screenshots and reports.
4. Include project security implementation (auth, encryption, validation, audit logs).

## 3) Recommended system architecture

- `frontend/`: React + TypeScript SPA (user + admin views)
- `backend/`: FastAPI REST API
- `ml/`: model inference service/helpers (face match, deepfake, liveness)
- `infra/`: Docker Compose, NGINX, environment configs
- `storage/`: encrypted uploads, generated reports
- `docs/`: SRS, API contract, test reports, screenshots for final report

## 4) Module-wise implementation breakdown

## Module A: Foundation (build first)
- User registration/login, JWT, RBAC (`user/reviewer/admin`)
- OTP flow (mock in dev, provider in prod)
- DB migrations and base entities:
  - `users`, `documents`, `verification_sessions`, `admin_reviews`, `audit_logs`
- File upload pipeline (size/type checks, UUID filenames)

## Module 1: Document Processing and OCR
- Upload and preprocessing for `aadhaar/pan/passport/dl/voter_id`
- OCR extraction (`Tesseract/EasyOCR`)
- Field validation (regex + document-specific rules)
- Save normalized + raw OCR data
- Quality checks (blur, resolution, crop)

## Module 2: Face Verification + Deepfake + Liveness
- Face detection/alignment (`InsightFace/RetinaFace`)
- Embedding generation and cosine similarity score
- Deepfake classifier inference (image first, then video)
- Liveness checks:
  - passive (texture/artifacts)
  - active (blink/head movement from video frames)
- Persist model scores + evidence metadata

## Module 3: Decision Engine and Admin Review
- Score aggregation and policy engine
- Auto decision vs flagged queue
- Admin review workflow (`approve/reject/request_reupload`)
- Notification hooks (email/SMS abstraction layer)
- Final KYC report generation (PDF + verification id/QR)

## Cross-cutting modules
- Audit logging (append-only pattern)
- Rate limiting and API key support
- Encryption at rest/in transit
- Analytics dashboard (approval/rejection trends, latency, fraud trend)

## 5) Execution roadmap (practical order)

1. Week 1-2: Project bootstrapping
   - Repo structure, dev environments, CI skeleton, DB schemas, auth base.
2. Week 3-5: Module 1 delivery
   - Document upload, OCR, validation, document APIs, basic UI flow.
3. Week 6-9: Module 2 delivery
   - Face match APIs, deepfake inference v1, liveness v1, threshold configs.
4. Week 10-12: Module 3 delivery
   - Decision engine, admin queue, review actions, notifications, reports.
5. Week 13-14: Security hardening
   - RBAC enforcement, encryption, rate limits, input sanitization, audit trails.
6. Week 15-16: Performance + reliability
   - profiling, async jobs, caching, retry strategy, backup strategy.
7. Week 17-18: Testing + documentation for submission
   - unit/integration/system tests, screenshots, report tables, viva rehearsal.

## 6) Deliverables checklist (what you should have at the end)

- Working app with user and admin portals
- Versioned REST API with Swagger/OpenAPI
- Model inference pipeline integrated with business workflow
- DB schema and migrations matching synopsis tables
- Test evidence:
  - unit tests,
  - API integration tests,
  - end-to-end happy path + failure path
- Generated sample outputs:
  - KYC PDF report,
  - audit logs,
  - analytics snapshots
- Submission-ready documentation mapped to IGNOU project report sections

## 7) Immediate next step (start here)

1. Freeze v1 scope exactly as in synopsis (no extra features).
2. Build a vertical slice first:
   - register/login -> upload one ID -> upload selfie -> face match -> decision -> admin review.
3. Once vertical slice works, expand document types, deepfake robustness, and reporting depth.
