# Software Requirements Specification (Implementation-Aligned)

## 1. Purpose

This SRS defines requirements for the implemented project: AI-Based Real-Time eKYC System for Deepfake-Free Identity Verification.

## 2. Product scope

The system performs digital identity verification using document processing, face matching, deepfake screening, liveness checks, automated decisioning, and admin review.

## 3. User classes

- End User: register, login, upload documents, perform verification, get status/report.
- Reviewer/Admin: review flagged sessions, decide approval/rejection/re-upload, view analytics.
- System Integrator (future): consume APIs for onboarding workflows.

## 4. Functional requirements

FR-01: User Registration/Login
- Register with `full_name`, `email`, `phone`, `password`.
- Login via email/phone/full name; fixed admin shortcut enabled for demo.
- JWT token issued on successful authentication.

FR-02: Document Upload
- Supported types: Aadhaar/PAN/Passport/DL/Voter ID.
- Allowed files: JPEG/PNG/PDF within configured size limit.

FR-03: Document Processing
- OCR extraction from image/PDF.
- Document number validation via type-specific patterns.
- Quality scoring and next-action recommendation.

FR-04: Face Matching
- Extract face from document and live image.
- Compare via external similarity model and return score.

FR-05: Deepfake Detection
- Run external deepfake model inference.
- Return deepfake risk score and confidence summary.

FR-06: Liveness Detection
- Run external liveness inference and return liveness score.

FR-07: Final Decision and Report
- Aggregate scores and assign decision (`approved` or `manual_review`).
- Generate downloadable PDF report.
- Trigger email handling (currently logged/mock).

FR-08: Verification Session APIs
- Create verification session with selfie/video.
- Persist session scores and status in DB.

FR-09: Admin Review
- List flagged sessions.
- Approve/reject/request re-upload with optional reason.
- Update user KYC status.

FR-10: Analytics
- Provide overview, trends, and latency endpoints for admin dashboard.

FR-11: Audit Logging
- Store auth/review actions into audit collection where available.

## 5. Non-functional requirements

NFR-01 Performance
- Target low-latency API responses for control endpoints.
- Model-dependent endpoints vary due to external inference APIs.

NFR-02 Security
- JWT auth, bcrypt password hashing, role-based route guards.
- Input sanitization and upload validation.
- Rate limiting via `slowapi`.

NFR-03 Reliability
- API health endpoint and service status endpoint.
- Dockerized multi-service deployment.

NFR-04 Maintainability
- Modular backend services and route separation.
- Typed frontend and backend schemas.

NFR-05 Portability
- Local run and Docker compose support.

## 6. External interface requirements

- REST API over HTTP/JSON + multipart uploads.
- Frontend SPA consuming backend APIs.
- External inference services (Gradio/HuggingFace).
- PostgreSQL/SQLite for structured data; MongoDB for audit logs; Redis for caching/rate limits.

## 7. Data requirements

Core entities:
- Users
- Documents
- VerificationSessions
- AdminReviews
- AuditLogs

Key constraints:
- Unique email/phone.
- Score range checks for match/liveness/deepfake.
- Review reason constraint on rejection.

## 8. Acceptance criteria (v1)

- Successful register/login/me flow.
- Document upload and process flow with stored OCR output.
- Face match/deepfake/liveness endpoints operational.
- Final report generation and download works.
- Admin queue and decision workflow operational.
- Automated tests pass in local environment.
