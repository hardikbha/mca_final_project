# System Design Specification

## 1. Architectural style

- Frontend: React + TypeScript SPA
- Backend: FastAPI REST service
- Data: PostgreSQL/SQLite + MongoDB + Redis
- Integration: external model APIs for face/deepfake/liveness

## 2. Module decomposition

1. Authentication Module
- Registration, login, JWT issuance, user retrieval

2. Document Module
- Upload, storage, OCR extraction, validation, quality scoring

3. Feature Pipeline Module
- Document OCR stage
- Face match stage
- Deepfake stage
- Liveness stage
- Final report stage

4. Verification Session Module
- Session creation with score persistence
- User session listing and retrieval

5. Admin Review Module
- Flagged queue retrieval
- Decision processing and status updates

6. Analytics Module
- Overview/trends/latency aggregation

7. Audit and Security Module
- Audit logging, rate limiting, sanitization, role checks

## 3. Decision engine logic

Inputs:
- `document_forgery_score` (risk)
- `face_match_score`
- `deepfake_score` (risk)
- `liveness_score`

Derived:
- `document_authenticity = 100 - document_forgery_score`
- `deepfake_authenticity = 100 - deepfake_score`
- `final_score = average(document_authenticity, face_match_score, deepfake_authenticity, liveness_score)`

Decision (current):
- Approved if all conditions true:
  - document_forgery <= 45
  - face_match >= 70
  - deepfake <= 40
  - liveness >= 65
  - final_score >= 70
- Else manual review.

## 4. Data integrity controls

- Enum constraints for role/status/document types.
- Check constraints for score ranges.
- FK constraints with cascade/set-null behavior.
- Input validation on MIME type and extension consistency.

## 5. Error handling strategy

- API returns explicit HTTP status and error details.
- External service failures mapped to gateway errors.
- Missing pipeline prerequisites return clear 400-level messages.

## 6. Deployment design

- Docker compose provisions postgres/mongodb/redis/backend/frontend.
- Backend performs health checks and DB migration handling.
- Frontend configured via `VITE_API_BASE_URL`.

## 7. Known design limitations

- Pipeline state for feature routes is in-memory (non-distributed persistence).
- Email delivery is log/mock, not real provider send.
- Some AI steps depend on external network services.
