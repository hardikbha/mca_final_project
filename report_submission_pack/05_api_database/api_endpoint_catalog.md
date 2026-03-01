| Method | Path | Tags | Summary |
|---|---|---|---|
| GET | `/api/v1/admin/audit-logs` | audit | List Audit Logs |
| GET | `/api/v1/admin/reviews/queue` | admin-review | List Flagged Sessions For Review |
| POST | `/api/v1/admin/reviews/{session_id}/decision` | admin-review | Decide Flagged Session |
| GET | `/api/v1/analytics/latency` | analytics | Analytics Latency |
| GET | `/api/v1/analytics/overview` | analytics | Analytics Overview |
| GET | `/api/v1/analytics/trends` | analytics | Analytics Trends |
| POST | `/api/v1/auth/login` | auth | Login User |
| GET | `/api/v1/auth/me` | auth | Get Me |
| POST | `/api/v1/auth/register` | auth | Register User |
| GET | `/api/v1/documents/my` | documents | List My Documents |
| POST | `/api/v1/documents/upload` | documents | Upload Document |
| GET | `/api/v1/documents/{document_id}` | documents | Get Document Details |
| POST | `/api/v1/documents/{document_id}/process` | documents | Process Document |
| GET | `/api/v1/features/catalog` | features | Get Feature Catalog |
| POST | `/api/v1/features/deepfake` | features | Run Deepfake Detection |
| POST | `/api/v1/features/document-ocr` | features | Run Document Ocr |
| POST | `/api/v1/features/face-match` | features | Run Face Match |
| POST | `/api/v1/features/final-report` | features | Generate Final Report |
| GET | `/api/v1/features/images/{image_key}` | features | Get Pipeline Image |
| POST | `/api/v1/features/liveness` | features | Run Liveness Check |
| GET | `/api/v1/features/reports/{report_id}` | features | Download Report |
| GET | `/api/v1/features/state` | features | Get Pipeline State |
| GET | `/api/v1/system/status` | system | System Status |
| GET | `/api/v1/verification-sessions/my` | verification | List My Verification Sessions |
| POST | `/api/v1/verification-sessions/upload` | verification | Upload Verification Session |
| GET | `/api/v1/verification-sessions/{session_id}` | verification | Get Verification Session |
| GET | `/health` | system | Health |
