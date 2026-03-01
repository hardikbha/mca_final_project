# Detailed Test Case Matrix (System + Negative Cases)

## Authentication

| ID | Scenario | Input | Expected | Status |
|---|---|---|---|---|
| AUTH-01 | Register valid user | full_name/email/phone/password | 201 + token | Pass |
| AUTH-02 | Duplicate registration | same email/phone | 409 conflict | Pass |
| AUTH-03 | Login valid fixed admin | hardik/1234 | 200 + admin role | Pass |
| AUTH-04 | Login invalid password | wrong password | 401 | Pass |
| AUTH-05 | Get profile without token | none | 401/403 | Pass |

## Document pipeline

| ID | Scenario | Input | Expected | Status |
|---|---|---|---|---|
| DOC-01 | Upload PAN image valid | JPG < 10MB | upload success | Pending manual evidence |
| DOC-02 | Upload unsupported MIME | TXT file | 400 invalid type | Pending |
| DOC-03 | Upload oversize file | >10MB | 413 payload too large | Pending |
| DOC-04 | Process uploaded document | valid document_id | OCR + validation payload | Pending |
| DOC-05 | Process missing file path | deleted file | 404 missing storage file | Pending |

## Face/deepfake/liveness

| ID | Scenario | Input | Expected | Status |
|---|---|---|---|---|
| BIO-01 | Face match without doc stage | selfie only | 400 run doc first | Pending |
| BIO-02 | Face match success | doc+live face | score + result | Pending |
| BIO-03 | Deepfake with uploaded image | live image | deepfake score output | Pending |
| BIO-04 | Liveness with default face image | no image after face stage | liveness score output | Pending |
| BIO-05 | External model timeout | forced network fail | 502 with error details | Pending |

## Decision/report

| ID | Scenario | Input | Expected | Status |
|---|---|---|---|---|
| DEC-01 | Final report missing steps | only auth | 400 missing stages | Pass |
| DEC-02 | Final report invalid email | malformed email | 400 invalid email | Pending |
| DEC-03 | Final report success | all stages complete | report id + PDF URL | Pending |

## Admin review

| ID | Scenario | Input | Expected | Status |
|---|---|---|---|---|
| ADM-01 | Queue list as admin | valid admin token | flagged sessions list | Pending |
| ADM-02 | Review non-flagged session | session status approved | 409 conflict | Pending |
| ADM-03 | Reject without reason | rejected + no reason | validation failure | Pending |
| ADM-04 | Approve flagged session | decision approved | session approved + user approved | Pending |

## Analytics and audit

| ID | Scenario | Input | Expected | Status |
|---|---|---|---|---|
| ANA-01 | Analytics overview | admin token | aggregate counts | Pending |
| ANA-02 | Analytics trends | admin token | 30-day data array | Pending |
| ANA-03 | Analytics latency | admin token | stage latency metrics | Pending |
| AUD-01 | Register/login action | normal auth flow | audit insert (if mongo active) | Pending |

## Security and validation

| ID | Scenario | Input | Expected | Status |
|---|---|---|---|---|
| SEC-01 | Access admin routes as user | user token | 403 | Pending |
| SEC-02 | JWT tampering | modified token | auth failure | Pending |
| SEC-03 | Rate-limit burst login | >10/min requests | throttling response | Pending |
| SEC-04 | Path traversal in image fetch | crafted key/path | blocked (404/400) | Pending |
