# Testing and Demo Plan

This plan aligns implementation with MCSP-232 evaluation expectations.

## 1) Testing layers

1. Unit tests
   - OCR parser utils
   - validators (Aadhaar/PAN/etc.)
   - score aggregation and decision policy
2. Integration tests
   - API + DB flows
   - file upload + storage + OCR extraction
   - face/deepfake/liveness pipeline invocation
3. System tests (end-to-end)
   - happy path auto-approval
   - flagged path requiring admin review
   - rejection + re-upload path

## 2) Minimum test evidence to keep

- `docs/test-cases/unit-tests.md`
- `docs/test-cases/integration-tests.md`
- `docs/test-cases/system-tests.md`
- API test export (Postman/Newman or pytest report)
- screenshots for key screens and outputs

## 3) Security test checklist

- AuthN/AuthZ checks (role-based endpoint access)
- input validation and invalid file rejection
- rate limit enforcement
- SQL injection and XSS sanity tests
- audit log entry creation on sensitive actions

## 4) Performance test checklist

- measure API latency for:
  - document processing,
  - face verification,
  - full decision pipeline
- capture p50/p95 response time and throughput
- validate target claims used in synopsis

## 5) Viva demo walkthrough (recommended)

1. Start stack using Docker Compose.
2. Show login and role separation (user vs admin).
3. User uploads document + selfie/video.
4. Show AI scores and auto decision.
5. Show flagged case in admin panel and manual decision.
6. Generate and download KYC report PDF.
7. Show audit logs and security controls.

## 6) Final acceptance criteria for your implementation

- All three core modules are functional.
- Threshold-based decision engine works exactly as documented.
- Admin review and reporting are demonstrable.
- Test evidence and executable are ready for viva.
