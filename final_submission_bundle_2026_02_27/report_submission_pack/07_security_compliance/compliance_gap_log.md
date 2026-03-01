# Compliance Gap Log

| Gap ID | Observation | Severity | Closure action |
|---|---|---|---|
| GAP-01 | Email delivery still mock/log based | Medium | Integrate SES/SendGrid/Resend or document as limitation |
| GAP-02 | Document forgery score is heuristic | High | Integrate dedicated forgery classifier or justify as phase-2 |
| GAP-03 | External model dependency for critical inference | Medium | Add fallback, retry strategy, and reliability metrics |
| GAP-04 | Limited system/security test evidence | High | Add expanded test evidence and chapter with logs/screenshots |
| GAP-05 | Signed annexures not packaged in repo | High | Collect and add final signed docs in report PDF |
| GAP-06 | Production TLS/data-at-rest controls not evidenced | Medium | Document deployment architecture and key management |
