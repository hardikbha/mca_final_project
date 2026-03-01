# Security Control Matrix

| Control Area | Implemented | Evidence | Gap/Note |
|---|---|---|---|
| Password hashing | Yes | `app/core/security.py` uses bcrypt via passlib | Keep hash policy documented in report |
| JWT authentication | Yes | token create/decode and protected deps | Ensure strong production secret in deployment notes |
| Role-based authorization | Yes | reviewer/admin dependencies for sensitive routes | Add explicit role-access matrix in report |
| Input sanitization | Partial | `sanitize_string` usage in auth register | Expand to all user-input surfaces where needed |
| File upload validation | Yes | MIME, extension, size checks in routes | Add malware-scan mention if not implemented |
| Rate limiting | Yes | slowapi limiter on auth routes | Add empirical test evidence |
| CORS control | Yes | configured origins list | Lock down origin values for production |
| Audit logging | Partial | Mongo audit inserts for key actions | Add monitoring/retention policy details |
| Encryption in transit | Partial | architecture assumes HTTPS/TLS in deployment | No reverse-proxy TLS config in repo |
| Encryption at rest | Partial | not explicit in code-level storage implementation | document as deployment responsibility |
| Secret management | Partial | env vars supported | avoid default secret in production |
| OWASP controls | Partial | some controls present | complete threat model not documented |
