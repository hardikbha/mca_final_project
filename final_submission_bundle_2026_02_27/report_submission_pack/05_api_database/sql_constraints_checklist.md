# SQL Constraints and Integrity Checklist

Source: `backend/alembic/versions/20260218_0001_initial_schema.py`

## Unique constraints

- `users.email` unique
- `users.phone` unique

## Foreign key constraints

- `documents.user_id -> users.user_id` (`ON DELETE CASCADE`)
- `verification_sessions.user_id -> users.user_id` (`ON DELETE CASCADE`)
- `admin_reviews.session_id -> verification_sessions.session_id` (`ON DELETE CASCADE`)
- `admin_reviews.admin_id -> users.user_id` (`ON DELETE SET NULL`)
- `audit_logs.user_id -> users.user_id` (`ON DELETE SET NULL`)

## Check constraints

- `verification_sessions.match_score BETWEEN 0 AND 100`
- `verification_sessions.liveness_score BETWEEN 0 AND 100`
- `verification_sessions.deepfake_probability BETWEEN 0 AND 100`
- `admin_reviews.review_decision != 'rejected' OR rejection_reason IS NOT NULL`

## Indexed fields

- `users.email`, `users.phone`
- `documents.user_id`
- `verification_sessions.user_id`
- `admin_reviews.session_id`, `admin_reviews.admin_id`
- `audit_logs.timestamp`, `audit_logs.user_id`
