# Database Schema Dictionary

## users

- `user_id` (UUID, PK)
- `full_name` (varchar(255), required)
- `email` (varchar(255), unique, indexed)
- `phone` (varchar(15), unique, indexed)
- `password_hash` (varchar(255), required)
- `is_verified` (boolean)
- `kyc_status` (enum: pending/approved/rejected/under_review)
- `role` (enum: user/admin/reviewer)
- `created_at`, `updated_at` (timestamp tz)

## documents

- `document_id` (UUID, PK)
- `user_id` (UUID, FK -> users.user_id)
- `document_type` (enum)
- `document_number` (varchar(50), nullable)
- `file_path` (varchar(500))
- `ocr_extracted_data` (JSON, nullable)
- `upload_timestamp` (timestamp tz)
- `is_verified` (boolean)

## verification_sessions

- `session_id` (UUID, PK)
- `user_id` (UUID, FK -> users.user_id)
- `selfie_image_path` (varchar(500))
- `video_path` (varchar(500), nullable)
- `id_face_embedding` (JSON, nullable)
- `selfie_face_embedding` (JSON, nullable)
- `match_score` (float, check 0..100)
- `liveness_score` (float, check 0..100)
- `deepfake_probability` (float, check 0..100)
- `authenticity_label` (enum: real/fake)
- `quality_checks` (JSON)
- `timestamp` (timestamp tz)
- `status` (enum: pending/approved/rejected/flagged)
- `admin_reviewed` (boolean)

## admin_reviews

- `review_id` (UUID, PK)
- `session_id` (UUID, FK -> verification_sessions.session_id)
- `admin_id` (UUID, FK -> users.user_id, nullable)
- `review_decision` (enum: approved/rejected/request_reupload)
- `rejection_reason` (text, required when decision is rejected)
- `review_timestamp` (timestamp tz)

## audit_logs

- `log_id` (UUID, PK)
- `user_id` (UUID, FK -> users.user_id, nullable)
- `action` (varchar(100))
- `ip_address` (varchar(45), nullable)
- `user_agent` (text, nullable)
- `timestamp` (timestamp tz)
- `additional_data` (JSON, nullable)
