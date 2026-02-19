# How To Run

Use these steps in your own terminal to run the project and view the current progress.

## 1) Go to project folder

```bash
cd /Users/hardiksharma/Downloads/final_project
```

## 2) Make sure Docker engine is running

If you use Colima:

```bash
colima start
docker context use colima
```

Check:

```bash
docker --version
docker compose version
docker info
```

## 3) Start the full stack

```bash
docker compose down -v --remove-orphans
docker compose up -d --build
docker compose ps
```

## 4) Seed demo users (optional but recommended)

```bash
docker compose exec -T backend python scripts/seed_demo_data.py
```

## 5) Open the app

- Frontend: `http://localhost:5173`
- Backend docs: `http://localhost:8000/docs`

## 6) Quick verification commands

```bash
curl http://localhost:8000/health
curl http://localhost:8000/api/v1/system/status
```

Expected:
- `/health` should return `{"status":"ok"}`
- `/api/v1/system/status` should show `postgresql`, `mongodb`, and `redis` as `ok`

## 7) Test auth quickly from terminal

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"full_name":"Test User","email":"testuser@example.com","phone":"9876543210","password":"StrongPass@123"}'

curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"identifier":"testuser@example.com","password":"StrongPass@123"}'
```

You can also test register/login/me from the frontend auth panel at `http://localhost:5173`.

## 8) Test document upload APIs (Step 3)

Use a JWT token from register/login response:

```bash
TOKEN="<paste_access_token_here>"
```

Create a sample file and upload:

```bash
printf 'sample pdf content' > /tmp/step3_test.pdf

curl -X POST http://localhost:8000/api/v1/documents/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "document_type=pan" \
  -F "document_number=ABCDE1234F" \
  -F "file=@/tmp/step3_test.pdf;type=application/pdf"
```

List uploaded documents:

```bash
curl http://localhost:8000/api/v1/documents/my \
  -H "Authorization: Bearer $TOKEN"
```

You can do this from frontend too:
- Login in auth panel
- Go to `Document Processing Framework (Step 3, 4, 5)` panel
- Select document type, choose file, click upload, then load documents

## 9) Run Step 4/5 processing (OCR + validation + quality)

Take `document_id` from the upload/list response and process it:

```bash
DOC_ID="<paste_document_id_here>"

curl -X POST http://localhost:8000/api/v1/documents/$DOC_ID/process \
  -H "Authorization: Bearer $TOKEN"
```

After processing, call list again to see `ocr_extracted_data`:

```bash
curl http://localhost:8000/api/v1/documents/my \
  -H "Authorization: Bearer $TOKEN"
```

In frontend:
- click `Run OCR` for a document
- click `View`
- inspect `Validation`, `Quality`, `Extracted Fields` in `OCR + Validation Output (Step 4/5)`

## 10) Run Step 6 face verification

Create a sample selfie and run verification session:

```bash
printf 'fake image data for selfie' > /tmp/step6_selfie.jpg

curl -X POST http://localhost:8000/api/v1/verification-sessions/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "reference_document_id=$DOC_ID" \
  -F "selfie_file=@/tmp/step6_selfie.jpg;type=image/jpeg"
```

List verification sessions:

```bash
curl http://localhost:8000/api/v1/verification-sessions/my \
  -H "Authorization: Bearer $TOKEN"
```

In frontend:
- Go to `Face Verification Intake (Step 6)` panel
- Choose reference document (optional), upload selfie (and optional video)
- Click `Run Verification`
- Open `Face Verification Monitor` to inspect match/liveness/deepfake cards

## 11) Run Step 7 admin review

Login as seeded admin user:

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"identifier":"admin@ekyc.local","password":"AdminPass@123"}'
```

Set token from response:

```bash
ADMIN_TOKEN="<paste_admin_access_token_here>"
```

Load flagged queue:

```bash
curl http://localhost:8000/api/v1/admin/reviews/queue \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Review one flagged session:

```bash
FLAGGED_SESSION_ID="<paste_session_id_here>"

curl -X POST http://localhost:8000/api/v1/admin/reviews/$FLAGGED_SESSION_ID/decision \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"review_decision":"request_reupload","rejection_reason":"Selfie is unclear. Please upload again."}'
```

Frontend check:
- login as `admin@ekyc.local` / `AdminPass@123`
- open `Admin Review Queue (Step 7)`
- load queue, then click approve/reject/request re-upload

## 12) Stop everything

```bash
docker compose down
```

## 13) If something fails

Run:

```bash
docker compose ps
docker compose logs backend --tail=200
docker compose logs postgres --tail=120
docker compose logs mongodb --tail=120
docker compose logs redis --tail=120
```

Share those logs and I will fix it quickly.
