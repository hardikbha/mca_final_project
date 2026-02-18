# Frontend Framework for Step 4 and Step 5

This framework defines how the frontend is structured for document OCR and validation flow.

## 1) UI modules

1. `Auth Panel`
   - register/login
   - token management
2. `Document Intake Panel`
   - document type selector
   - document number input
   - file upload control
3. `Document Pipeline Table`
   - list all uploaded documents for logged-in user
   - show validation state (`Valid`, `Invalid`, `Not processed`)
   - show quality score (`0-100`)
   - actions: `Run OCR`, `View`
4. `Analysis Inspector`
   - engine info
   - processed timestamp
   - next action
   - validation JSON
   - quality JSON
   - extracted fields JSON

## 2) State model (React)

- `token`, `currentUser`
- `documents[]`
- `uploadForm` + selected `file`
- `processingDocumentId`
- `selectedDocumentId`
- status messages (`authMessage`, `documentMessage`)

## 3) API contract used by frontend

1. `POST /api/v1/auth/register`
2. `POST /api/v1/auth/login`
3. `GET /api/v1/auth/me`
4. `POST /api/v1/documents/upload`
5. `GET /api/v1/documents/my`
6. `POST /api/v1/documents/{document_id}/process`

## 4) User workflow

1. Login/Register
2. Upload document
3. Load documents
4. Click `Run OCR`
5. Click `View`
6. Inspect validation + quality output

## 5) Extension points for next phases

1. Replace current OCR extraction with model-backed OCR service.
2. Add confidence score UI and field-level correction controls.
3. Add face verification tab with score cards.
4. Add admin review screen for flagged documents.
