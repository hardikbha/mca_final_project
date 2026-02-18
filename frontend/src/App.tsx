import { ChangeEvent, useEffect, useMemo, useState } from "react";

type ServiceState = {
  status: "ok" | "error";
  detail: string;
};

type SystemStatus = {
  api: "ok" | "error";
  timestamp: string;
  services: {
    postgresql: ServiceState;
    mongodb: ServiceState;
    redis: ServiceState;
  };
};

type AuthUser = {
  user_id: string;
  full_name: string;
  email: string;
  phone: string;
  role: string;
  kyc_status: string;
  is_verified: boolean;
};

type AuthResponse = {
  access_token: string;
  token_type: string;
  user: AuthUser;
};

type OcrValidation = {
  document_type: string;
  declared_document_number?: string | null;
  normalized_document_number?: string | null;
  is_valid: boolean;
  source?: string;
  reason?: string;
};

type OcrQuality = {
  file_size_bytes: number;
  file_extension: string;
  text_length: number;
  score: number;
  status: string;
  warnings?: string[];
};

type OcrExtractedData = {
  engine: string;
  processed_at: string;
  raw_text_sample?: string;
  extracted_fields?: Record<string, string | null>;
  validation?: OcrValidation;
  quality?: OcrQuality;
  next_action?: string;
};

type DocumentResponse = {
  document_id: string;
  user_id: string;
  document_type: string;
  document_number: string | null;
  file_path: string;
  upload_timestamp: string;
  is_verified: boolean;
  ocr_extracted_data: OcrExtractedData | null;
};

type DocumentUploadResponse = {
  message: string;
  document: DocumentResponse;
};

type DocumentProcessResponse = {
  message: string;
  document: DocumentResponse;
};

type VerificationSessionResponse = {
  session_id: string;
  user_id: string;
  selfie_image_path: string;
  video_path: string | null;
  match_score: number | null;
  liveness_score: number | null;
  deepfake_probability: number | null;
  authenticity_label: "real" | "fake" | null;
  quality_checks: Record<string, unknown> | null;
  timestamp: string;
  status: "pending" | "approved" | "rejected" | "flagged";
  admin_reviewed: boolean;
};

type VerificationCreateResponse = {
  message: string;
  session: VerificationSessionResponse;
};

const DEFAULT_STATUS: SystemStatus = {
  api: "error",
  timestamp: "",
  services: {
    postgresql: { status: "error", detail: "not checked" },
    mongodb: { status: "error", detail: "not checked" },
    redis: { status: "error", detail: "not checked" }
  }
};

const DOCUMENT_TYPES = [
  "aadhaar",
  "pan",
  "passport",
  "driving_license",
  "voter_id",
  "bank_statement",
  "utility_bill"
] as const;

type DocumentType = (typeof DOCUMENT_TYPES)[number];

const getApiError = (payload: unknown, fallback: string): string => {
  if (!payload || typeof payload !== "object") {
    return fallback;
  }
  const detail = (payload as { detail?: unknown }).detail;
  if (typeof detail === "string") {
    return detail;
  }
  if (Array.isArray(detail)) {
    return detail
      .map((item) =>
        typeof item === "object" && item !== null && "msg" in item
          ? String((item as { msg: unknown }).msg)
          : String(item)
      )
      .join(", ");
  }
  return fallback;
};

function App() {
  const apiBase = useMemo(
    () => import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000",
    []
  );
  const [status, setStatus] = useState<SystemStatus>(DEFAULT_STATUS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [authMessage, setAuthMessage] = useState("");
  const [token, setToken] = useState<string>(() => localStorage.getItem("access_token") ?? "");
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null);
  const [documentMessage, setDocumentMessage] = useState("");
  const [documents, setDocuments] = useState<DocumentResponse[]>([]);
  const [isLoadingDocuments, setIsLoadingDocuments] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [processingDocumentId, setProcessingDocumentId] = useState("");
  const [selectedDocumentId, setSelectedDocumentId] = useState("");
  const [referenceDocumentId, setReferenceDocumentId] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileInputKey, setFileInputKey] = useState(0);
  const [verificationMessage, setVerificationMessage] = useState("");
  const [verificationSessions, setVerificationSessions] = useState<VerificationSessionResponse[]>(
    []
  );
  const [isLoadingVerificationSessions, setIsLoadingVerificationSessions] = useState(false);
  const [isCreatingVerification, setIsCreatingVerification] = useState(false);
  const [selectedVerificationSessionId, setSelectedVerificationSessionId] = useState("");
  const [selectedSelfieFile, setSelectedSelfieFile] = useState<File | null>(null);
  const [selectedVideoFile, setSelectedVideoFile] = useState<File | null>(null);
  const [selfieInputKey, setSelfieInputKey] = useState(0);
  const [videoInputKey, setVideoInputKey] = useState(0);
  const [uploadForm, setUploadForm] = useState<{
    document_type: DocumentType;
    document_number: string;
  }>({
    document_type: DOCUMENT_TYPES[0],
    document_number: ""
  });
  const [registerForm, setRegisterForm] = useState({
    full_name: "",
    email: "",
    phone: "",
    password: ""
  });
  const [loginForm, setLoginForm] = useState({
    identifier: "",
    password: ""
  });

  const loadStatus = async () => {
    setLoading(true);
    setError("");
    try {
      const response = await fetch(`${apiBase}/api/v1/system/status`);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const data = (await response.json()) as SystemStatus;
      setStatus(data);
    } catch (err) {
      const message = err instanceof Error ? err.message : "unknown error";
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const saveToken = (newToken: string) => {
    setToken(newToken);
    localStorage.setItem("access_token", newToken);
  };

  const clearToken = () => {
    setToken("");
    localStorage.removeItem("access_token");
    setCurrentUser(null);
    setDocuments([]);
    setSelectedDocumentId("");
    setReferenceDocumentId("");
    setVerificationSessions([]);
    setSelectedVerificationSessionId("");
    setSelectedSelfieFile(null);
    setSelectedVideoFile(null);
    setDocumentMessage("Token cleared. Login again to access document APIs.");
    setVerificationMessage("Token cleared. Login again to access verification APIs.");
  };

  const registerUser = async () => {
    setAuthMessage("");
    const response = await fetch(`${apiBase}/api/v1/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(registerForm)
    });
    const data = (await response.json()) as AuthResponse | { detail?: unknown };
    if (!response.ok) {
      throw new Error(getApiError(data, "Register failed"));
    }
    const authData = data as AuthResponse;
    saveToken(authData.access_token);
    setCurrentUser(authData.user);
    setAuthMessage("Registration successful.");
    await listMyDocuments(authData.access_token);
    await listMyVerificationSessions(authData.access_token);
  };

  const loginUser = async () => {
    setAuthMessage("");
    const response = await fetch(`${apiBase}/api/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(loginForm)
    });
    const data = (await response.json()) as AuthResponse | { detail?: unknown };
    if (!response.ok) {
      throw new Error(getApiError(data, "Login failed"));
    }
    const authData = data as AuthResponse;
    saveToken(authData.access_token);
    setCurrentUser(authData.user);
    setAuthMessage("Login successful.");
    await listMyDocuments(authData.access_token);
    await listMyVerificationSessions(authData.access_token);
  };

  const fetchMe = async () => {
    if (!token) {
      setAuthMessage("No token available. Login first.");
      return;
    }
    setAuthMessage("");
    const response = await fetch(`${apiBase}/api/v1/auth/me`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    const data = (await response.json()) as AuthUser | { detail?: unknown };
    if (!response.ok) {
      throw new Error(getApiError(data, "Could not fetch profile"));
    }
    setCurrentUser(data as AuthUser);
    setAuthMessage("Fetched current user profile.");
  };

  const listMyDocuments = async (tokenOverride?: string) => {
    const authToken = tokenOverride ?? token;
    if (!authToken) {
      setDocumentMessage("No token available. Login first.");
      setDocuments([]);
      return;
    }
    setIsLoadingDocuments(true);
    setDocumentMessage("");
    try {
      const response = await fetch(`${apiBase}/api/v1/documents/my`, {
        headers: { Authorization: `Bearer ${authToken}` }
      });
      const data = (await response.json()) as DocumentResponse[] | { detail?: unknown };
      if (!response.ok) {
        throw new Error(getApiError(data, "Could not fetch documents"));
      }
      const items = data as DocumentResponse[];
      setDocuments(items);
      if (items.length === 0) {
        setSelectedDocumentId("");
        setReferenceDocumentId("");
      } else if (!items.some((item) => item.document_id === selectedDocumentId)) {
        setSelectedDocumentId(items[0].document_id);
      }
      if (items.length > 0 && !items.some((item) => item.document_id === referenceDocumentId)) {
        setReferenceDocumentId(items[0].document_id);
      }
      setDocumentMessage("Document list loaded.");
    } catch (err) {
      setDocumentMessage(err instanceof Error ? err.message : "Could not fetch documents");
    } finally {
      setIsLoadingDocuments(false);
    }
  };

  const onFileChange = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0] ?? null;
    setSelectedFile(file);
  };

  const uploadDocument = async () => {
    if (!token) {
      setDocumentMessage("No token available. Login first.");
      return;
    }
    if (!selectedFile) {
      setDocumentMessage("Please choose a file before uploading.");
      return;
    }

    setIsUploading(true);
    setDocumentMessage("");
    try {
      const formData = new FormData();
      formData.append("document_type", uploadForm.document_type);
      if (uploadForm.document_number.trim()) {
        formData.append("document_number", uploadForm.document_number.trim());
      }
      formData.append("file", selectedFile);

      const response = await fetch(`${apiBase}/api/v1/documents/upload`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: formData
      });
      const data = (await response.json()) as DocumentUploadResponse | { detail?: unknown };
      if (!response.ok) {
        throw new Error(getApiError(data, "Document upload failed"));
      }

      setUploadForm((prev) => ({ ...prev, document_number: "" }));
      setSelectedFile(null);
      setFileInputKey((prev) => prev + 1);
      setDocumentMessage((data as DocumentUploadResponse).message);
      await listMyDocuments(token);
    } catch (err) {
      setDocumentMessage(err instanceof Error ? err.message : "Document upload failed");
    } finally {
      setIsUploading(false);
    }
  };

  const processDocument = async (documentId: string) => {
    if (!token) {
      setDocumentMessage("No token available. Login first.");
      return;
    }

    setProcessingDocumentId(documentId);
    setDocumentMessage("");
    try {
      const response = await fetch(`${apiBase}/api/v1/documents/${documentId}/process`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = (await response.json()) as DocumentProcessResponse | { detail?: unknown };
      if (!response.ok) {
        throw new Error(getApiError(data, "OCR processing failed"));
      }

      const processed = (data as DocumentProcessResponse).document;
      setDocuments((prev) =>
        prev.map((doc) => (doc.document_id === processed.document_id ? processed : doc))
      );
      setSelectedDocumentId(processed.document_id);
      setDocumentMessage((data as DocumentProcessResponse).message);
    } catch (err) {
      setDocumentMessage(err instanceof Error ? err.message : "OCR processing failed");
    } finally {
      setProcessingDocumentId("");
    }
  };

  const listMyVerificationSessions = async (tokenOverride?: string) => {
    const authToken = tokenOverride ?? token;
    if (!authToken) {
      setVerificationMessage("No token available. Login first.");
      setVerificationSessions([]);
      return;
    }
    setIsLoadingVerificationSessions(true);
    setVerificationMessage("");
    try {
      const response = await fetch(`${apiBase}/api/v1/verification-sessions/my`, {
        headers: { Authorization: `Bearer ${authToken}` }
      });
      const data = (await response.json()) as VerificationSessionResponse[] | { detail?: unknown };
      if (!response.ok) {
        throw new Error(getApiError(data, "Could not fetch verification sessions"));
      }
      const items = data as VerificationSessionResponse[];
      setVerificationSessions(items);
      if (items.length === 0) {
        setSelectedVerificationSessionId("");
      } else if (!items.some((item) => item.session_id === selectedVerificationSessionId)) {
        setSelectedVerificationSessionId(items[0].session_id);
      }
      setVerificationMessage("Verification sessions loaded.");
    } catch (err) {
      setVerificationMessage(
        err instanceof Error ? err.message : "Could not fetch verification sessions"
      );
    } finally {
      setIsLoadingVerificationSessions(false);
    }
  };

  const onSelfieChange = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0] ?? null;
    setSelectedSelfieFile(file);
  };

  const onVideoChange = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0] ?? null;
    setSelectedVideoFile(file);
  };

  const createVerificationSession = async () => {
    if (!token) {
      setVerificationMessage("No token available. Login first.");
      return;
    }
    if (!selectedSelfieFile) {
      setVerificationMessage("Please choose a selfie file before running verification.");
      return;
    }

    setIsCreatingVerification(true);
    setVerificationMessage("");
    try {
      const formData = new FormData();
      formData.append("selfie_file", selectedSelfieFile);
      if (selectedVideoFile) {
        formData.append("video_file", selectedVideoFile);
      }
      if (referenceDocumentId) {
        formData.append("reference_document_id", referenceDocumentId);
      }

      const response = await fetch(`${apiBase}/api/v1/verification-sessions/upload`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: formData
      });
      const data = (await response.json()) as VerificationCreateResponse | { detail?: unknown };
      if (!response.ok) {
        throw new Error(getApiError(data, "Verification session creation failed"));
      }
      const created = (data as VerificationCreateResponse).session;
      setVerificationSessions((prev) => [created, ...prev.filter((item) => item.session_id !== created.session_id)]);
      setSelectedVerificationSessionId(created.session_id);
      setSelectedSelfieFile(null);
      setSelectedVideoFile(null);
      setSelfieInputKey((prev) => prev + 1);
      setVideoInputKey((prev) => prev + 1);
      setVerificationMessage((data as VerificationCreateResponse).message);
    } catch (err) {
      setVerificationMessage(
        err instanceof Error ? err.message : "Verification session creation failed"
      );
    } finally {
      setIsCreatingVerification(false);
    }
  };

  const selectedDocument = documents.find((doc) => doc.document_id === selectedDocumentId) ?? null;
  const selectedVerificationSession =
    verificationSessions.find((session) => session.session_id === selectedVerificationSessionId) ??
    null;
  const serviceEntries = Object.entries(status.services);
  const healthyServices = serviceEntries.filter(([, service]) => service.status === "ok").length;
  const processedDocuments = documents.filter((doc) => doc.ocr_extracted_data).length;
  const validDocuments = documents.filter((doc) => doc.ocr_extracted_data?.validation?.is_valid).length;
  const flaggedDocuments = documents.filter(
    (doc) => doc.ocr_extracted_data?.next_action === "manual_review_required"
  ).length;
  const approvedSessions = verificationSessions.filter((session) => session.status === "approved").length;
  const flaggedSessions = verificationSessions.filter((session) => session.status === "flagged").length;

  const getQualityClass = (quality?: OcrQuality): string => {
    if (!quality) {
      return "status-neutral";
    }
    if (quality.status === "good") {
      return "status-ok";
    }
    if (quality.status === "poor") {
      return "status-bad";
    }
    return "status-warn";
  };

  useEffect(() => {
    void loadStatus();
  }, [apiBase]);

  useEffect(() => {
    if (!token) {
      return;
    }
    void listMyDocuments(token);
    void listMyVerificationSessions(token);
  }, [token]);

  return (
    <main className="page-shell">
      <div className="ambient ambient-left" />
      <div className="ambient ambient-right" />

      <header className="hero">
        <div>
          <p className="eyebrow">AI-Based Real-Time eKYC System</p>
          <h1>Verification Command Center</h1>
          <p className="hero-copy">
            This dashboard runs your complete current pipeline: auth, document upload, OCR
            processing, validation, quality checks and face verification scoring.
          </p>
        </div>

        <div className="hero-meta">
          <div className={`status-pill ${status.api === "ok" ? "status-ok" : "status-bad"}`}>
            Backend API: {status.api.toUpperCase()}
          </div>
          <div className="timestamp">
            Last check: {status.timestamp ? new Date(status.timestamp).toLocaleString() : "N/A"}
          </div>
          <button className="btn secondary" onClick={() => void loadStatus()} type="button">
            Refresh Health
          </button>
          {loading && <p className="muted">Refreshing service health...</p>}
        </div>
      </header>

      {error && <p className="error-text">Could not fetch backend status: {error}</p>}

      <section className="stats-grid">
        <article className="stat-card">
          <span>Service Health</span>
          <strong>
            {healthyServices}/{serviceEntries.length}
          </strong>
          <small>PostgreSQL, MongoDB, Redis</small>
        </article>
        <article className="stat-card">
          <span>Documents Uploaded</span>
          <strong>{documents.length}</strong>
          <small>Current logged-in user</small>
        </article>
        <article className="stat-card">
          <span>Documents Processed</span>
          <strong>{processedDocuments}</strong>
          <small>OCR + validation completed</small>
        </article>
        <article className="stat-card">
          <span>Flagged For Review</span>
          <strong>{flaggedDocuments}</strong>
          <small>Manual review required</small>
        </article>
      </section>

      <section className="services-grid">
        {serviceEntries.map(([name, service]) => (
          <article key={name} className="service-card">
            <h3>{name.toUpperCase()}</h3>
            <p className={`service-state ${service.status === "ok" ? "status-ok" : "status-bad"}`}>
              {service.status.toUpperCase()}
            </p>
            <p>{service.detail}</p>
          </article>
        ))}
      </section>

      <section className="workbench">
        <article className="panel">
          <div className="panel-head">
            <h2>Authentication</h2>
            <span className="panel-tag">Step 2</span>
          </div>
          <p className="muted">Register/login, then use token-secured APIs.</p>

          <div className="form-grid">
            <div className="form-box">
              <h3>Register</h3>
              <input
                placeholder="Full name"
                value={registerForm.full_name}
                onChange={(e) => setRegisterForm((prev) => ({ ...prev, full_name: e.target.value }))}
              />
              <input
                placeholder="Email"
                value={registerForm.email}
                onChange={(e) => setRegisterForm((prev) => ({ ...prev, email: e.target.value }))}
              />
              <input
                placeholder="Phone"
                value={registerForm.phone}
                onChange={(e) => setRegisterForm((prev) => ({ ...prev, phone: e.target.value }))}
              />
              <input
                type="password"
                placeholder="Password"
                value={registerForm.password}
                onChange={(e) => setRegisterForm((prev) => ({ ...prev, password: e.target.value }))}
              />
              <button
                className="btn"
                onClick={() => {
                  void registerUser().catch((err: unknown) =>
                    setAuthMessage(err instanceof Error ? err.message : "Register failed")
                  );
                }}
                type="button"
              >
                Register
              </button>
            </div>

            <div className="form-box">
              <h3>Login</h3>
              <input
                placeholder="Email or phone"
                value={loginForm.identifier}
                onChange={(e) => setLoginForm((prev) => ({ ...prev, identifier: e.target.value }))}
              />
              <input
                type="password"
                placeholder="Password"
                value={loginForm.password}
                onChange={(e) => setLoginForm((prev) => ({ ...prev, password: e.target.value }))}
              />
              <button
                className="btn"
                onClick={() => {
                  void loginUser().catch((err: unknown) =>
                    setAuthMessage(err instanceof Error ? err.message : "Login failed")
                  );
                }}
                type="button"
              >
                Login
              </button>
              <button
                className="btn secondary"
                onClick={() => {
                  void fetchMe().catch((err: unknown) =>
                    setAuthMessage(err instanceof Error ? err.message : "Fetch me failed")
                  );
                }}
                type="button"
              >
                Get Current User
              </button>
              <button className="btn danger" onClick={clearToken} type="button">
                Logout
              </button>
            </div>
          </div>

          <p className={authMessage ? "muted" : ""}>{authMessage || "No auth actions yet."}</p>

          <div className="code-box">
            <strong>Access Token</strong>
            <code>{token ? `${token.slice(0, 64)}...` : "Not set"}</code>
          </div>

          <div className="code-box">
            <strong>Current User</strong>
            <pre>{currentUser ? JSON.stringify(currentUser, null, 2) : "No user loaded."}</pre>
          </div>
        </article>

        <article className="panel">
          <div className="panel-head">
            <h2>Document Intake</h2>
            <span className="panel-tag">Step 3</span>
          </div>
          <p className="muted">Upload docs and load your current document queue.</p>

          <label htmlFor="documentType">Document Type</label>
          <select
            id="documentType"
            value={uploadForm.document_type}
            onChange={(e) =>
              setUploadForm((prev) => ({
                ...prev,
                document_type: e.target.value as DocumentType
              }))
            }
          >
            {DOCUMENT_TYPES.map((type) => (
              <option key={type} value={type}>
                {type}
              </option>
            ))}
          </select>

          <label htmlFor="documentNumber">Document Number (Optional)</label>
          <input
            id="documentNumber"
            placeholder="Enter document number"
            value={uploadForm.document_number}
            onChange={(e) => setUploadForm((prev) => ({ ...prev, document_number: e.target.value }))}
          />

          <label htmlFor="documentFile">Document File</label>
          <input
            key={fileInputKey}
            id="documentFile"
            type="file"
            accept=".jpg,.jpeg,.png,.pdf"
            onChange={onFileChange}
          />

          <div className="btn-row">
            <button className="btn" onClick={() => void uploadDocument()} type="button" disabled={isUploading}>
              {isUploading ? "Uploading..." : "Upload Document"}
            </button>
            <button
              className="btn secondary"
              onClick={() => void listMyDocuments()}
              type="button"
              disabled={isLoadingDocuments}
            >
              {isLoadingDocuments ? "Loading..." : "Load My Documents"}
            </button>
          </div>

          <div className="quick-kpis">
            <div>
              <small>Valid Docs</small>
              <strong>{validDocuments}</strong>
            </div>
            <div>
              <small>Need Review</small>
              <strong>{flaggedDocuments}</strong>
            </div>
          </div>
        </article>

        <article className="panel">
          <div className="panel-head">
            <h2>Face Verification Intake</h2>
            <span className="panel-tag">Step 6</span>
          </div>
          <p className="muted">
            Upload selfie (and optional liveness video) to generate face-match/deepfake/liveness
            placeholder scores.
          </p>

          <label htmlFor="referenceDocument">Reference Document</label>
          <select
            id="referenceDocument"
            value={referenceDocumentId}
            onChange={(e) => setReferenceDocumentId(e.target.value)}
          >
            <option value="">No reference document</option>
            {documents.map((doc) => (
              <option key={doc.document_id} value={doc.document_id}>
                {doc.document_type} | {doc.document_number || doc.document_id.slice(0, 8)}
              </option>
            ))}
          </select>

          <label htmlFor="selfieFile">Selfie Image (jpg/png)</label>
          <input
            key={selfieInputKey}
            id="selfieFile"
            type="file"
            accept=".jpg,.jpeg,.png"
            onChange={onSelfieChange}
          />

          <label htmlFor="videoFile">Liveness Video (optional mp4/mov/avi)</label>
          <input
            key={videoInputKey}
            id="videoFile"
            type="file"
            accept=".mp4,.mov,.avi"
            onChange={onVideoChange}
          />

          <div className="btn-row">
            <button
              className="btn"
              onClick={() => void createVerificationSession()}
              type="button"
              disabled={isCreatingVerification}
            >
              {isCreatingVerification ? "Running..." : "Run Verification"}
            </button>
            <button
              className="btn secondary"
              onClick={() => void listMyVerificationSessions()}
              type="button"
              disabled={isLoadingVerificationSessions}
            >
              {isLoadingVerificationSessions ? "Loading..." : "Load Sessions"}
            </button>
          </div>

          <div className="quick-kpis">
            <div>
              <small>Approved Sessions</small>
              <strong>{approvedSessions}</strong>
            </div>
            <div>
              <small>Flagged Sessions</small>
              <strong>{flaggedSessions}</strong>
            </div>
          </div>

          <p className={verificationMessage ? "muted" : ""}>
            {verificationMessage || "No verification actions yet."}
          </p>
        </article>
      </section>

      <section className="panel wide">
        <div className="panel-head">
          <h2>OCR Pipeline Monitor</h2>
          <span className="panel-tag">Step 4 / 5</span>
        </div>
        <p className="muted">Run OCR per document and inspect validation + quality outputs.</p>

        <div className="table-wrap">
          {documents.length === 0 ? (
            <p className="muted">No documents uploaded yet.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Number</th>
                  <th>Validation</th>
                  <th>Quality</th>
                  <th>Uploaded At</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {documents.map((doc) => (
                  <tr key={doc.document_id}>
                    <td>{doc.document_type}</td>
                    <td>{doc.document_number || "N/A"}</td>
                    <td>
                      {doc.ocr_extracted_data?.validation ? (
                        <span
                          className={
                            doc.ocr_extracted_data.validation.is_valid ? "status-ok" : "status-bad"
                          }
                        >
                          {doc.ocr_extracted_data.validation.is_valid ? "Valid" : "Invalid"}
                        </span>
                      ) : (
                        <span className="status-neutral">Not processed</span>
                      )}
                    </td>
                    <td>
                      <span className={getQualityClass(doc.ocr_extracted_data?.quality)}>
                        {doc.ocr_extracted_data?.quality
                          ? `${doc.ocr_extracted_data.quality.score}/100`
                          : "N/A"}
                      </span>
                    </td>
                    <td>{new Date(doc.upload_timestamp).toLocaleString()}</td>
                    <td>
                      <div className="row-actions">
                        <button
                          className="btn small"
                          type="button"
                          onClick={() => void processDocument(doc.document_id)}
                          disabled={processingDocumentId === doc.document_id}
                        >
                          {processingDocumentId === doc.document_id ? "Processing..." : "Run OCR"}
                        </button>
                        <button
                          className="btn secondary small"
                          type="button"
                          onClick={() => setSelectedDocumentId(doc.document_id)}
                        >
                          View
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="analysis-box">
          <h3>Analysis Inspector</h3>
          {!selectedDocument || !selectedDocument.ocr_extracted_data ? (
            <p className="muted">Select a document and run OCR to view detailed output.</p>
          ) : (
            <>
              <div className="analysis-grid">
                <div className="code-box">
                  <strong>Engine</strong>
                  <div>{selectedDocument.ocr_extracted_data.engine || "N/A"}</div>
                </div>
                <div className="code-box">
                  <strong>Processed At</strong>
                  <div>
                    {selectedDocument.ocr_extracted_data.processed_at
                      ? new Date(selectedDocument.ocr_extracted_data.processed_at).toLocaleString()
                      : "N/A"}
                  </div>
                </div>
                <div className="code-box">
                  <strong>Next Action</strong>
                  <div>{selectedDocument.ocr_extracted_data.next_action || "N/A"}</div>
                </div>
              </div>

              <div className="analysis-columns">
                <div className="code-box">
                  <strong>Validation</strong>
                  <pre>
                    {JSON.stringify(
                      selectedDocument.ocr_extracted_data.validation ?? "No validation output",
                      null,
                      2
                    )}
                  </pre>
                </div>

                <div className="code-box">
                  <strong>Quality</strong>
                  <pre>
                    {JSON.stringify(
                      selectedDocument.ocr_extracted_data.quality ?? "No quality output",
                      null,
                      2
                    )}
                  </pre>
                </div>

                <div className="code-box">
                  <strong>Extracted Fields</strong>
                  <pre>
                    {JSON.stringify(
                      selectedDocument.ocr_extracted_data.extracted_fields ?? "No extracted fields",
                      null,
                      2
                    )}
                  </pre>
                </div>
              </div>
            </>
          )}
        </div>

        <p className={documentMessage ? "muted" : ""}>
          {documentMessage || "No document actions yet."}
        </p>
      </section>

      <section className="panel wide">
        <div className="panel-head">
          <h2>Face Verification Monitor</h2>
          <span className="panel-tag">Step 6</span>
        </div>
        <p className="muted">
          Review verification sessions and check threshold pass/fail for match, liveness and deepfake risk.
        </p>

        <div className="table-wrap">
          {verificationSessions.length === 0 ? (
            <p className="muted">No verification sessions created yet.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Match</th>
                  <th>Liveness</th>
                  <th>Deepfake</th>
                  <th>Authenticity</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {verificationSessions.map((session) => (
                  <tr key={session.session_id}>
                    <td>{new Date(session.timestamp).toLocaleString()}</td>
                    <td>{session.match_score ?? "N/A"}</td>
                    <td>{session.liveness_score ?? "N/A"}</td>
                    <td>{session.deepfake_probability ?? "N/A"}</td>
                    <td>
                      <span
                        className={
                          session.authenticity_label === "real"
                            ? "status-ok"
                            : session.authenticity_label === "fake"
                              ? "status-bad"
                              : "status-neutral"
                        }
                      >
                        {session.authenticity_label ?? "N/A"}
                      </span>
                    </td>
                    <td>
                      <span
                        className={
                          session.status === "approved"
                            ? "status-ok"
                            : session.status === "flagged"
                              ? "status-bad"
                              : "status-neutral"
                        }
                      >
                        {session.status}
                      </span>
                    </td>
                    <td>
                      <button
                        className="btn secondary small"
                        type="button"
                        onClick={() => setSelectedVerificationSessionId(session.session_id)}
                      >
                        View
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="analysis-box">
          <h3>Verification Inspector</h3>
          {!selectedVerificationSession ? (
            <p className="muted">Select a session to inspect scores and quality checks.</p>
          ) : (
            <>
              <div className="score-grid">
                <div className="score-card">
                  <span>Face Match</span>
                  <strong>{selectedVerificationSession.match_score ?? "N/A"}</strong>
                  <small
                    className={
                      (selectedVerificationSession.match_score ?? 0) >= 80
                        ? "status-ok"
                        : "status-bad"
                    }
                  >
                    Threshold: &gt;= 80
                  </small>
                </div>
                <div className="score-card">
                  <span>Liveness</span>
                  <strong>{selectedVerificationSession.liveness_score ?? "N/A"}</strong>
                  <small
                    className={
                      (selectedVerificationSession.liveness_score ?? 0) >= 60
                        ? "status-ok"
                        : "status-bad"
                    }
                  >
                    Threshold: &gt;= 60
                  </small>
                </div>
                <div className="score-card">
                  <span>Deepfake Risk</span>
                  <strong>{selectedVerificationSession.deepfake_probability ?? "N/A"}</strong>
                  <small
                    className={
                      (selectedVerificationSession.deepfake_probability ?? 100) <= 30
                        ? "status-ok"
                        : "status-bad"
                    }
                  >
                    Threshold: &lt;= 30
                  </small>
                </div>
              </div>

              <div className="analysis-columns">
                <div className="code-box">
                  <strong>Session Metadata</strong>
                  <pre>
                    {JSON.stringify(
                      {
                        session_id: selectedVerificationSession.session_id,
                        authenticity_label: selectedVerificationSession.authenticity_label,
                        status: selectedVerificationSession.status,
                        admin_reviewed: selectedVerificationSession.admin_reviewed,
                        selfie_image_path: selectedVerificationSession.selfie_image_path,
                        video_path: selectedVerificationSession.video_path
                      },
                      null,
                      2
                    )}
                  </pre>
                </div>

                <div className="code-box">
                  <strong>Quality Checks</strong>
                  <pre>
                    {JSON.stringify(
                      selectedVerificationSession.quality_checks ?? "No quality checks found",
                      null,
                      2
                    )}
                  </pre>
                </div>

                <div className="code-box">
                  <strong>Decision Summary</strong>
                  <pre>
                    {JSON.stringify(
                      {
                        auto_approval_rule:
                          "match >= 80, liveness >= 60, deepfake_probability <= 30",
                        session_status: selectedVerificationSession.status,
                        decision:
                          selectedVerificationSession.status === "approved"
                            ? "Auto-approval criteria met"
                            : "Manual review recommended"
                      },
                      null,
                      2
                    )}
                  </pre>
                </div>
              </div>
            </>
          )}
        </div>
      </section>
    </main>
  );
}

export default App;
