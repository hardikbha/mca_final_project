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
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileInputKey, setFileInputKey] = useState(0);
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
    setDocumentMessage("Token cleared. Login again to access document APIs.");
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
      } else if (!items.some((item) => item.document_id === selectedDocumentId)) {
        setSelectedDocumentId(items[0].document_id);
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

  const selectedDocument = documents.find((doc) => doc.document_id === selectedDocumentId) ?? null;
  const serviceEntries = Object.entries(status.services);
  const healthyServices = serviceEntries.filter(([, service]) => service.status === "ok").length;
  const processedDocuments = documents.filter((doc) => doc.ocr_extracted_data).length;
  const validDocuments = documents.filter((doc) => doc.ocr_extracted_data?.validation?.is_valid).length;
  const flaggedDocuments = documents.filter(
    (doc) => doc.ocr_extracted_data?.next_action === "manual_review_required"
  ).length;

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
            processing, validation and quality checks.
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
    </main>
  );
}

export default App;
