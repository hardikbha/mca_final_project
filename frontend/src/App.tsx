import { useMemo, useState } from "react";

type TabKey = "overview" | "ocr" | "face" | "deepfake" | "liveness" | "final";

type UserInfo = {
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
  user: UserInfo;
};

type DocumentResult = {
  stage: "document_ocr";
  file_name: string;
  document_type: string;
  ocr_confidence: number;
  document_forgery_score: number;
  extracted_face_available: boolean;
  ocr_preview: string[];
  extracted_fields: Record<string, string>;
  timestamp: string;
};

type FaceMatchResult = {
  stage: "face_match";
  reference_face_id: string;
  reference_document_type: string;
  live_image_name: string;
  face_match_score: number;
  result: string;
  timestamp: string;
};

type DeepfakeResult = {
  stage: "deepfake_detection";
  live_image_name: string;
  deepfake_score: number;
  authenticity_confidence: number;
  label: string;
  timestamp: string;
};

type LivenessResult = {
  stage: "liveness_check";
  image_name: string;
  liveness_score: number;
  status: string;
  timestamp: string;
};

type FinalReportResult = {
  stage: "final_decision";
  scores: {
    document_forgery_score: number;
    face_match_score: number;
    deepfake_score: number;
    liveness_score: number;
    final_score: number;
  };
  decision: string;
  report_id: string;
  report_download_url: string;
  email_delivery: {
    to: string;
    status: string;
    note: string;
  };
  generated_at: string;
};

const TABS: Array<{ key: TabKey; label: string; subtitle: string }> = [
  { key: "overview", label: "Overview", subtitle: "See all scores and pipeline status" },
  { key: "ocr", label: "Document OCR", subtitle: "Upload PDF/PNG/JPG and detect forgery risk" },
  { key: "face", label: "Face Match", subtitle: "Compare document face with live/uploaded face" },
  { key: "deepfake", label: "Deepfake", subtitle: "Analyze current shared image for deepfake risk" },
  { key: "liveness", label: "Liveness", subtitle: "Single image liveness confidence check" },
  { key: "final", label: "Final Report", subtitle: "Combine all four scores and generate PDF" }
];

const DOCUMENT_TYPES = ["aadhaar", "pan", "passport", "driving_license", "voter_id"] as const;

const readErrorMessage = (payload: unknown, fallback: string): string => {
  if (payload && typeof payload === "object" && "detail" in payload) {
    const detail = (payload as { detail?: unknown }).detail;
    if (typeof detail === "string" && detail.trim()) {
      return detail;
    }
  }
  return fallback;
};

const prettyJson = (payload: unknown): string => JSON.stringify(payload, null, 2);

function App() {
  const apiBase = useMemo(
    () => import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000",
    []
  );

  const [token, setToken] = useState<string>(() => localStorage.getItem("access_token") ?? "");
  const [currentUser, setCurrentUser] = useState<UserInfo | null>(null);
  const [activeTab, setActiveTab] = useState<TabKey>("overview");

  const [authMessage, setAuthMessage] = useState("Login to start the eKYC flow.");
  const [actionMessage, setActionMessage] = useState("Select a feature from the taskbar.");
  const [rawOutput, setRawOutput] = useState<string>("No API response yet.");
  const [isBusy, setIsBusy] = useState(false);

  const [loginForm, setLoginForm] = useState({ identifier: "hardik", password: "1234" });
  const [registerForm, setRegisterForm] = useState({
    full_name: "",
    email: "",
    phone: "",
    password: ""
  });

  const [documentType, setDocumentType] = useState<string>("aadhaar");
  const [destinationEmail, setDestinationEmail] = useState<string>("hardik@example.com");

  const [documentFile, setDocumentFile] = useState<File | null>(null);
  const [faceFile, setFaceFile] = useState<File | null>(null);
  const [deepfakeFile, setDeepfakeFile] = useState<File | null>(null);
  const [livenessFile, setLivenessFile] = useState<File | null>(null);

  const [documentResult, setDocumentResult] = useState<DocumentResult | null>(null);
  const [faceResult, setFaceResult] = useState<FaceMatchResult | null>(null);
  const [deepfakeResult, setDeepfakeResult] = useState<DeepfakeResult | null>(null);
  const [livenessResult, setLivenessResult] = useState<LivenessResult | null>(null);
  const [finalResult, setFinalResult] = useState<FinalReportResult | null>(null);

  const hasAllScores =
    documentResult !== null &&
    faceResult !== null &&
    deepfakeResult !== null &&
    livenessResult !== null;

  const saveToken = (accessToken: string) => {
    localStorage.setItem("access_token", accessToken);
    setToken(accessToken);
  };

  const clearPipelineState = () => {
    setDocumentFile(null);
    setFaceFile(null);
    setDeepfakeFile(null);
    setLivenessFile(null);
    setDocumentResult(null);
    setFaceResult(null);
    setDeepfakeResult(null);
    setLivenessResult(null);
    setFinalResult(null);
    setRawOutput("No API response yet.");
    setActionMessage("Select a feature from the taskbar.");
  };

  const logout = () => {
    localStorage.removeItem("access_token");
    setToken("");
    setCurrentUser(null);
    clearPipelineState();
    setAuthMessage("Logged out.");
  };

  const login = async () => {
    setIsBusy(true);
    setAuthMessage("");
    try {
      const response = await fetch(`${apiBase}/api/v1/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(loginForm)
      });
      const payload = (await response.json()) as unknown;
      if (!response.ok) {
        setAuthMessage(readErrorMessage(payload, "Login failed."));
        return;
      }
      const data = payload as AuthResponse;
      saveToken(data.access_token);
      setCurrentUser(data.user);
      clearPipelineState();
      setAuthMessage(`Welcome ${data.user.full_name}.`);
    } finally {
      setIsBusy(false);
    }
  };

  const register = async () => {
    setIsBusy(true);
    setAuthMessage("");
    try {
      const response = await fetch(`${apiBase}/api/v1/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(registerForm)
      });
      const payload = (await response.json()) as unknown;
      if (!response.ok) {
        setAuthMessage(readErrorMessage(payload, "Registration failed."));
        return;
      }
      setRegisterForm({
        full_name: "",
        email: "",
        phone: "",
        password: ""
      });
      setAuthMessage(
        "Registration successful. Now login with your registered email/phone and password."
      );
    } finally {
      setIsBusy(false);
    }
  };

  const runDocumentOcr = async () => {
    if (!token) {
      setActionMessage("Please login first.");
      return;
    }
    if (!documentFile) {
      setActionMessage("Please upload a document file first.");
      return;
    }

    setIsBusy(true);
    setActionMessage("Running OCR and document forgery scoring...");
    try {
      const formData = new FormData();
      formData.append("document_type", documentType);
      formData.append("document", documentFile);
      const response = await fetch(`${apiBase}/api/v1/features/document-ocr`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: formData
      });
      const payload = (await response.json()) as unknown;
      if (!response.ok) {
        setActionMessage(readErrorMessage(payload, "Document OCR failed."));
        return;
      }
      const data = payload as DocumentResult;
      setDocumentResult(data);
      setFinalResult(null);
      setRawOutput(prettyJson(payload));
      setActionMessage("Document step completed.");
      setActiveTab("face");
    } finally {
      setIsBusy(false);
    }
  };

  const runFaceMatch = async () => {
    if (!token) {
      setActionMessage("Please login first.");
      return;
    }
    if (!faceFile) {
      setActionMessage("Please upload a live/shared face image first.");
      return;
    }

    setIsBusy(true);
    setActionMessage("Running face match using document reference face...");
    try {
      const formData = new FormData();
      formData.append("live_face", faceFile);
      const response = await fetch(`${apiBase}/api/v1/features/face-match`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: formData
      });
      const payload = (await response.json()) as unknown;
      if (!response.ok) {
        setActionMessage(readErrorMessage(payload, "Face match failed."));
        return;
      }
      const data = payload as FaceMatchResult;
      setFaceResult(data);
      setFinalResult(null);
      setRawOutput(prettyJson(payload));
      setActionMessage("Face match step completed.");
      setActiveTab("deepfake");
    } finally {
      setIsBusy(false);
    }
  };

  const runDeepfake = async () => {
    if (!token) {
      setActionMessage("Please login first.");
      return;
    }
    if (!deepfakeFile) {
      setActionMessage("Please upload the image to check deepfake score.");
      return;
    }

    setIsBusy(true);
    setActionMessage("Running deepfake detection on current image...");
    try {
      const formData = new FormData();
      formData.append("live_image", deepfakeFile);
      const response = await fetch(`${apiBase}/api/v1/features/deepfake`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: formData
      });
      const payload = (await response.json()) as unknown;
      if (!response.ok) {
        setActionMessage(readErrorMessage(payload, "Deepfake check failed."));
        return;
      }
      const data = payload as DeepfakeResult;
      setDeepfakeResult(data);
      setFinalResult(null);
      setRawOutput(prettyJson(payload));
      setActionMessage("Deepfake step completed.");
      setActiveTab("liveness");
    } finally {
      setIsBusy(false);
    }
  };

  const runLiveness = async () => {
    if (!token) {
      setActionMessage("Please login first.");
      return;
    }
    if (!livenessFile) {
      setActionMessage("Please upload a single image for liveness.");
      return;
    }

    setIsBusy(true);
    setActionMessage("Running liveness analysis...");
    try {
      const formData = new FormData();
      formData.append("single_image", livenessFile);
      const response = await fetch(`${apiBase}/api/v1/features/liveness`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: formData
      });
      const payload = (await response.json()) as unknown;
      if (!response.ok) {
        setActionMessage(readErrorMessage(payload, "Liveness check failed."));
        return;
      }
      const data = payload as LivenessResult;
      setLivenessResult(data);
      setFinalResult(null);
      setRawOutput(prettyJson(payload));
      setActionMessage("Liveness step completed.");
      setActiveTab("final");
    } finally {
      setIsBusy(false);
    }
  };

  const generateFinalReport = async () => {
    if (!token) {
      setActionMessage("Please login first.");
      return;
    }
    if (!hasAllScores) {
      setActionMessage("Complete OCR, Face Match, Deepfake, and Liveness first.");
      return;
    }

    setIsBusy(true);
    setActionMessage("Generating final PDF report...");
    try {
      const response = await fetch(`${apiBase}/api/v1/features/final-report`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ email: destinationEmail })
      });
      const payload = (await response.json()) as unknown;
      if (!response.ok) {
        setActionMessage(readErrorMessage(payload, "Final report generation failed."));
        return;
      }
      const data = payload as FinalReportResult;
      setFinalResult(data);
      setRawOutput(prettyJson(payload));
      setActionMessage("Final report generated. You can download it now.");
    } finally {
      setIsBusy(false);
    }
  };

  const downloadReport = async () => {
    if (!token || !finalResult) {
      setActionMessage("No generated report available yet.");
      return;
    }

    setIsBusy(true);
    try {
      const response = await fetch(`${apiBase}${finalResult.report_download_url}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (!response.ok) {
        const payload = (await response.json().catch(() => ({}))) as unknown;
        setActionMessage(readErrorMessage(payload, "Unable to download report."));
        return;
      }
      const blob = await response.blob();
      const objectUrl = window.URL.createObjectURL(blob);
      const link = window.document.createElement("a");
      link.href = objectUrl;
      link.download = `${finalResult.report_id}.pdf`;
      window.document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(objectUrl);
      setActionMessage("Report downloaded.");
    } finally {
      setIsBusy(false);
    }
  };

  const renderAuthScreen = () => (
    <main className="auth-page">
      <section className="auth-wrap">
        <div className="brand-card">
          <p className="eyebrow">MCA Final Project</p>
          <h1>AI-based Real-Time eKYC System</h1>
          <p className="subtext">
            Secure onboarding flow with OCR, face match, deepfake detection, liveness scoring, and
            final PDF report generation.
          </p>
          <div className="info-list">
            <div>
              <strong>Admin Shortcut</strong>
              <span>
                login id: <code>hardik</code> | password: <code>1234</code>
              </span>
            </div>
            <div>
              <strong>New Users</strong>
              <span>Register first, then login using your email/phone.</span>
            </div>
          </div>
        </div>

        <div className="auth-grid">
          <article className="panel glass">
            <h2>Login</h2>
            <label>
              Login ID
              <input
                value={loginForm.identifier}
                onChange={(event) =>
                  setLoginForm((prev) => ({ ...prev, identifier: event.target.value }))
                }
              />
            </label>
            <label>
              Password
              <input
                type="password"
                value={loginForm.password}
                onChange={(event) =>
                  setLoginForm((prev) => ({ ...prev, password: event.target.value }))
                }
              />
            </label>
            <button onClick={() => void login()} className="btn primary" disabled={isBusy}>
              {isBusy ? "Please wait..." : "Login"}
            </button>
          </article>

          <article className="panel glass">
            <h2>Register</h2>
            <label>
              Full Name
              <input
                value={registerForm.full_name}
                onChange={(event) =>
                  setRegisterForm((prev) => ({ ...prev, full_name: event.target.value }))
                }
              />
            </label>
            <label>
              Email
              <input
                value={registerForm.email}
                onChange={(event) =>
                  setRegisterForm((prev) => ({ ...prev, email: event.target.value }))
                }
              />
            </label>
            <label>
              Phone
              <input
                value={registerForm.phone}
                onChange={(event) =>
                  setRegisterForm((prev) => ({ ...prev, phone: event.target.value }))
                }
              />
            </label>
            <label>
              Password
              <input
                type="password"
                value={registerForm.password}
                onChange={(event) =>
                  setRegisterForm((prev) => ({ ...prev, password: event.target.value }))
                }
              />
            </label>
            <button onClick={() => void register()} className="btn secondary" disabled={isBusy}>
              {isBusy ? "Please wait..." : "Register"}
            </button>
          </article>
        </div>

        <p className="message-line">{authMessage}</p>
      </section>
    </main>
  );

  const renderOverview = () => (
    <section className="content-grid">
      <article className="panel">
        <h2>Pipeline Scoreboard</h2>
        <div className="score-grid">
          <div className="score-box">
            <span>Document Forgery (risk)</span>
            <strong>{documentResult ? documentResult.document_forgery_score.toFixed(2) : "—"}</strong>
          </div>
          <div className="score-box">
            <span>Face Match</span>
            <strong>{faceResult ? faceResult.face_match_score.toFixed(2) : "—"}</strong>
          </div>
          <div className="score-box">
            <span>Deepfake (risk)</span>
            <strong>{deepfakeResult ? deepfakeResult.deepfake_score.toFixed(2) : "—"}</strong>
          </div>
          <div className="score-box">
            <span>Liveness</span>
            <strong>{livenessResult ? livenessResult.liveness_score.toFixed(2) : "—"}</strong>
          </div>
          <div className="score-box final">
            <span>Final Score</span>
            <strong>{finalResult ? finalResult.scores.final_score.toFixed(2) : "—"}</strong>
          </div>
        </div>
      </article>

      <article className="panel">
        <h2>Current Status</h2>
        <ul className="status-list">
          <li className={documentResult ? "done" : ""}>
            Document OCR: {documentResult ? "completed" : "pending"}
          </li>
          <li className={faceResult ? "done" : ""}>Face Match: {faceResult ? "completed" : "pending"}</li>
          <li className={deepfakeResult ? "done" : ""}>
            Deepfake: {deepfakeResult ? "completed" : "pending"}
          </li>
          <li className={livenessResult ? "done" : ""}>
            Liveness: {livenessResult ? "completed" : "pending"}
          </li>
          <li className={finalResult ? "done" : ""}>
            Final PDF: {finalResult ? `ready (${finalResult.report_id})` : "pending"}
          </li>
        </ul>
      </article>
    </section>
  );

  const renderOcrTab = () => (
    <section className="content-grid">
      <article className="panel">
        <h2>Document OCR + Forgery</h2>
        <p className="subtext">
          Upload a document. Accepted formats: PDF, PNG, JPG, JPEG, WEBP.
        </p>
        <label>
          Document Type
          <select value={documentType} onChange={(event) => setDocumentType(event.target.value)}>
            {DOCUMENT_TYPES.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>
        <label>
          Document File
          <input
            type="file"
            accept=".pdf,.png,.jpg,.jpeg,.webp"
            onChange={(event) => setDocumentFile(event.target.files?.[0] ?? null)}
          />
        </label>
        <button onClick={() => void runDocumentOcr()} className="btn primary" disabled={isBusy}>
          Run OCR
        </button>
      </article>

      <article className="panel">
        <h2>OCR Output</h2>
        <pre className="output">{documentResult ? prettyJson(documentResult) : "No result yet."}</pre>
      </article>
    </section>
  );

  const renderFaceTab = () => (
    <section className="content-grid">
      <article className="panel">
        <h2>Face Match</h2>
        <p className="subtext">
          Uses the face extracted from uploaded document and compares it with current live/shared image.
        </p>
        <label>
          Live/Selfie Face Image
          <input
            type="file"
            accept=".png,.jpg,.jpeg,.webp"
            capture="user"
            onChange={(event) => setFaceFile(event.target.files?.[0] ?? null)}
          />
        </label>
        <button onClick={() => void runFaceMatch()} className="btn primary" disabled={isBusy}>
          Run Face Match
        </button>
      </article>

      <article className="panel">
        <h2>Face Match Output</h2>
        <pre className="output">{faceResult ? prettyJson(faceResult) : "No result yet."}</pre>
      </article>
    </section>
  );

  const renderDeepfakeTab = () => (
    <section className="content-grid">
      <article className="panel">
        <h2>Deepfake Detection</h2>
        <p className="subtext">
          Upload the current image shared by the user. Backend returns deepfake risk and confidence.
        </p>
        <label>
          Current User Image
          <input
            type="file"
            accept=".png,.jpg,.jpeg,.webp"
            capture="user"
            onChange={(event) => setDeepfakeFile(event.target.files?.[0] ?? null)}
          />
        </label>
        <button onClick={() => void runDeepfake()} className="btn primary" disabled={isBusy}>
          Run Deepfake Check
        </button>
      </article>

      <article className="panel">
        <h2>Deepfake Output</h2>
        <pre className="output">{deepfakeResult ? prettyJson(deepfakeResult) : "No result yet."}</pre>
      </article>
    </section>
  );

  const renderLivenessTab = () => (
    <section className="content-grid">
      <article className="panel">
        <h2>Liveness Check</h2>
        <p className="subtext">Single image based liveness confidence scoring.</p>
        <label>
          Single Image
          <input
            type="file"
            accept=".png,.jpg,.jpeg,.webp"
            capture="user"
            onChange={(event) => setLivenessFile(event.target.files?.[0] ?? null)}
          />
        </label>
        <button onClick={() => void runLiveness()} className="btn primary" disabled={isBusy}>
          Run Liveness
        </button>
      </article>

      <article className="panel">
        <h2>Liveness Output</h2>
        <pre className="output">{livenessResult ? prettyJson(livenessResult) : "No result yet."}</pre>
      </article>
    </section>
  );

  const renderFinalTab = () => (
    <section className="content-grid">
      <article className="panel">
        <h2>Final Decision + PDF Report</h2>
        <p className="subtext">
          Final score uses all 4 modules: document forgery, face match, deepfake, and liveness.
        </p>
        <label>
          Destination Email
          <input
            value={destinationEmail}
            onChange={(event) => setDestinationEmail(event.target.value)}
            placeholder="name@example.com"
          />
        </label>
        <button onClick={() => void generateFinalReport()} className="btn primary" disabled={isBusy}>
          Generate Final PDF
        </button>
        <button
          onClick={() => void downloadReport()}
          className="btn secondary"
          disabled={!finalResult || isBusy}
        >
          Download Report PDF
        </button>
      </article>

      <article className="panel">
        <h2>Final Output</h2>
        <pre className="output">{finalResult ? prettyJson(finalResult) : "No final report yet."}</pre>
      </article>
    </section>
  );

  if (!token) {
    return renderAuthScreen();
  }

  return (
    <main className="workspace-page">
      <header className="workspace-header">
        <div>
          <p className="eyebrow">Authenticated Session</p>
          <h1>eKYC Verification Workbench</h1>
          <p className="subtext">
            Logged in as <strong>{currentUser?.full_name ?? "User"}</strong>
          </p>
        </div>
        <button onClick={logout} className="btn danger">
          Logout
        </button>
      </header>

      <nav className="taskbar">
        {TABS.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={tab.key === activeTab ? "task active" : "task"}
          >
            <span>{tab.label}</span>
            <small>{tab.subtitle}</small>
          </button>
        ))}
      </nav>

      <p className="message-line">{isBusy ? "Working..." : actionMessage}</p>

      {activeTab === "overview" && renderOverview()}
      {activeTab === "ocr" && renderOcrTab()}
      {activeTab === "face" && renderFaceTab()}
      {activeTab === "deepfake" && renderDeepfakeTab()}
      {activeTab === "liveness" && renderLivenessTab()}
      {activeTab === "final" && renderFinalTab()}

      <section className="panel">
        <h2>Latest Raw API Output</h2>
        <pre className="output">{rawOutput}</pre>
      </section>
    </main>
  );
}

export default App;
