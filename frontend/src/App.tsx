import { useState } from "react";
import type { DocumentResult, FaceMatchResult, DeepfakeResult, LivenessResult, FinalReportResult } from "./types";
import { useAuth } from "./hooks/useAuth";
import { ToastProvider, useToast } from "./contexts/ToastContext";

import LoginForm from "./components/auth/LoginForm";
import RegisterForm from "./components/auth/RegisterForm";
import WorkspaceHeader from "./components/layout/WorkspaceHeader";
import PipelineStepper from "./components/layout/PipelineStepper";
import OverviewScoreboard from "./components/dashboard/OverviewScoreboard";
import AnalyticsDashboard from "./components/dashboard/AnalyticsDashboard";
import OcrTab from "./components/pipeline/OcrTab";
import FaceMatchTab from "./components/pipeline/FaceMatchTab";
import DeepfakeTab from "./components/pipeline/DeepfakeTab";
import LivenessTab from "./components/pipeline/LivenessTab";
import FinalReportTab from "./components/pipeline/FinalReportTab";

function AppInner() {
  const { token, currentUser, login, register, logout, isLoggedIn } = useAuth();
  const { showToast } = useToast();
  const [rawOutput, setRawOutput] = useState("No API response yet.");
  const [authMessage, setAuthMessage] = useState("Login to start the eKYC flow.");
  const [isBusy, setIsBusy] = useState(false);

  const [documentResult, setDocumentResult] = useState<DocumentResult | null>(null);
  const [faceResult, setFaceResult] = useState<FaceMatchResult | null>(null);
  const [deepfakeResult, setDeepfakeResult] = useState<DeepfakeResult | null>(null);
  const [livenessResult, setLivenessResult] = useState<LivenessResult | null>(null);
  const [finalResult, setFinalResult] = useState<FinalReportResult | null>(null);

  const hasAllScores = documentResult !== null && faceResult !== null && deepfakeResult !== null && livenessResult !== null;
  const isAdminOrReviewer = currentUser?.role === "admin" || currentUser?.role === "reviewer";

  const handleLogin = async (identifier: string, password: string) => {
    setIsBusy(true);
    const err = await login(identifier, password);
    setIsBusy(false);
    if (err) { setAuthMessage(err); showToast(err, "error"); }
    else { setAuthMessage("Welcome!"); showToast("Logged in successfully.", "success"); }
  };

  const handleRegister = async (data: { full_name: string; email: string; phone: string; password: string }) => {
    setIsBusy(true);
    const err = await register(data);
    setIsBusy(false);
    if (err) { setAuthMessage(err); showToast(err, "error"); }
    else { setAuthMessage("Welcome!"); showToast("Registered and logged in.", "success"); }
  };

  const handleLogout = () => {
    logout();
    setDocumentResult(null);
    setFaceResult(null);
    setDeepfakeResult(null);
    setLivenessResult(null);
    setFinalResult(null);
    setRawOutput("No API response yet.");
    setAuthMessage("Logged out.");
  };

  const steps = [
    { number: 1, label: "OCR", done: documentResult !== null },
    { number: 2, label: "Face Match", done: faceResult !== null },
    { number: 3, label: "Deepfake", done: deepfakeResult !== null },
    { number: 4, label: "Liveness", done: livenessResult !== null },
    { number: 5, label: "Report", done: finalResult !== null },
  ];

  if (!isLoggedIn) {
    return (
      <main className="auth-page">
        <section className="auth-wrap">
          <div className="brand-card">
            <p className="eyebrow">MCA Final Project</p>
            <h1>AI-based Real-Time eKYC System</h1>
            <p className="subtext">
              Secure onboarding flow with OCR, face match, deepfake detection, liveness scoring, and final PDF report generation.
            </p>
            <div className="info-list">
              <div><strong>New here?</strong><span>Register with your name, email, and phone to get started.</span></div>
              <div><strong>Returning?</strong><span>Login using your email, phone, or full name.</span></div>
            </div>
          </div>
          <div className="auth-grid">
            <LoginForm onLogin={handleLogin} isBusy={isBusy} />
            <RegisterForm onRegister={handleRegister} isBusy={isBusy} />
          </div>
          <p className="message-line">{authMessage}</p>
        </section>
      </main>
    );
  }

  return (
    <main className="workspace-page">
      <WorkspaceHeader user={currentUser} onLogout={handleLogout} />

      {/* Pipeline progress stepper */}
      <PipelineStepper steps={steps} />

      {/* Scoreboard summary bar */}
      <OverviewScoreboard
        documentResult={documentResult}
        faceResult={faceResult}
        deepfakeResult={deepfakeResult}
        livenessResult={livenessResult}
        finalResult={finalResult}
      />

      {/* Section 1: Document OCR */}
      <section className="pipeline-section" id="section-ocr">
        <div className="section-header">
          <span className="section-badge">1</span>
          <h2>Document OCR + Forgery</h2>
        </div>
        <OcrTab token={token} result={documentResult}
          onResult={(r) => { setDocumentResult(r); setFinalResult(null); }}
          onRawOutput={setRawOutput} onNextTab={() => {}} />
      </section>

      {/* Section 2: Face Match */}
      <section className="pipeline-section" id="section-face">
        <div className="section-header">
          <span className="section-badge">2</span>
          <h2>Face Verification</h2>
        </div>
        <FaceMatchTab token={token} result={faceResult}
          referenceFaceImageUrl={documentResult?.reference_face_image_url ?? null}
          onResult={(r) => { setFaceResult(r); setFinalResult(null); }}
          onRawOutput={setRawOutput} onNextTab={() => {}} />
      </section>

      {/* Section 3: Deepfake */}
      <section className="pipeline-section" id="section-deepfake">
        <div className="section-header">
          <span className="section-badge">3</span>
          <h2>Deepfake Detection</h2>
        </div>
        <DeepfakeTab token={token} result={deepfakeResult}
          sharedLiveImageUrl={faceResult?.live_image_url ?? null}
          onResult={(r) => { setDeepfakeResult(r); setFinalResult(null); }}
          onRawOutput={setRawOutput} onNextTab={() => {}} />
      </section>

      {/* Section 4: Liveness */}
      <section className="pipeline-section" id="section-liveness">
        <div className="section-header">
          <span className="section-badge">4</span>
          <h2>Liveness Check</h2>
        </div>
        <LivenessTab token={token} result={livenessResult}
          sharedLiveImageUrl={faceResult?.live_image_url ?? null}
          onResult={(r) => { setLivenessResult(r); setFinalResult(null); }}
          onRawOutput={setRawOutput} onNextTab={() => {}} />
      </section>

      {/* Section 5: Final Report */}
      <section className="pipeline-section" id="section-final">
        <div className="section-header">
          <span className="section-badge">5</span>
          <h2>Final Decision + PDF Report</h2>
        </div>
        <FinalReportTab token={token} hasAllScores={hasAllScores} result={finalResult}
          onResult={setFinalResult} onRawOutput={setRawOutput} />
      </section>

      {/* Raw API Output — collapsible */}
      <details className="raw-output-details">
        <summary>Raw API Output</summary>
        <pre className="output">{rawOutput}</pre>
      </details>

      {/* Analytics (admin only) */}
      {isAdminOrReviewer && (
        <section className="pipeline-section" id="section-analytics">
          <div className="section-header">
            <span className="section-badge section-badge-admin">A</span>
            <h2>Analytics Dashboard</h2>
          </div>
          <AnalyticsDashboard token={token} />
        </section>
      )}
    </main>
  );
}

export default function App() {
  return (
    <ToastProvider>
      <AppInner />
    </ToastProvider>
  );
}
