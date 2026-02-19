type UsagePageProps = {
  onNavigate: (path: "/" | "/app" | "/usage") => void;
};

function UsagePage({ onNavigate }: UsagePageProps) {
  return (
    <main className="landing-shell usage-shell">
      <div className="ambient ambient-left" />
      <div className="ambient ambient-right" />

      <header className="landing-header">
        <p className="eyebrow">Usage Guide</p>
        <h1>Run and Test Flow</h1>
        <p className="landing-copy">
          Practical command sequence to run locally and test Step 2 to Step 6 endpoints quickly.
        </p>
      </header>

      <section className="usage-grid">
        <article className="usage-card">
          <h2>Start Stack</h2>
          <pre>{`cd /Users/hardiksharma/Downloads/final_project
docker compose up -d --build
docker compose ps`}</pre>
        </article>

        <article className="usage-card">
          <h2>Core URLs</h2>
          <pre>{`Frontend: http://localhost:5173
Backend Docs: http://localhost:8000/docs
Health: http://localhost:8000/health`}</pre>
        </article>

        <article className="usage-card">
          <h2>Auth + Document + OCR</h2>
          <pre>{`POST /api/v1/auth/register
POST /api/v1/auth/login
POST /api/v1/documents/upload
GET  /api/v1/documents/my
POST /api/v1/documents/{document_id}/process`}</pre>
        </article>

        <article className="usage-card">
          <h2>Face Verification (Step 6)</h2>
          <pre>{`POST /api/v1/verification-sessions/upload
GET  /api/v1/verification-sessions/my
GET  /api/v1/verification-sessions/{session_id}`}</pre>
        </article>
      </section>

      <div className="usage-actions">
        <a
          href="/"
          className="btn secondary"
          onClick={(event) => {
            event.preventDefault();
            onNavigate("/");
          }}
        >
          Back to Home
        </a>
        <a
          href="/app"
          className="btn"
          onClick={(event) => {
            event.preventDefault();
            onNavigate("/app");
          }}
        >
          Open Application
        </a>
      </div>
    </main>
  );
}

export default UsagePage;
