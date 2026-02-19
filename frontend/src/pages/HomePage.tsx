type HomePageProps = {
  onNavigate: (path: "/" | "/app" | "/usage") => void;
};

function HomePage({ onNavigate }: HomePageProps) {
  return (
    <main className="landing-shell">
      <div className="ambient ambient-left" />
      <div className="ambient ambient-right" />

      <header className="landing-header">
        <p className="eyebrow">MCA Final Project</p>
        <h1>AI-Based Real-Time eKYC System</h1>
        <p className="landing-copy">
          Choose where you want to go. This home page separates application workbench, API usage,
          and quick command flow.
        </p>
      </header>

      <section className="mission-grid">
        <a
          href="/app"
          className="mission-card mission-primary"
          onClick={(event) => {
            event.preventDefault();
            onNavigate("/app");
          }}
        >
          <span className="mission-tag">Application</span>
          <h2>Open Verification Workspace</h2>
          <p>
            Use auth, document OCR, face verification, score cards, and pipeline monitor in one
            place.
          </p>
          <span className="mission-link">Go to App &rarr;</span>
        </a>

        <a
          href="/usage"
          className="mission-card mission-secondary"
          onClick={(event) => {
            event.preventDefault();
            onNavigate("/usage");
          }}
        >
          <span className="mission-tag">Usage</span>
          <h2>API and Run Guide</h2>
          <p>
            View terminal commands, endpoint map, and practical sequence to test each module step.
          </p>
          <span className="mission-link">Open Usage &rarr;</span>
        </a>

        <a href="http://localhost:8000/docs" target="_blank" rel="noreferrer" className="mission-card mission-neutral">
          <span className="mission-tag">Swagger</span>
          <h2>Open API Docs</h2>
          <p>
            Check live request/response contracts from FastAPI OpenAPI docs on your local backend.
          </p>
          <span className="mission-link">Open Docs &rarr;</span>
        </a>
      </section>
    </main>
  );
}

export default HomePage;
