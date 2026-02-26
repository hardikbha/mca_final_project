import { useState } from "react";
import type { FinalReportResult } from "../../types";
import { downloadReport, generateFinalReport, prettyJson } from "../../services/api";
import { useToast } from "../../contexts/ToastContext";
import LoadingSkeleton from "../shared/LoadingSkeleton";

type Props = {
  token: string;
  hasAllScores: boolean;
  result: FinalReportResult | null;
  onResult: (r: FinalReportResult) => void;
  onRawOutput: (s: string) => void;
};

export default function FinalReportTab({ token, hasAllScores, result, onResult, onRawOutput }: Props) {
  const [email, setEmail] = useState("hardik@example.com");
  const [busy, setBusy] = useState(false);
  const { showToast } = useToast();

  const generate = async () => {
    if (!hasAllScores) { showToast("Complete all 4 steps first.", "warning"); return; }
    setBusy(true);
    const res = await generateFinalReport(token, email);
    setBusy(false);
    if (res.error || !res.data) { showToast(res.error ?? "Report generation failed.", "error"); return; }
    onResult(res.data);
    onRawOutput(prettyJson(res.data));
    showToast("Final report generated.", "success");
  };

  const download = async () => {
    if (!result) return;
    setBusy(true);
    const blob = await downloadReport(token, result.report_download_url);
    setBusy(false);
    if (!blob) { showToast("Download failed.", "error"); return; }
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${result.report_id}.pdf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
    showToast("Report downloaded.", "success");
  };

  return (
    <div className="content-grid">
      <article className="panel">
        <p className="subtext">Combines all 4 modules: document forgery, face match, deepfake, and liveness.</p>
        <label>
          Destination Email
          <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="name@example.com" />
        </label>
        <button onClick={() => void generate()} className="btn primary" disabled={busy}>
          {busy ? "Generating..." : "Generate Final PDF"}
        </button>
        <button onClick={() => void download()} className="btn secondary" disabled={!result || busy}>
          Download Report PDF
        </button>
      </article>
      <article className="panel">
        <h3>Result</h3>
        {busy ? <LoadingSkeleton lines={8} /> : result ? (
          <div className="result-summary">
            <div className="result-row"><span>Decision</span><strong>{result.decision}</strong></div>
            <div className="result-row"><span>Final Score</span><strong>{result.scores.final_score}%</strong></div>
            <div className="result-row"><span>Report ID</span><strong>{result.report_id}</strong></div>
            <div className="result-row"><span>Email Status</span><strong>{result.email_delivery.status}</strong></div>
            <details className="collapsible-json">
              <summary>Full JSON Output</summary>
              <pre className="output">{prettyJson(result)}</pre>
            </details>
          </div>
        ) : <p className="subtext">No final report yet. Complete all steps and generate.</p>}
      </article>
    </div>
  );
}
