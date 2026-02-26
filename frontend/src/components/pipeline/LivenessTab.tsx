import { useEffect, useState } from "react";
import type { LivenessResult } from "../../types";
import { fetchProtectedBlob, prettyJson, runLiveness } from "../../services/api";
import { useToast } from "../../contexts/ToastContext";
import LoadingSkeleton from "../shared/LoadingSkeleton";

type Props = {
  token: string;
  sharedLiveImageUrl: string | null;
  result: LivenessResult | null;
  onResult: (r: LivenessResult) => void;
  onRawOutput: (s: string) => void;
  onNextTab: () => void;
};

export default function LivenessTab({
  token,
  sharedLiveImageUrl,
  result,
  onResult,
  onRawOutput,
  onNextTab,
}: Props) {
  const [busy, setBusy] = useState(false);
  const [selectedImagePreviewUrl, setSelectedImagePreviewUrl] = useState<string | null>(null);
  const [processedImagePreviewUrl, setProcessedImagePreviewUrl] = useState<string | null>(null);
  const { showToast } = useToast();

  useEffect(() => {
    let active = true;
    let objectUrl: string | null = null;
    setSelectedImagePreviewUrl(null);

    if (!sharedLiveImageUrl) return;

    void (async () => {
      const blob = await fetchProtectedBlob(token, sharedLiveImageUrl);
      if (!blob || !active) return;
      objectUrl = URL.createObjectURL(blob);
      setSelectedImagePreviewUrl(objectUrl);
    })();

    return () => {
      active = false;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [sharedLiveImageUrl, token]);

  useEffect(() => {
    let active = true;
    let objectUrl: string | null = null;
    setProcessedImagePreviewUrl(null);

    const imageUrl = result?.image_url;
    if (!imageUrl) return;

    void (async () => {
      const blob = await fetchProtectedBlob(token, imageUrl);
      if (!blob || !active) return;
      objectUrl = URL.createObjectURL(blob);
      setProcessedImagePreviewUrl(objectUrl);
    })();

    return () => {
      active = false;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [result?.image_url, token]);

  const run = async () => {
    if (!sharedLiveImageUrl) {
      showToast("Run face verification first. Liveness will reuse that selfie automatically.", "warning");
      return;
    }
    setBusy(true);
    const res = await runLiveness(token);
    setBusy(false);
    if (res.error || !res.data) { showToast(res.error ?? "Liveness check failed.", "error"); return; }
    onResult(res.data);
    onRawOutput(prettyJson(res.data));
    showToast("Liveness check completed.", "success");
    onNextTab();
  };

  return (
    <div className="content-grid">
      <article className="panel">
        <p className="subtext">Uses the same selfie/live image from Face Verification automatically.</p>
        <div className="preview-card">
          <h4>Selfie Reused from Face Verification</h4>
          {selectedImagePreviewUrl ? (
            <img src={selectedImagePreviewUrl} alt="Selfie reused for liveness detection" className="preview-media" />
          ) : (
            <p className="subtext">Run Face Verification first so this step can reuse that selfie.</p>
          )}
        </div>
        <button onClick={() => void run()} className="btn primary" disabled={busy || !sharedLiveImageUrl}>
          {busy ? "Processing..." : "Run Liveness"}
        </button>
      </article>
      <article className="panel">
        <h3>Result</h3>
        {busy ? <LoadingSkeleton lines={4} /> : result ? (
          <div className="result-summary">
            <div className="result-row"><span>Liveness Score</span><strong>{result.liveness_score}%</strong></div>
            <div className="result-row"><span>Status</span><strong>{result.status}</strong></div>
            <div className="preview-card">
              <h4>Image Processed by Liveness Model</h4>
              {processedImagePreviewUrl ? (
                <img src={processedImagePreviewUrl} alt="Processed liveness input" className="preview-media" />
              ) : selectedImagePreviewUrl ? (
                <img src={selectedImagePreviewUrl} alt="Selected liveness input" className="preview-media" />
              ) : (
                <p className="subtext">Upload an image to visualize what the model receives.</p>
              )}
            </div>
            <details className="collapsible-json">
              <summary>Full JSON Output</summary>
              <pre className="output">{prettyJson(result)}</pre>
            </details>
          </div>
        ) : <p className="subtext">No result yet. Run liveness check to see output.</p>}
      </article>
    </div>
  );
}
