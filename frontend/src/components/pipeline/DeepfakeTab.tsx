import { useEffect, useState } from "react";
import type { DeepfakeResult } from "../../types";
import { fetchProtectedBlob, prettyJson, runDeepfake } from "../../services/api";
import { useToast } from "../../contexts/ToastContext";
import LoadingSkeleton from "../shared/LoadingSkeleton";

type Props = {
  token: string;
  sharedLiveImageUrl: string | null;
  result: DeepfakeResult | null;
  onResult: (r: DeepfakeResult) => void;
  onRawOutput: (s: string) => void;
  onNextTab: () => void;
};

export default function DeepfakeTab({
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

    const livePreviewUrl = result?.live_image_url;
    if (!livePreviewUrl) return;

    void (async () => {
      const blob = await fetchProtectedBlob(token, livePreviewUrl);
      if (!blob || !active) return;
      objectUrl = URL.createObjectURL(blob);
      setProcessedImagePreviewUrl(objectUrl);
    })();

    return () => {
      active = false;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [result?.live_image_url, token]);

  const run = async () => {
    if (!sharedLiveImageUrl) {
      showToast("Run face verification first. Deepfake will reuse that selfie automatically.", "warning");
      return;
    }
    setBusy(true);
    const res = await runDeepfake(token);
    setBusy(false);
    if (res.error || !res.data) { showToast(res.error ?? "Deepfake check failed.", "error"); return; }
    onResult(res.data);
    onRawOutput(prettyJson(res.data));
    showToast("Deepfake detection completed.", "success");
    onNextTab();
  };

  return (
    <div className="content-grid">
      <article className="panel">
        <p className="subtext">Uses the same selfie/live image from Face Verification automatically.</p>
        <div className="preview-card">
          <h4>Selfie Reused from Face Verification</h4>
          {selectedImagePreviewUrl ? (
            <img src={selectedImagePreviewUrl} alt="Selfie reused for deepfake detection" className="preview-media" />
          ) : (
            <p className="subtext">Run Face Verification first so this step can reuse that selfie.</p>
          )}
        </div>
        <button onClick={() => void run()} className="btn primary" disabled={busy || !sharedLiveImageUrl}>
          {busy ? "Processing..." : "Run Deepfake Check"}
        </button>
      </article>
      <article className="panel">
        <h3>Result</h3>
        {busy ? <LoadingSkeleton lines={5} /> : result ? (
          <div className="result-summary">
            <div className="result-row"><span>Deepfake Risk</span><strong>{result.deepfake_score}%</strong></div>
            <div className="result-row"><span>Authenticity</span><strong>{result.authenticity_confidence}%</strong></div>
            <div className="result-row"><span>Label</span><strong>{result.label}</strong></div>
            <div className="preview-card">
              <h4>Image Sent for Deepfake Detection</h4>
              {processedImagePreviewUrl ? (
                <img src={processedImagePreviewUrl} alt="Processed deepfake input" className="preview-media" />
              ) : selectedImagePreviewUrl ? (
                <img src={selectedImagePreviewUrl} alt="Selected deepfake input" className="preview-media" />
              ) : (
                <p className="subtext">Upload an image to visualize the model input.</p>
              )}
            </div>
            <details className="collapsible-json">
              <summary>Full JSON Output</summary>
              <pre className="output">{prettyJson(result)}</pre>
            </details>
          </div>
        ) : <p className="subtext">No result yet. Run deepfake check to see output.</p>}
      </article>
    </div>
  );
}
