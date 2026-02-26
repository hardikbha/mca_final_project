import { useEffect, useState } from "react";
import type { FaceMatchResult } from "../../types";
import { fetchProtectedBlob, prettyJson, runFaceMatch } from "../../services/api";
import { useToast } from "../../contexts/ToastContext";
import FileUpload from "../shared/FileUpload";
import LoadingSkeleton from "../shared/LoadingSkeleton";

type Props = {
  token: string;
  result: FaceMatchResult | null;
  referenceFaceImageUrl: string | null;
  onResult: (r: FaceMatchResult) => void;
  onRawOutput: (s: string) => void;
  onNextTab: () => void;
};

export default function FaceMatchTab({
  token,
  result,
  referenceFaceImageUrl,
  onResult,
  onRawOutput,
  onNextTab,
}: Props) {
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [selectedLivePreviewUrl, setSelectedLivePreviewUrl] = useState<string | null>(null);
  const [referencePreviewUrl, setReferencePreviewUrl] = useState<string | null>(null);
  const [processedLivePreviewUrl, setProcessedLivePreviewUrl] = useState<string | null>(null);
  const { showToast } = useToast();

  useEffect(() => {
    if (!file) {
      setSelectedLivePreviewUrl(null);
      return;
    }
    const objectUrl = URL.createObjectURL(file);
    setSelectedLivePreviewUrl(objectUrl);
    return () => URL.revokeObjectURL(objectUrl);
  }, [file]);

  useEffect(() => {
    let active = true;
    let objectUrl: string | null = null;
    setReferencePreviewUrl(null);

    const previewUrl = result?.reference_face_image_url ?? referenceFaceImageUrl;
    if (!previewUrl) return;

    void (async () => {
      const blob = await fetchProtectedBlob(token, previewUrl);
      if (!blob || !active) return;
      objectUrl = URL.createObjectURL(blob);
      setReferencePreviewUrl(objectUrl);
    })();

    return () => {
      active = false;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [result?.reference_face_image_url, referenceFaceImageUrl, token]);

  useEffect(() => {
    let active = true;
    let objectUrl: string | null = null;
    setProcessedLivePreviewUrl(null);

    const livePreviewUrl = result?.live_face_crop_image_url ?? result?.live_image_url;
    if (!livePreviewUrl) return;

    void (async () => {
      const blob = await fetchProtectedBlob(token, livePreviewUrl);
      if (!blob || !active) return;
      objectUrl = URL.createObjectURL(blob);
      setProcessedLivePreviewUrl(objectUrl);
    })();

    return () => {
      active = false;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [result?.live_face_crop_image_url, result?.live_image_url, token]);

  const run = async () => {
    if (!file) { showToast("Upload a face image first.", "warning"); return; }
    setBusy(true);
    const res = await runFaceMatch(token, file);
    setBusy(false);
    if (res.error || !res.data) { showToast(res.error ?? "Face match failed.", "error"); return; }
    onResult(res.data);
    onRawOutput(prettyJson(res.data));
    showToast("Face match completed.", "success");
    onNextTab();
  };

  return (
    <div className="content-grid">
      <article className="panel">
        <p className="subtext">Compare the face extracted from your document with a live/selfie image.</p>
        <div className="preview-card">
          <h4>Reference Face from OCR Step</h4>
          {referencePreviewUrl ? (
            <img src={referencePreviewUrl} alt="Reference face from OCR" className="preview-media" />
          ) : (
            <p className="subtext">Run Document OCR first to populate the extracted reference face.</p>
          )}
        </div>
        <FileUpload label="Live/Selfie Face Image" accept=".png,.jpg,.jpeg,.webp" onChange={setFile} capture="user" disabled={busy} />
        {selectedLivePreviewUrl && (
          <div className="preview-card">
            <h4>Uploaded Live/Selfie Image</h4>
            <img src={selectedLivePreviewUrl} alt="Live face input" className="preview-media" />
          </div>
        )}
        <button onClick={() => void run()} className="btn primary" disabled={busy}>
          {busy ? "Processing..." : "Run Face Match"}
        </button>
      </article>
      <article className="panel">
        <h3>Result</h3>
        {busy ? <LoadingSkeleton lines={5} /> : result ? (
          <div className="result-summary">
            <div className="result-row"><span>Match Score</span><strong>{result.face_match_score}%</strong></div>
            <div className="result-row"><span>Verdict</span><strong>{result.result}</strong></div>
            <div className="result-row"><span>Reference Doc</span><strong>{result.reference_document_type}</strong></div>
            <div className="preview-grid">
              <div className="preview-card">
                <h4>Reference Face (From OCR Step)</h4>
                {referencePreviewUrl ? (
                  <img src={referencePreviewUrl} alt="Reference face from document" className="preview-media" />
                ) : (
                  <p className="subtext">Run OCR first to get the extracted reference face.</p>
                )}
              </div>
              <div className="preview-card">
                <h4>Live Face Features Used for Match</h4>
                {processedLivePreviewUrl ? (
                  <img src={processedLivePreviewUrl} alt="Extracted live face used in matching" className="preview-media" />
                ) : selectedLivePreviewUrl ? (
                  <img src={selectedLivePreviewUrl} alt="Uploaded live face" className="preview-media" />
                ) : (
                  <p className="subtext">Upload a live/selfie image to compare.</p>
                )}
              </div>
            </div>
            <p className="preview-note">
              Face verification compares embeddings from the extracted document face and the extracted live-face crop.
            </p>
            <details className="collapsible-json">
              <summary>Full JSON Output</summary>
              <pre className="output">{prettyJson(result)}</pre>
            </details>
          </div>
        ) : <p className="subtext">No result yet. Run face match to see output.</p>}
      </article>
    </div>
  );
}
