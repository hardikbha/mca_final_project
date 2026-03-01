import { useEffect, useRef, useState } from "react";
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

  // ── Webcam state ───────────────────────────────────────────────
  const [webcamActive, setWebcamActive] = useState(false);
  const [stream, setStream] = useState<MediaStream | null>(null);
  const [capturedFromWebcam, setCapturedFromWebcam] = useState(false);
  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  // Cleanup stream on unmount
  useEffect(() => {
    return () => { stream?.getTracks().forEach(t => t.stop()); };
  }, [stream]);

  const startWebcam = async () => {
    try {
      const s = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "user", width: { ideal: 640 }, height: { ideal: 480 } },
      });
      setStream(s);
      setWebcamActive(true);
      // attach after React renders the video element
      requestAnimationFrame(() => {
        if (videoRef.current) {
          videoRef.current.srcObject = s;
          void videoRef.current.play();
        }
      });
    } catch {
      showToast("Could not access camera. Please allow camera permissions.", "error");
    }
  };

  const stopWebcam = () => {
    stream?.getTracks().forEach(t => t.stop());
    setStream(null);
    setWebcamActive(false);
  };

  const capturePhoto = () => {
    if (!videoRef.current || !canvasRef.current) return;
    const video = videoRef.current;
    const canvas = canvasRef.current;
    canvas.width = video.videoWidth || 640;
    canvas.height = video.videoHeight || 480;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.drawImage(video, 0, 0);
    canvas.toBlob(blob => {
      if (!blob) return;
      const captured = new File([blob], "webcam-selfie.jpg", { type: "image/jpeg" });
      setFile(captured);
      setCapturedFromWebcam(true);
      stopWebcam();
      showToast("Selfie captured successfully!", "success");
    }, "image/jpeg", 0.92);
  };
  // ──────────────────────────────────────────────────────────────

  useEffect(() => {
    if (!file) {
      setSelectedLivePreviewUrl(null);
      setCapturedFromWebcam(false);
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
    if (!file) { showToast("Provide a face image first (upload or capture).", "warning"); return; }
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
      {/* ── Left: Inputs ── */}
      <article className="panel">
        <p className="subtext">
          Compare the face extracted from your document with a live selfie.
          Upload an image <em>or</em> use your webcam to capture a photo in real time.
        </p>

        {/* Reference face */}
        <div className="preview-card">
          <h4>Reference Face — Extracted from Document (Step 1)</h4>
          {referencePreviewUrl ? (
            <img src={referencePreviewUrl} alt="Reference face from OCR" className="preview-media" />
          ) : (
            <p className="subtext">Run Document OCR first to populate the extracted reference face.</p>
          )}
        </div>

        {/* Webcam or file upload */}
        {webcamActive ? (
          <>
            <div className="webcam-feed-wrapper">
              <video ref={videoRef} className="webcam-video" autoPlay playsInline muted />
              <span className="webcam-live-badge">
                <span className="webcam-live-dot" />
                Live
              </span>
            </div>
            <div className="webcam-action-row">
              <button className="btn capture sm" onClick={capturePhoto}>
                📸 Capture Selfie
              </button>
              <button className="btn sm" onClick={stopWebcam}>
                Cancel
              </button>
            </div>
          </>
        ) : (
          <>
            <FileUpload
              label="Live / Selfie Image (upload file)"
              accept=".png,.jpg,.jpeg,.webp"
              onChange={f => { setFile(f); setCapturedFromWebcam(false); }}
              capture="user"
              disabled={busy}
            />
            <button
              className="btn webcam-toggle sm"
              onClick={() => void startWebcam()}
              disabled={busy}
            >
              📷 Use Webcam to Take a Selfie
            </button>
          </>
        )}

        {/* Hidden canvas used for snapshot */}
        <canvas ref={canvasRef} style={{ display: "none" }} />

        {/* Preview of the selected / captured image */}
        {selectedLivePreviewUrl && !webcamActive && (
          <div className="preview-card">
            <h4>
              {capturedFromWebcam ? "Webcam Capture — Ready to Submit" : "Uploaded Selfie Image"}
            </h4>
            <img src={selectedLivePreviewUrl} alt="Selected live face" className="preview-media" />
            {capturedFromWebcam && (
              <span className="webcam-captured-badge">
                ✓ Captured from webcam
              </span>
            )}
          </div>
        )}

        <button onClick={() => void run()} className="btn primary" disabled={busy || (!file && !webcamActive)}>
          {busy ? "Processing..." : "Run Face Match"}
        </button>
      </article>

      {/* ── Right: Result ── */}
      <article className="panel">
        <h3>Result</h3>
        {busy ? <LoadingSkeleton lines={5} /> : result ? (
          <div className="result-summary">
            <div className="result-row"><span>Match Score</span><strong>{result.face_match_score}%</strong></div>
            <div className="result-row"><span>Verdict</span><strong>{result.result}</strong></div>
            <div className="result-row"><span>Reference Doc</span><strong>{result.reference_document_type}</strong></div>
            <div className="preview-grid">
              <div className="preview-card">
                <h4>Reference Face (From Document)</h4>
                {referencePreviewUrl ? (
                  <img src={referencePreviewUrl} alt="Reference face from document" className="preview-media" />
                ) : (
                  <p className="subtext">Run OCR first to get the extracted reference face.</p>
                )}
              </div>
              <div className="preview-card">
                <h4>Live Face Crop Used for Match</h4>
                {processedLivePreviewUrl ? (
                  <img src={processedLivePreviewUrl} alt="Extracted live face used in matching" className="preview-media" />
                ) : selectedLivePreviewUrl ? (
                  <img src={selectedLivePreviewUrl} alt="Uploaded live face" className="preview-media" />
                ) : (
                  <p className="subtext">Upload or capture an image to compare.</p>
                )}
              </div>
            </div>
            <p className="preview-note">
              Face verification compares embeddings from the extracted document face and the live-face crop.
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
