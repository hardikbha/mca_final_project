import { useEffect, useState } from "react";
import type { DocumentResult } from "../../types";
import { fetchProtectedBlob, prettyJson, runDocumentOcr } from "../../services/api";
import { useToast } from "../../contexts/ToastContext";
import FileUpload from "../shared/FileUpload";
import LoadingSkeleton from "../shared/LoadingSkeleton";

const DOCUMENT_TYPES = ["aadhaar", "pan", "passport", "driving_license", "voter_id"] as const;

type Props = {
  token: string;
  result: DocumentResult | null;
  onResult: (r: DocumentResult) => void;
  onRawOutput: (s: string) => void;
  onNextTab: () => void;
};

export default function OcrTab({ token, result, onResult, onRawOutput, onNextTab }: Props) {
  const [file, setFile] = useState<File | null>(null);
  const [docType, setDocType] = useState("aadhaar");
  const [busy, setBusy] = useState(false);
  const [selectedDocumentPreviewUrl, setSelectedDocumentPreviewUrl] = useState<string | null>(null);
  const [processedDocumentPreviewUrl, setProcessedDocumentPreviewUrl] = useState<string | null>(null);
  const [referenceFacePreviewUrl, setReferenceFacePreviewUrl] = useState<string | null>(null);
  const { showToast } = useToast();

  useEffect(() => {
    if (!file) {
      setSelectedDocumentPreviewUrl(null);
      return;
    }
    const objectUrl = URL.createObjectURL(file);
    setSelectedDocumentPreviewUrl(objectUrl);
    return () => URL.revokeObjectURL(objectUrl);
  }, [file]);

  useEffect(() => {
    let active = true;
    let objectUrl: string | null = null;
    setProcessedDocumentPreviewUrl(null);

    const documentImageUrl = result?.document_image_url;
    if (!documentImageUrl) return;

    void (async () => {
      const blob = await fetchProtectedBlob(token, documentImageUrl);
      if (!blob || !active) return;
      objectUrl = URL.createObjectURL(blob);
      setProcessedDocumentPreviewUrl(objectUrl);
    })();

    return () => {
      active = false;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [result?.document_image_url, token]);

  useEffect(() => {
    let active = true;
    let objectUrl: string | null = null;
    setReferenceFacePreviewUrl(null);

    const referenceImageUrl = result?.reference_face_image_url;
    if (!referenceImageUrl) return;

    void (async () => {
      const blob = await fetchProtectedBlob(token, referenceImageUrl);
      if (!blob || !active) return;
      objectUrl = URL.createObjectURL(blob);
      setReferenceFacePreviewUrl(objectUrl);
    })();

    return () => {
      active = false;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [result?.reference_face_image_url, token]);

  const run = async () => {
    if (!file) { showToast("Upload a document file first.", "warning"); return; }
    setBusy(true);
    const res = await runDocumentOcr(token, file, docType);
    setBusy(false);
    if (res.error || !res.data) { showToast(res.error ?? "OCR failed.", "error"); return; }
    onResult(res.data);
    onRawOutput(prettyJson(res.data));
    showToast("Document OCR completed.", "success");
    onNextTab();
  };

  const selectedFileIsPdf = file?.type === "application/pdf";

  return (
    <div className="content-grid">
      <article className="panel">
        <p className="subtext">Upload a document. Accepted formats: PDF, PNG, JPG, JPEG, WEBP.</p>
        <label>
          Document Type
          <select value={docType} onChange={(e) => setDocType(e.target.value)}>
            {DOCUMENT_TYPES.map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
        </label>
        <FileUpload label="Document File" accept=".pdf,.png,.jpg,.jpeg,.webp" onChange={setFile} disabled={busy} />
        {selectedDocumentPreviewUrl && (
          <div className="preview-card">
            <h4>Uploaded Document</h4>
            {selectedFileIsPdf ? (
              <iframe src={selectedDocumentPreviewUrl} title="Uploaded document preview" className="preview-pdf" />
            ) : (
              <img src={selectedDocumentPreviewUrl} alt="Uploaded document" className="preview-media" />
            )}
          </div>
        )}
        <button onClick={() => void run()} className="btn primary" disabled={busy}>
          {busy ? "Processing..." : "Run OCR"}
        </button>
      </article>
      <article className="panel">
        <h3>Result</h3>
        {busy ? <LoadingSkeleton lines={6} /> : result ? (
          <div className="result-summary">
            <div className="result-row"><span>Engine</span><strong>{(result as any).engine ?? "N/A"}</strong></div>
            <div className="result-row"><span>OCR Confidence</span><strong>{(result.ocr_confidence * 100).toFixed(1)}%</strong></div>
            <div className="result-row"><span>Forgery Risk</span><strong>{result.document_forgery_score}%</strong></div>
            <div className="result-row"><span>Face Extracted</span><strong>{result.extracted_face_available ? "Yes" : "No"}</strong></div>
            <div className="preview-grid">
              <div className="preview-card">
                <h4>Document Used for OCR + Forgery</h4>
                {processedDocumentPreviewUrl ? (
                  <img src={processedDocumentPreviewUrl} alt="Processed document" className="preview-media" />
                ) : selectedDocumentPreviewUrl ? (
                  selectedFileIsPdf ? (
                    <iframe src={selectedDocumentPreviewUrl} title="Document preview" className="preview-pdf" />
                  ) : (
                    <img src={selectedDocumentPreviewUrl} alt="Selected document" className="preview-media" />
                  )
                ) : (
                  <p className="subtext">Document preview will appear after you upload a file.</p>
                )}
              </div>
              <div className="preview-card">
                <h4>Extracted Face from Document</h4>
                {referenceFacePreviewUrl ? (
                  <img src={referenceFacePreviewUrl} alt="Extracted reference face" className="preview-media" />
                ) : (
                  <p className="subtext">Run OCR to see the extracted reference face.</p>
                )}
              </div>
            </div>
            <p className="preview-note">
              The extracted face above is used as the reference image in Face Verification (Step 2).
            </p>
            <details className="collapsible-json">
              <summary>Full JSON Output</summary>
              <pre className="output">{prettyJson(result)}</pre>
            </details>
          </div>
        ) : <p className="subtext">No result yet. Run OCR to see output.</p>}
      </article>
    </div>
  );
}
