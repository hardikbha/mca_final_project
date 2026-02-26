export type TabKey = "overview" | "ocr" | "face" | "deepfake" | "liveness" | "final" | "analytics";

export type UserInfo = {
  user_id: string;
  full_name: string;
  email: string;
  phone: string;
  role: string;
  kyc_status: string;
  is_verified: boolean;
};

export type AuthResponse = {
  access_token: string;
  token_type: string;
  user: UserInfo;
};

export type DocumentResult = {
  stage: "document_ocr";
  file_name: string;
  document_image_url?: string;
  document_type: string;
  ocr_confidence: number;
  document_forgery_score: number;
  extracted_face_available: boolean;
  reference_face_image_url?: string;
  ocr_preview: string[];
  extracted_fields: Record<string, string>;
  timestamp: string;
};

export type FaceMatchResult = {
  stage: "face_match";
  reference_face_id: string;
  reference_document_type: string;
  reference_face_image_url?: string;
  live_image_name: string;
  live_image_url?: string;
  live_face_crop_image_url?: string;
  face_match_score: number;
  result: string;
  timestamp: string;
};

export type DeepfakeResult = {
  stage: "deepfake_detection";
  live_image_name: string;
  live_image_url?: string;
  input_source?: string;
  deepfake_score: number;
  authenticity_confidence: number;
  label: string;
  timestamp: string;
};

export type LivenessResult = {
  stage: "liveness_check";
  image_name: string;
  image_url?: string;
  input_source?: string;
  liveness_score: number;
  status: string;
  timestamp: string;
};

export type FinalReportResult = {
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

export type ToastType = "success" | "error" | "info" | "warning";

export type ToastItem = {
  id: number;
  message: string;
  type: ToastType;
};

export type AnalyticsOverview = {
  total_users: number;
  total_documents: number;
  total_sessions: number;
  approved_count: number;
  rejected_count: number;
  pending_count: number;
  under_review_count: number;
  flagged_sessions: number;
};

export type AnalyticsTrendDay = {
  date: string;
  approved: number;
  rejected: number;
  flagged: number;
};

export type AnalyticsLatencyStage = {
  stage: string;
  avg_ms: number;
  p95_ms: number;
};
