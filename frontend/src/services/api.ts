import type {
  AnalyticsLatencyStage,
  AnalyticsOverview,
  AnalyticsTrendDay,
  AuthResponse,
  DeepfakeResult,
  DocumentResult,
  FaceMatchResult,
  FinalReportResult,
  LivenessResult,
} from "../types";

export const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

export const readErrorMessage = (payload: unknown, fallback: string): string => {
  if (payload && typeof payload === "object" && "detail" in payload) {
    const detail = (payload as { detail?: unknown }).detail;
    if (typeof detail === "string" && detail.trim()) return detail;
  }
  return fallback;
};

export const prettyJson = (payload: unknown): string => JSON.stringify(payload, null, 2);

type ApiResult<T> = { data: T; error: null } | { data: null; error: string };

async function apiCall<T>(url: string, init: RequestInit): Promise<ApiResult<T>> {
  try {
    const response = await fetch(url, init);
    const payload = await response.json();
    if (!response.ok) return { data: null, error: readErrorMessage(payload, "Request failed.") };
    return { data: payload as T, error: null };
  } catch (err) {
    return { data: null, error: err instanceof Error ? err.message : "Network error." };
  }
}

export async function login(identifier: string, password: string): Promise<ApiResult<AuthResponse>> {
  return apiCall<AuthResponse>(`${API_BASE}/api/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ identifier, password }),
  });
}

export async function register(data: {
  full_name: string;
  email: string;
  phone: string;
  password: string;
}): Promise<ApiResult<AuthResponse>> {
  return apiCall<AuthResponse>(`${API_BASE}/api/v1/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
}

export async function runDocumentOcr(
  token: string,
  file: File,
  docType: string
): Promise<ApiResult<DocumentResult>> {
  const formData = new FormData();
  formData.append("document_type", docType);
  formData.append("document", file);
  return apiCall<DocumentResult>(`${API_BASE}/api/v1/features/document-ocr`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body: formData,
  });
}

export async function runFaceMatch(token: string, file: File): Promise<ApiResult<FaceMatchResult>> {
  const formData = new FormData();
  formData.append("live_face", file);
  return apiCall<FaceMatchResult>(`${API_BASE}/api/v1/features/face-match`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body: formData,
  });
}

export async function runDeepfake(token: string, file?: File): Promise<ApiResult<DeepfakeResult>> {
  if (file) {
    const formData = new FormData();
    formData.append("live_image", file);
    return apiCall<DeepfakeResult>(`${API_BASE}/api/v1/features/deepfake`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: formData,
    });
  }
  return apiCall<DeepfakeResult>(`${API_BASE}/api/v1/features/deepfake`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function runLiveness(token: string, file?: File): Promise<ApiResult<LivenessResult>> {
  if (file) {
    const formData = new FormData();
    formData.append("single_image", file);
    return apiCall<LivenessResult>(`${API_BASE}/api/v1/features/liveness`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: formData,
    });
  }
  return apiCall<LivenessResult>(`${API_BASE}/api/v1/features/liveness`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function generateFinalReport(
  token: string,
  email: string
): Promise<ApiResult<FinalReportResult>> {
  return apiCall<FinalReportResult>(`${API_BASE}/api/v1/features/final-report`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify({ email }),
  });
}

export async function downloadReport(token: string, url: string): Promise<Blob | null> {
  try {
    const response = await fetch(`${API_BASE}${url}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!response.ok) return null;
    return response.blob();
  } catch {
    return null;
  }
}

export async function fetchProtectedBlob(token: string, url: string): Promise<Blob | null> {
  const resolvedUrl = url.startsWith("http://") || url.startsWith("https://") ? url : `${API_BASE}${url}`;
  try {
    const response = await fetch(resolvedUrl, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!response.ok) return null;
    return response.blob();
  } catch {
    return null;
  }
}

export async function fetchAnalyticsOverview(token: string): Promise<ApiResult<AnalyticsOverview>> {
  return apiCall<AnalyticsOverview>(`${API_BASE}/api/v1/analytics/overview`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function fetchAnalyticsTrends(
  token: string
): Promise<ApiResult<{ data: AnalyticsTrendDay[] }>> {
  return apiCall<{ data: AnalyticsTrendDay[] }>(`${API_BASE}/api/v1/analytics/trends`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function fetchAnalyticsLatency(
  token: string
): Promise<ApiResult<{ stages: AnalyticsLatencyStage[] }>> {
  return apiCall<{ stages: AnalyticsLatencyStage[] }>(`${API_BASE}/api/v1/analytics/latency`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}
