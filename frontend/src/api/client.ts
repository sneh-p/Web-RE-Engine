import type {
  AiExplanation,
  AnalysisJob,
  ApiResponse,
  ExplainScope,
  EngineStatus,
  BrowserInput,
  EvmInput,
} from '@shared/types.js';

const API_BASE = '/api';

let onUnauthorizedHandler: (() => void) | null = null;

export function setOnUnauthorized(handler: () => void) {
  onUnauthorizedHandler = handler;
}

export async function apiFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const res = await fetch(input, init);
  if (res.status === 401) {
    if (onUnauthorizedHandler) {
      onUnauthorizedHandler();
    }
  }
  return res;
}

export interface AuthInfo {
  authenticated: boolean;
  authConfigured: boolean;
}

export async function fetchAuthMe(): Promise<AuthInfo> {
  const res = await fetch(`${API_BASE}/auth/me`);
  if (!res.ok) {
    if (res.status === 503) {
      return { authenticated: false, authConfigured: false };
    }
  }
  const json = await res.json().catch(() => ({}));
  const data = json.data ?? json;
  return {
    authenticated: Boolean(data.authenticated),
    authConfigured: data.authConfigured !== undefined ? Boolean(data.authConfigured) : true,
  };
}

export async function loginAdmin(password: string): Promise<void> {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password }),
  });

  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(json.error || 'Login failed');
  }
}

export async function logoutAdmin(): Promise<void> {
  await fetch(`${API_BASE}/auth/logout`, {
    method: 'POST',
  });
}

export async function fetchStatus(): Promise<EngineStatus> {
  const res = await apiFetch(`${API_BASE}/status`);
  const json: ApiResponse<EngineStatus> = await res.json();
  if (!json.success || !json.data) throw new Error(json.error || 'Failed to fetch status');
  return json.data;
}

export async function fetchJobs(): Promise<AnalysisJob[]> {
  const res = await apiFetch(`${API_BASE}/jobs`);
  const json: ApiResponse<AnalysisJob[]> = await res.json();
  if (!json.success || !json.data) throw new Error(json.error || 'Failed to fetch jobs');
  return json.data;
}

export async function fetchJob(id: string): Promise<AnalysisJob> {
  const res = await apiFetch(`${API_BASE}/jobs/${id}`);
  const json: ApiResponse<AnalysisJob> = await res.json();
  if (!json.success || !json.data) throw new Error(json.error || 'Failed to fetch job');
  return json.data;
}

export async function submitFileUpload(
  type: 'javascript' | 'native' | 'dotnet' | 'android' | 'extension',
  file: File,
  extra?: Record<string, string>
): Promise<AnalysisJob> {
  const formData = new FormData();
  formData.append('file', file);
  if (extra) {
    for (const [k, v] of Object.entries(extra)) {
      formData.append(k, v);
    }
  }

  const res = await apiFetch(`${API_BASE}/analysis/${type}`, {
    method: 'POST',
    body: formData,
  });
  const json: ApiResponse<AnalysisJob> = await res.json();
  if (!json.success || !json.data) throw new Error(json.error || 'Failed to submit analysis');
  return json.data;
}

export async function submitBrowserAnalysis(data: BrowserInput): Promise<AnalysisJob> {
  const res = await apiFetch(`${API_BASE}/analysis/browser`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  const json: ApiResponse<AnalysisJob> = await res.json();
  if (!json.success || !json.data) throw new Error(json.error || 'Failed to start browser analysis');
  return json.data;
}

export async function submitEvmAnalysis(data: EvmInput): Promise<AnalysisJob> {
  const res = await apiFetch(`${API_BASE}/analysis/evm`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  const json: ApiResponse<AnalysisJob> = await res.json();
  if (!json.success || !json.data) throw new Error(json.error || 'Failed to start EVM analysis');
  return json.data;
}

export async function submitAutoAnalysis(file: File): Promise<AnalysisJob> {
  const formData = new FormData();
  formData.append('file', file);

  const res = await apiFetch(`${API_BASE}/analysis/auto`, {
    method: 'POST',
    body: formData,
  });
  const json: ApiResponse<AnalysisJob> = await res.json();
  if (!json.success || !json.data) throw new Error(json.error || 'Failed to submit auto-detected analysis');
  return json.data;
}

export async function rerunJob(id: string): Promise<AnalysisJob> {
  const res = await apiFetch(`${API_BASE}/jobs/${id}/rerun`, {
    method: 'POST',
  });
  const json: ApiResponse<AnalysisJob> = await res.json();
  if (!json.success || !json.data) throw new Error(json.error || 'Failed to rerun job');
  return json.data;
}

export async function deleteJob(id: string): Promise<void> {
  const res = await apiFetch(`${API_BASE}/jobs/${id}`, {
    method: 'DELETE',
  });
  const json: ApiResponse<unknown> = await res.json();
  if (!json.success) throw new Error(json.error || 'Failed to delete job');
}

export interface FileContentWindow {
  path: string;
  content: string;
  size?: number;
  isBinary?: boolean;
  offset?: number;
  length?: number;
  truncated?: boolean;
  windowSize?: number;
}

export async function fetchFileContent(jobId: string, relPath?: string, offset?: number): Promise<FileContentWindow> {
  const params = new URLSearchParams();
  if (relPath) params.set('path', relPath);
  if (offset) params.set('offset', String(offset));
  const query = params.toString();
  const url = `${API_BASE}/files/${jobId}${query ? `?${query}` : ''}`;
  const res = await apiFetch(url);
  const json = await res.json();
  if (!json.success || !json.data) throw new Error(json.error || 'Failed to load file content');
  return json.data;
}

async function readJson<T>(res: Response, fallbackError: string): Promise<T> {
  const json: ApiResponse<T> = await res.json().catch(() => ({ success: false }));
  if (!res.ok || !json.success || json.data === undefined) throw new Error(json.error || fallbackError);
  return json.data;
}

export async function updateJobMeta(id: string, patch: { notes?: string; tags?: string[] }): Promise<AnalysisJob> {
  const res = await apiFetch(`${API_BASE}/jobs/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(patch),
  });
  return readJson<AnalysisJob>(res, 'Failed to save');
}

export interface SearchHit {
  kind: 'function' | 'string' | 'import' | 'ioc' | 'yara' | 'file';
  title: string;
  target?: string;
  line?: number;
  snippet: string;
}

export async function searchJob(id: string, q: string): Promise<{ hits: SearchHit[]; truncated: boolean }> {
  const res = await apiFetch(`${API_BASE}/jobs/${id}/search?q=${encodeURIComponent(q)}`);
  return readJson(res, 'Search failed');
}

export const reportUrl = (id: string, format: 'md' | 'pdf' | 'html') => `${API_BASE}/jobs/${id}/report?format=${format}`;

export interface SetDiff {
  added: string[];
  removed: string[];
  common: number;
}

export interface JobComparison {
  a: { id: string; name: string; type: string; sha256?: string };
  b: { id: string; name: string; type: string; sha256?: string };
  identical: boolean;
  sections: Record<string, SetDiff>;
  changedFunctions: { name: string; sizeA: number; sizeB: number }[];
}

export async function compareJobs(a: string, b: string): Promise<JobComparison> {
  const res = await apiFetch(`${API_BASE}/compare?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`);
  return readJson(res, 'Comparison failed');
}

export async function submitBulkAnalysis(files: File[]): Promise<{ jobs: AnalysisJob[]; rejected: { fileName: string; error: string }[] }> {
  const formData = new FormData();
  for (const f of files) formData.append('files', f);
  const res = await apiFetch(`${API_BASE}/analysis/bulk`, { method: 'POST', body: formData });
  return readJson(res, 'Bulk upload failed');
}

// Streams an AI explanation. Calls onText with each chunk; resolves with the saved explanation.
export async function streamExplanation(
  jobId: string,
  scope: ExplainScope,
  onText: (chunk: string) => void,
  signal?: AbortSignal
): Promise<{ key: string; explanation: AiExplanation }> {
  const res = await apiFetch(`${API_BASE}/jobs/${jobId}/explain`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(scope),
    signal,
  });
  if (!res.ok || !res.body) {
    const json = await res.json().catch(() => ({}));
    throw new Error(json.error || `Request failed (${res.status})`);
  }

  const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
  let buffer = '';
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += value;
    let sep: number;
    while ((sep = buffer.indexOf('\n\n')) >= 0) {
      const raw = buffer.slice(0, sep);
      buffer = buffer.slice(sep + 2);
      if (!raw.startsWith('data: ')) continue;
      const event = JSON.parse(raw.slice(6));
      if (event.type === 'text') onText(event.text);
      else if (event.type === 'done') return { key: event.key, explanation: event.explanation };
      else if (event.type === 'error') throw new Error(event.error);
    }
  }
  throw new Error('The explanation stream ended unexpectedly');
}

export type AiProvider = 'anthropic' | 'openai';

export interface AiSettings {
  configured: boolean;
  source: 'portal' | 'env' | 'none';
  provider?: AiProvider;
  model?: string;
  baseUrl?: string;
  keyHint?: string;
}

export interface AiSettingsUpdate {
  provider: AiProvider;
  model: string;
  baseUrl?: string;
  apiKey?: string;
}

const jsonInit = (method: string, body?: unknown): RequestInit => ({
  method,
  headers: { 'Content-Type': 'application/json' },
  body: body === undefined ? undefined : JSON.stringify(body),
});

export async function fetchAiSettings(): Promise<AiSettings> {
  return readJson(await apiFetch(`${API_BASE}/settings/ai`), 'Failed to load AI settings');
}

export async function saveAiSettings(update: AiSettingsUpdate): Promise<AiSettings> {
  return readJson(await apiFetch(`${API_BASE}/settings/ai`, jsonInit('PUT', update)), 'Failed to save AI settings');
}

export async function clearAiSettings(): Promise<AiSettings> {
  return readJson(await apiFetch(`${API_BASE}/settings/ai`, jsonInit('DELETE')), 'Failed to remove AI settings');
}

export async function testAiSettings(update?: AiSettingsUpdate): Promise<{ ok: boolean; model?: string; reply?: string; error?: string }> {
  return readJson(await apiFetch(`${API_BASE}/settings/ai/test`, jsonInit('POST', update ?? {})), 'Test failed');
}

// Download from the Chrome Web Store / Edge Add-ons / addons.mozilla.org and analyze
export async function submitExtensionFromStore(ref: string, browser: 'chrome' | 'firefox'): Promise<AnalysisJob> {
  const res = await apiFetch(`${API_BASE}/analysis/extension/store`, jsonInit('POST', { ref, browser }));
  return readJson(res, 'Failed to download the extension');
}
