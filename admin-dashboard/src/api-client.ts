// ponytail: kept in sync manually with file-explorer/src/lib/api-client.ts.
// The generic wrapper (top section: ApiError, token storage, request/requestJson/
// uploadForm/fetchBlob) is meant to stay identical between the two copies.
// Promote to a real shared npm package if a 3rd frontend needs this or drift becomes a problem.

export const BASE_URL =
  (import.meta.env.VITE_API_BASE_URL as string | undefined) || 'http://127.0.0.1:8080'

const TOKEN_KEY = 'plaste_token'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}
export function setToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token)
}
export function clearToken() {
  localStorage.removeItem(TOKEN_KEY)
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

function authHeaders(): HeadersInit {
  const token = getToken()
  return token ? { Authorization: `Bearer ${token}` } : {}
}

export async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...init,
    headers: {
      ...authHeaders(),
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...init?.headers,
    },
  })
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new ApiError(res.status, text || res.statusText)
  }
  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}

export function requestJson<T>(path: string, method: string, body: unknown): Promise<T> {
  return request<T>(path, { method, body: JSON.stringify(body) })
}

// XHR-based upload with progress reporting (fetch has no upload progress event).
export function uploadForm<T>(
  path: string,
  form: FormData,
  onProgress?: (pct: number) => void,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('POST', `${BASE_URL}${path}`)
    const token = getToken()
    if (token) xhr.setRequestHeader('Authorization', `Bearer ${token}`)
    if (onProgress) {
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) onProgress(Math.round((e.loaded / e.total) * 100))
      }
    }
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(JSON.parse(xhr.responseText))
      } else {
        reject(new ApiError(xhr.status, xhr.responseText))
      }
    }
    xhr.onerror = () => reject(new ApiError(0, 'upload failed'))
    xhr.send(form)
  })
}

export async function fetchBlob(path: string): Promise<Blob> {
  const res = await fetch(`${BASE_URL}${path}`, { headers: authHeaders() })
  if (!res.ok) throw new ApiError(res.status, res.statusText)
  return res.blob()
}

// ---------- admin-dashboard endpoints ----------

export interface TokenResp {
  id: number
  token: string
  owner: string
  is_admin: boolean
  quota_bytes: number
  used_bytes: number
}

export interface AuditEntry {
  id: number
  actor_owner: string
  action: string
  resource_type: string | null
  resource_id: number | null
  detail: string | null
  created_at: string
}

export const api = {
  listTokens: () => request<TokenResp[]>('/admin/tokens'),
  createToken: (body: { owner: string; is_admin: boolean; quota_bytes: number }) =>
    requestJson<TokenResp>('/admin/tokens', 'POST', body),
  deleteToken: (id: number) => request<void>(`/admin/tokens/${id}`, { method: 'DELETE' }),
  auditLog: (limit: number) => request<AuditEntry[]>(`/admin/audit-log?limit=${limit}`),
}
