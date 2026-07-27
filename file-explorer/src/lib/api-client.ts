// ponytail: kept in sync manually with admin-dashboard/src/api-client.ts.
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

// ---------- file-explorer endpoints ----------
// Endpoint shapes taken directly from the Rust handlers (src/folders.rs, files.rs,
// search.rs, tags.rs, sharing.rs, comments.rs).

export interface SubFolder {
  id: number
  name: string
  created_at: string
}
export interface FileEntry {
  id: number
  name: string
  size: number
  created_at: string
}
export interface FolderContents {
  folders: SubFolder[]
  files: FileEntry[]
}

export const foldersApi = {
  listRoot: () => request<FolderContents>('/folders'),
  listFolder: (id: number) => request<FolderContents>(`/folders/${id}`),
  create: (name: string, parent_id: number | null) =>
    requestJson<{ id: number; name: string; parent_id: number | null }>('/folders', 'POST', {
      name,
      parent_id,
    }),
  delete: (id: number) => request<void>(`/folders/${id}`, { method: 'DELETE' }),
}

export interface UploadResp {
  file_id: number
  version_id: number
  version_no: number
  size: number
}

export function uploadFile(
  file: File,
  folderId: number | null,
  onProgress: (pct: number) => void,
): Promise<UploadResp> {
  const form = new FormData()
  if (folderId != null) form.append('folder_id', String(folderId))
  form.append('name', file.name)
  form.append('file', file)
  return uploadForm<UploadResp>('/files/upload', form, onProgress)
}

export const fetchFileBlob = (id: number) => fetchBlob(`/files/${id}/preview`)
export const downloadFileBlob = (id: number) => fetchBlob(`/files/${id}/download`)

export const filesApi = {
  delete: (id: number) => request<void>(`/files/${id}`, { method: 'DELETE' }),
}

export interface SearchResp {
  folders: { id: number; name: string; parent_id: number | null }[]
  files: { id: number; name: string; folder_id: number | null }[]
}

export const searchApi = {
  search: (q: string) => request<SearchResp>(`/search?q=${encodeURIComponent(q)}`),
}

export interface Tag {
  id: number
  name: string
}
export interface ResourceTagEntry {
  id: number
  tag_id: number
  name: string
}
export interface FavoriteEntry {
  id: number
  resource_type: string
  resource_id: number
  name: string | null
}

export const tagsApi = {
  list: () => request<Tag[]>('/tags'),
  create: (name: string) => requestJson<Tag>('/tags', 'POST', { name }),
  delete: (id: number) => request<void>(`/tags/${id}`, { method: 'DELETE' }),
  listForResource: (resource_type: string, resource_id: number) =>
    request<ResourceTagEntry[]>(
      `/resource-tags?resource_type=${resource_type}&resource_id=${resource_id}`,
    ),
  attach: (resource_type: string, resource_id: number, tag_id: number) =>
    requestJson<ResourceTagEntry>('/resource-tags', 'POST', { resource_type, resource_id, tag_id }),
  detach: (id: number) => request<void>(`/resource-tags/${id}`, { method: 'DELETE' }),
}

export const favoritesApi = {
  list: () => request<FavoriteEntry[]>('/favorites'),
  add: (resource_type: string, resource_id: number) =>
    requestJson<FavoriteEntry>('/favorites', 'POST', { resource_type, resource_id }),
  remove: (id: number) => request<void>(`/favorites/${id}`, { method: 'DELETE' }),
}

export interface CreateShareResp {
  id: number
  share_token: string
  permission: string
  expires_at: string | null
}

export const sharesApi = {
  create: (
    resource_type: string,
    resource_id: number,
    permission: string,
    password?: string,
    expires_at?: string,
  ) =>
    requestJson<CreateShareResp>('/shares', 'POST', {
      resource_type,
      resource_id,
      permission,
      password: password || undefined,
      expires_at: expires_at || undefined,
    }),
}

export interface CommentListItem {
  id: number
  author_owner: string
  body: string
  mentions: string[]
  created_at: string
}

export const commentsApi = {
  list: (resource_type: string, resource_id: number) =>
    request<CommentListItem[]>(
      `/comments?resource_type=${resource_type}&resource_id=${resource_id}`,
    ),
  create: (resource_type: string, resource_id: number, body: string) =>
    requestJson<CommentListItem>('/comments', 'POST', { resource_type, resource_id, body }),
  delete: (id: number) => request<void>(`/comments/${id}`, { method: 'DELETE' }),
}
