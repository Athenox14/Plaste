import { useState } from 'react'
import { sharesApi, BASE_URL } from '../lib/api-client'

export default function ShareDialog({
  resourceType,
  resourceId,
  onClose,
}: {
  resourceType: 'file' | 'folder'
  resourceId: number
  onClose: () => void
}) {
  const [password, setPassword] = useState('')
  const [expiresAt, setExpiresAt] = useState('')
  const [link, setLink] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  async function create() {
    setError(null)
    try {
      const resp = await sharesApi.create(
        resourceType,
        resourceId,
        'read',
        password || undefined,
        expiresAt ? new Date(expiresAt).toISOString() : undefined,
      )
      setLink(`${BASE_URL}/public/shares/${resp.share_token}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create share')
    }
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={onClose}>
      <div
        className="bg-white dark:bg-gray-800 rounded-lg p-6 w-full max-w-sm space-y-3"
        onClick={(e) => e.stopPropagation()}
      >
        <h3 className="font-medium text-gray-900 dark:text-gray-100">Share</h3>
        <label className="block text-sm text-gray-600 dark:text-gray-300">
          Password (optional)
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full border border-gray-300 dark:border-gray-600 bg-transparent rounded px-2 py-1 mt-1"
          />
        </label>
        <label className="block text-sm text-gray-600 dark:text-gray-300">
          Expires (optional)
          <input
            type="datetime-local"
            value={expiresAt}
            onChange={(e) => setExpiresAt(e.target.value)}
            className="w-full border border-gray-300 dark:border-gray-600 bg-transparent rounded px-2 py-1 mt-1"
          />
        </label>
        {error && <p className="text-sm text-red-500">{error}</p>}
        {!link ? (
          <button onClick={create} className="w-full bg-blue-600 text-white rounded px-3 py-2">
            Create link
          </button>
        ) : (
          <div className="flex gap-2">
            <input readOnly value={link} className="flex-1 border rounded px-2 py-1 text-xs" />
            <button
              onClick={() => {
                navigator.clipboard.writeText(link)
                setCopied(true)
              }}
              className="bg-gray-200 dark:bg-gray-700 rounded px-2 py-1 text-sm"
            >
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
        )}
        <button onClick={onClose} className="w-full text-sm text-gray-500">
          Close
        </button>
      </div>
    </div>
  )
}
