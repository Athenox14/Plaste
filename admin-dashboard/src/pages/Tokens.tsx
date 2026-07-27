import { useEffect, useState } from 'react'
import Nav from './Nav'
import { api, ApiError, type TokenResp } from '../api-client'

function formatBytes(n: number) {
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(1)} ${units[i]}`
}

export default function Tokens() {
  const [tokens, setTokens] = useState<TokenResp[]>([])
  const [error, setError] = useState('')
  const [owner, setOwner] = useState('')
  const [isAdmin, setIsAdmin] = useState(false)
  const [quotaGb, setQuotaGb] = useState(10)
  const [creating, setCreating] = useState(false)

  async function load() {
    try {
      setTokens(await api.listTokens())
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load tokens')
    }
  }

  useEffect(() => {
    load()
  }, [])

  async function onCreate(e: React.FormEvent) {
    e.preventDefault()
    setCreating(true)
    setError('')
    try {
      await api.createToken({
        owner,
        is_admin: isAdmin,
        quota_bytes: Math.round(quotaGb * 1024 * 1024 * 1024),
      })
      setOwner('')
      setIsAdmin(false)
      setQuotaGb(10)
      await load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to create token')
    } finally {
      setCreating(false)
    }
  }

  async function onDelete(id: number) {
    if (!confirm('Delete this token?')) return
    try {
      await api.deleteToken(id)
      await load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to delete token')
    }
  }

  const totalUsed = tokens.reduce((s, t) => s + t.used_bytes, 0)

  return (
    <div className="mx-auto max-w-4xl p-6">
      <Nav />
      <div className="mb-6 flex gap-6 rounded border border-gray-300 p-4 dark:border-gray-700">
        <div>
          <div className="text-2xl font-semibold">{tokens.length}</div>
          <div className="text-sm text-gray-500">tokens</div>
        </div>
        <div>
          <div className="text-2xl font-semibold">{formatBytes(totalUsed)}</div>
          <div className="text-sm text-gray-500">total used</div>
        </div>
      </div>

      {error && <p className="mb-3 text-sm text-red-600">{error}</p>}

      <form onSubmit={onCreate} className="mb-6 flex flex-wrap items-end gap-2">
        <div>
          <label className="block text-xs text-gray-500">Owner</label>
          <input
            required
            value={owner}
            onChange={(e) => setOwner(e.target.value)}
            className="rounded border border-gray-300 px-2 py-1 dark:border-gray-600 dark:bg-gray-800"
          />
        </div>
        <div>
          <label className="block text-xs text-gray-500">Quota (GB)</label>
          <input
            type="number"
            min={0}
            step="0.1"
            value={quotaGb}
            onChange={(e) => setQuotaGb(Number(e.target.value))}
            className="w-24 rounded border border-gray-300 px-2 py-1 dark:border-gray-600 dark:bg-gray-800"
          />
        </div>
        <label className="flex items-center gap-1 pb-1 text-sm">
          <input type="checkbox" checked={isAdmin} onChange={(e) => setIsAdmin(e.target.checked)} />
          Admin
        </label>
        <button
          type="submit"
          disabled={creating}
          className="rounded bg-blue-600 px-3 py-1.5 text-white disabled:opacity-50"
        >
          Create token
        </button>
      </form>

      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b border-gray-300 text-left dark:border-gray-700">
            <th className="p-2">Owner</th>
            <th className="p-2">Admin</th>
            <th className="p-2">Usage</th>
            <th className="p-2">Created</th>
            <th className="p-2"></th>
          </tr>
        </thead>
        <tbody>
          {tokens.map((t) => {
            const pct = t.quota_bytes > 0 ? Math.min(100, (t.used_bytes / t.quota_bytes) * 100) : 0
            return (
              <tr key={t.id} className="border-b border-gray-200 dark:border-gray-800">
                <td className="p-2">{t.owner}</td>
                <td className="p-2">{t.is_admin ? 'yes' : ''}</td>
                <td className="p-2">
                  <div className="mb-1 text-xs text-gray-500">
                    {formatBytes(t.used_bytes)} / {formatBytes(t.quota_bytes)}
                  </div>
                  <div className="h-2 w-40 rounded bg-gray-200 dark:bg-gray-700">
                    <div
                      className="h-2 rounded bg-blue-600"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </td>
                <td className="p-2 text-gray-500">{'—' /* not returned by list endpoint */}</td>
                <td className="p-2">
                  <button onClick={() => onDelete(t.id)} className="text-red-600 hover:underline">
                    Delete
                  </button>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
