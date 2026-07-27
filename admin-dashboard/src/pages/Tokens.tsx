import { useEffect, useMemo, useState } from 'react'
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

function formatExpiry(expires_at: string | null) {
  if (!expires_at) return 'never'
  const d = new Date(expires_at)
  const days = Math.ceil((d.getTime() - Date.now()) / 86_400_000)
  if (days < 0) return `expired ${d.toLocaleDateString()}`
  return `${d.toLocaleDateString()} (${days}d)`
}

export default function Tokens() {
  const [tokens, setTokens] = useState<TokenResp[]>([])
  const [error, setError] = useState('')
  const [owner, setOwner] = useState('')
  const [isAdmin, setIsAdmin] = useState(false)
  const [quotaGb, setQuotaGb] = useState(10)
  const [durationDays, setDurationDays] = useState(30)
  const [creating, setCreating] = useState(false)
  const [justCreated, setJustCreated] = useState<TokenResp | null>(null)

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

  async function createFor(ownerName: string, admin: boolean, quotaBytes: number, days: number) {
    setError('')
    const created = await api.createToken({
      owner: ownerName,
      is_admin: admin,
      quota_bytes: quotaBytes,
      duration_days: days,
    })
    setJustCreated(created)
    await load()
    return created
  }

  async function onCreate(e: React.FormEvent) {
    e.preventDefault()
    setCreating(true)
    try {
      await createFor(owner, isAdmin, Math.round(quotaGb * 1024 * 1024 * 1024), durationDays)
      setOwner('')
      setIsAdmin(false)
      setQuotaGb(10)
      setDurationDays(30)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to create token')
    } finally {
      setCreating(false)
    }
  }

  // Issue another token for a user who already has at least one — reuses their existing
  // is_admin/quota as a sane default, just a fresh 30-day credential (e.g. for a new device).
  async function onAddDevice(existing: TokenResp) {
    setError('')
    try {
      await createFor(existing.owner, existing.is_admin, existing.quota_bytes, 30)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to create token')
    }
  }

  async function onRenew(id: number) {
    const days = Number(prompt('Renew for how many days?', '30'))
    if (!days || days <= 0) return
    setError('')
    try {
      await api.renewToken(id, days)
      await load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to renew token')
    }
  }

  async function onDelete(id: number) {
    if (!confirm('Revoke this token? Any app/device using it loses access immediately.')) return
    try {
      await api.deleteToken(id)
      await load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to revoke token')
    }
  }

  const totalUsed = tokens.reduce((s, t) => s + t.used_bytes, 0)

  // Group tokens by owner so a user's multiple devices/tokens show together.
  const groups = useMemo(() => {
    const m = new Map<string, TokenResp[]>()
    for (const t of tokens) {
      const list = m.get(t.owner) ?? []
      list.push(t)
      m.set(t.owner, list)
    }
    return [...m.entries()].sort((a, b) => a[0].localeCompare(b[0]))
  }, [tokens])

  return (
    <div className="mx-auto max-w-4xl p-6">
      <Nav />
      <div className="mb-6 flex gap-6 rounded border border-gray-300 p-4 dark:border-gray-700">
        <div>
          <div className="text-2xl font-semibold">{groups.length}</div>
          <div className="text-sm text-gray-500">users</div>
        </div>
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

      {justCreated && (
        <div className="mb-4 rounded border border-blue-300 bg-blue-50 p-3 text-sm dark:border-blue-800 dark:bg-blue-950">
          New token for <b>{justCreated.owner}</b> — copy it now, it won't be shown again:
          <div className="mt-1 flex items-center gap-2">
            <code className="rounded bg-white px-2 py-1 dark:bg-black">{justCreated.token}</code>
            <button
              className="text-blue-600 hover:underline"
              onClick={() => navigator.clipboard.writeText(justCreated.token)}
            >
              copy
            </button>
            <button className="text-gray-500 hover:underline" onClick={() => setJustCreated(null)}>
              dismiss
            </button>
          </div>
        </div>
      )}

      <form onSubmit={onCreate} className="mb-6 flex flex-wrap items-end gap-2">
        <div>
          <label className="block text-xs text-gray-500">New user (owner name)</label>
          <input
            required
            value={owner}
            onChange={(e) => setOwner(e.target.value)}
            placeholder="e.g. alice"
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
        <div>
          <label className="block text-xs text-gray-500">Expires in (days)</label>
          <input
            type="number"
            min={1}
            value={durationDays}
            onChange={(e) => setDurationDays(Number(e.target.value))}
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
          Create user + token
        </button>
      </form>

      <div className="space-y-4">
        {groups.map(([ownerName, ownerTokens]) => {
          const used = ownerTokens.reduce((s, t) => s + t.used_bytes, 0)
          const quota = ownerTokens[0].quota_bytes
          const pct = quota > 0 ? Math.min(100, (used / quota) * 100) : 0
          return (
            <div key={ownerName} className="rounded border border-gray-300 dark:border-gray-700">
              <div className="flex items-center justify-between border-b border-gray-200 bg-gray-50 p-3 dark:border-gray-800 dark:bg-gray-900">
                <div>
                  <span className="font-medium">{ownerName}</span>
                  {ownerTokens.some((t) => t.is_admin) && (
                    <span className="ml-2 rounded bg-purple-100 px-1.5 py-0.5 text-xs text-purple-700 dark:bg-purple-900 dark:text-purple-300">
                      admin
                    </span>
                  )}
                  <span className="ml-2 text-xs text-gray-500">
                    {ownerTokens.length} token{ownerTokens.length > 1 ? 's' : ''}
                  </span>
                </div>
                <button
                  onClick={() => onAddDevice(ownerTokens[0])}
                  className="rounded border border-gray-300 px-2 py-1 text-xs hover:bg-gray-100 dark:border-gray-600 dark:hover:bg-gray-800"
                >
                  + New token for {ownerName}
                </button>
              </div>
              <div className="p-3">
                <div className="mb-3 text-xs text-gray-500">
                  {formatBytes(used)} / {formatBytes(quota)} used
                  <div className="mt-1 h-2 w-full max-w-xs rounded bg-gray-200 dark:bg-gray-700">
                    <div className="h-2 rounded bg-blue-600" style={{ width: `${pct}%` }} />
                  </div>
                </div>
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-gray-500">
                      <th className="pb-1 pr-2">Token</th>
                      <th className="pb-1 pr-2">Expires</th>
                      <th className="pb-1 pr-2"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {ownerTokens.map((t) => (
                      <tr key={t.id} className="border-t border-gray-100 dark:border-gray-800">
                        <td className="py-1.5 pr-2 font-mono text-xs text-gray-500">
                          {t.token.slice(0, 18)}…
                        </td>
                        <td className="py-1.5 pr-2 text-xs">{formatExpiry(t.expires_at)}</td>
                        <td className="py-1.5 pr-2 text-right">
                          <button onClick={() => onRenew(t.id)} className="mr-3 text-blue-600 hover:underline">
                            Renew
                          </button>
                          <button onClick={() => onDelete(t.id)} className="text-red-600 hover:underline">
                            Revoke
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
