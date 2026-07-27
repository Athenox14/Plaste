import { useEffect, useState } from 'react'
import Nav from './Nav'
import { api, ApiError, type AuditEntry } from '../api-client'

export default function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [limit, setLimit] = useState(100)
  const [error, setError] = useState('')

  useEffect(() => {
    api
      .auditLog(limit)
      .then(setEntries)
      .catch((err) => setError(err instanceof ApiError ? err.message : 'Failed to load audit log'))
  }, [limit])

  return (
    <div className="mx-auto max-w-5xl p-6">
      <Nav />
      <div className="mb-4 flex items-center gap-2">
        <label className="text-sm text-gray-500">Limit</label>
        <select
          value={limit}
          onChange={(e) => setLimit(Number(e.target.value))}
          className="rounded border border-gray-300 px-2 py-1 dark:border-gray-600 dark:bg-gray-800"
        >
          {[25, 50, 100, 250, 500].map((n) => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </select>
      </div>

      {error && <p className="mb-3 text-sm text-red-600">{error}</p>}

      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b border-gray-300 text-left dark:border-gray-700">
            <th className="p-2">Actor</th>
            <th className="p-2">Action</th>
            <th className="p-2">Resource</th>
            <th className="p-2">Detail</th>
            <th className="p-2">When</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((e) => (
            <tr key={e.id} className="border-b border-gray-200 dark:border-gray-800">
              <td className="p-2">{e.actor_owner}</td>
              <td className="p-2">{e.action}</td>
              <td className="p-2">
                {e.resource_type ? `${e.resource_type}#${e.resource_id ?? ''}` : ''}
              </td>
              <td className="p-2">{e.detail ?? ''}</td>
              <td className="p-2 text-gray-500">{e.created_at}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
