import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, ApiError } from '../api-client'
import { setToken } from '../api-client'

export default function Login() {
  const [value, setValue] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    setToken(value.trim())
    try {
      await api.listTokens()
      navigate('/tokens')
    } catch (err) {
      const msg =
        err instanceof ApiError && (err.status === 401 || err.status === 403)
          ? 'Invalid or non-admin token.'
          : 'Could not reach the Plaste server.'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="mx-auto mt-24 max-w-sm rounded-lg border border-gray-300 p-6 shadow-sm dark:border-gray-700">
      <h1 className="mb-4 text-xl font-semibold">Plaste Admin</h1>
      <form onSubmit={onSubmit} className="flex flex-col gap-3">
        <input
          type="password"
          placeholder="Admin bearer token"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          className="rounded border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-800"
          autoFocus
        />
        <button
          type="submit"
          disabled={loading || !value}
          className="rounded bg-blue-600 px-3 py-2 text-white disabled:opacity-50"
        >
          {loading ? 'Checking…' : 'Sign in'}
        </button>
        {error && <p className="text-sm text-red-600">{error}</p>}
      </form>
    </div>
  )
}
