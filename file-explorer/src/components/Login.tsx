import { useState } from 'react'
import { setToken, foldersApi } from '../lib/api-client'

export default function Login({ onLoggedIn }: { onLoggedIn: () => void }) {
  const [token, setTok] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setBusy(true)
    setToken(token.trim())
    try {
      await foldersApi.listRoot()
      onLoggedIn()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
      <form
        onSubmit={submit}
        className="bg-white dark:bg-gray-800 p-8 rounded-lg shadow-md w-full max-w-sm space-y-4"
      >
        <h1 className="text-xl font-semibold text-gray-900 dark:text-gray-100">Plaste</h1>
        <p className="text-sm text-gray-500 dark:text-gray-400">
          Paste a bearer token to sign in.
        </p>
        <input
          type="password"
          value={token}
          onChange={(e) => setTok(e.target.value)}
          placeholder="Bearer token"
          className="w-full border border-gray-300 dark:border-gray-600 bg-transparent rounded px-3 py-2 text-gray-900 dark:text-gray-100"
          autoFocus
        />
        {error && <p className="text-sm text-red-500">{error}</p>}
        <button
          type="submit"
          disabled={busy || !token.trim()}
          className="w-full bg-blue-600 text-white rounded px-3 py-2 disabled:opacity-50"
        >
          {busy ? 'Checking...' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
