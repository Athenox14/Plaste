import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { favoritesApi, type FavoriteEntry, type FileEntry } from '../lib/api-client'
import PreviewModal from '../components/PreviewModal'

export default function Favorites() {
  const [favs, setFavs] = useState<FavoriteEntry[]>([])
  const [previewFile, setPreviewFile] = useState<FileEntry | null>(null)

  useEffect(() => {
    favoritesApi.list().then(setFavs).catch(() => setFavs([]))
  }, [])

  return (
    <div className="max-w-6xl mx-auto p-4 space-y-4">
      <header className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-gray-900 dark:text-gray-100">Favorites</h1>
        <Link to="/" className="text-sm text-blue-600">
          ← Back to files
        </Link>
      </header>
      <ul className="space-y-1">
        {favs.map((f) => (
          <li key={f.id}>
            <button
              className="text-sm text-blue-600"
              onClick={() =>
                f.resource_type === 'file' &&
                setPreviewFile({ id: f.resource_id, name: f.name || 'file', size: 0, created_at: '' })
              }
            >
              {f.resource_type === 'file' ? '📄' : '📁'} {f.name || `#${f.resource_id}`}
            </button>
          </li>
        ))}
        {favs.length === 0 && <li className="text-sm text-gray-400">No favorites yet.</li>}
      </ul>
      {previewFile && <PreviewModal file={previewFile} onClose={() => setPreviewFile(null)} />}
    </div>
  )
}
