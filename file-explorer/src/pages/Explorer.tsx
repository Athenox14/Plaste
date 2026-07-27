import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  foldersApi,
  filesApi,
  searchApi,
  type FolderContents,
  type FileEntry,
  type SearchResp,
} from '../lib/api-client'
import FileGrid from '../components/FileGrid'
import UploadDropzone from '../components/UploadDropzone'
import PreviewModal from '../components/PreviewModal'

interface Crumb {
  id: number | null
  name: string
}

export default function Explorer() {
  const [path, setPath] = useState<Crumb[]>([{ id: null, name: 'Root' }])
  const [contents, setContents] = useState<FolderContents>({ folders: [], files: [] })
  const [previewFile, setPreviewFile] = useState<FileEntry | null>(null)
  const [query, setQuery] = useState('')
  const [searchResults, setSearchResults] = useState<SearchResp | null>(null)
  const [error, setError] = useState<string | null>(null)

  const currentId = path[path.length - 1].id

  const load = useCallback(() => {
    const p = currentId == null ? foldersApi.listRoot() : foldersApi.listFolder(currentId)
    p.then(setContents).catch((err) => setError(err instanceof Error ? err.message : 'Load failed'))
  }, [currentId])

  useEffect(load, [load])

  function openFolder(id: number, name: string) {
    setPath((p) => [...p, { id, name }])
    setSearchResults(null)
  }
  function goToCrumb(index: number) {
    setPath((p) => p.slice(0, index + 1))
    setSearchResults(null)
  }

  async function createFolder() {
    const name = prompt('New folder name')
    if (!name) return
    await foldersApi.create(name, currentId)
    load()
  }

  async function deleteFolder(id: number) {
    await foldersApi.delete(id)
    load()
  }

  async function submitSearch(e: React.FormEvent) {
    e.preventDefault()
    if (!query.trim()) {
      setSearchResults(null)
      return
    }
    const res = await searchApi.search(query.trim())
    setSearchResults(res)
  }

  return (
    <div className="max-w-6xl mx-auto p-4 space-y-4">
      <header className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-gray-900 dark:text-gray-100">Plaste Files</h1>
        <Link to="/favorites" className="text-sm text-blue-600">
          ★ Favorites
        </Link>
      </header>

      <form onSubmit={submitSearch} className="flex gap-2">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search files and folders..."
          className="flex-1 border border-gray-300 dark:border-gray-600 bg-transparent rounded px-3 py-1.5"
        />
        <button className="bg-gray-200 dark:bg-gray-700 rounded px-3 py-1.5 text-sm">Search</button>
        {searchResults && (
          <button
            type="button"
            onClick={() => {
              setSearchResults(null)
              setQuery('')
            }}
            className="text-sm text-gray-400"
          >
            Clear
          </button>
        )}
      </form>

      {searchResults ? (
        <div className="space-y-2">
          <h2 className="text-sm font-medium text-gray-500">Search results</h2>
          <ul className="space-y-1">
            {searchResults.folders.map((f) => (
              <li key={`sf-${f.id}`}>
                <button
                  className="text-sm text-blue-600"
                  onClick={() => {
                    setSearchResults(null)
                    setPath([{ id: null, name: 'Root' }, { id: f.id, name: f.name }])
                  }}
                >
                  📁 {f.name}
                </button>
              </li>
            ))}
            {searchResults.files.map((f) => (
              <li key={`sfile-${f.id}`}>
                <button
                  className="text-sm text-blue-600"
                  onClick={() => {
                    setSearchResults(null)
                    setPreviewFile({ id: f.id, name: f.name, size: 0, created_at: '' })
                  }}
                >
                  📄 {f.name}
                </button>
              </li>
            ))}
            {searchResults.folders.length === 0 && searchResults.files.length === 0 && (
              <li className="text-sm text-gray-400">No results.</li>
            )}
          </ul>
        </div>
      ) : (
        <>
          <nav className="text-sm text-gray-500 flex flex-wrap gap-1">
            {path.map((c, i) => (
              <span key={i}>
                {i > 0 && ' / '}
                <button
                  onClick={() => goToCrumb(i)}
                  className={i === path.length - 1 ? 'font-semibold text-gray-900 dark:text-gray-100' : 'text-blue-600'}
                >
                  {c.name}
                </button>
              </span>
            ))}
          </nav>

          <div className="flex items-center justify-between">
            <button onClick={createFolder} className="text-sm bg-gray-200 dark:bg-gray-700 rounded px-3 py-1">
              + New folder
            </button>
          </div>

          <UploadDropzone folderId={currentId} onUploaded={load} />

          {error && <p className="text-sm text-red-500">{error}</p>}

          <FileGrid
            folders={contents.folders}
            files={contents.files}
            onOpenFolder={(id) => {
              const f = contents.folders.find((x) => x.id === id)
              if (f) openFolder(id, f.name)
            }}
            onOpenFile={setPreviewFile}
            onDeleteFolder={deleteFolder}
            onDeleteFile={async (id) => {
              await filesApi.delete(id)
              load()
            }}
          />
        </>
      )}

      {previewFile && <PreviewModal file={previewFile} onClose={() => setPreviewFile(null)} />}
    </div>
  )
}
