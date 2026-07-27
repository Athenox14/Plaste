import { useState } from 'react'
import type { SubFolder, FileEntry } from '../lib/api-client'
import ShareDialog from './ShareDialog'

function formatSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

export default function FileGrid({
  folders,
  files,
  onOpenFolder,
  onOpenFile,
  onDeleteFolder,
  onDeleteFile,
}: {
  folders: SubFolder[]
  files: FileEntry[]
  onOpenFolder: (id: number) => void
  onOpenFile: (file: FileEntry) => void
  onDeleteFolder: (id: number) => void
  onDeleteFile: (id: number) => void
}) {
  const [shareTarget, setShareTarget] = useState<{ type: 'file' | 'folder'; id: number } | null>(
    null,
  )

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
      {folders.map((f) => (
        <div
          key={`folder-${f.id}`}
          className="group relative border border-gray-200 dark:border-gray-700 rounded-lg p-3 hover:bg-gray-50 dark:hover:bg-gray-800 cursor-pointer"
          onClick={() => onOpenFolder(f.id)}
        >
          <div className="text-3xl">📁</div>
          <p className="text-sm truncate mt-1 text-gray-900 dark:text-gray-100">{f.name}</p>
          <p className="text-xs text-gray-400">{new Date(f.created_at).toLocaleDateString()}</p>
          <div className="hidden group-hover:flex gap-1 absolute top-1 right-1">
            <button
              onClick={(e) => {
                e.stopPropagation()
                setShareTarget({ type: 'folder', id: f.id })
              }}
              className="text-xs bg-white dark:bg-gray-700 rounded px-1 shadow"
            >
              Share
            </button>
            <button
              onClick={(e) => {
                e.stopPropagation()
                if (confirm(`Delete folder "${f.name}"?`)) onDeleteFolder(f.id)
              }}
              className="text-xs bg-white dark:bg-gray-700 rounded px-1 shadow text-red-500"
            >
              Del
            </button>
          </div>
        </div>
      ))}
      {files.map((f) => (
        <div
          key={`file-${f.id}`}
          className="group relative border border-gray-200 dark:border-gray-700 rounded-lg p-3 hover:bg-gray-50 dark:hover:bg-gray-800 cursor-pointer"
          onClick={() => onOpenFile(f)}
        >
          <div className="text-3xl">📄</div>
          <p className="text-sm truncate mt-1 text-gray-900 dark:text-gray-100">{f.name}</p>
          <p className="text-xs text-gray-400">{formatSize(f.size)}</p>
          <div className="hidden group-hover:flex gap-1 absolute top-1 right-1">
            <button
              onClick={(e) => {
                e.stopPropagation()
                setShareTarget({ type: 'file', id: f.id })
              }}
              className="text-xs bg-white dark:bg-gray-700 rounded px-1 shadow"
            >
              Share
            </button>
            <button
              onClick={(e) => {
                e.stopPropagation()
                if (confirm(`Delete file "${f.name}"?`)) onDeleteFile(f.id)
              }}
              className="text-xs bg-white dark:bg-gray-700 rounded px-1 shadow text-red-500"
            >
              Del
            </button>
          </div>
        </div>
      ))}
      {folders.length === 0 && files.length === 0 && (
        <p className="col-span-full text-sm text-gray-400 py-8 text-center">Empty folder.</p>
      )}
      {shareTarget && (
        <ShareDialog
          resourceType={shareTarget.type}
          resourceId={shareTarget.id}
          onClose={() => setShareTarget(null)}
        />
      )}
    </div>
  )
}
