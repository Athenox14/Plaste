import { useEffect, useMemo, useState } from 'react'
import { Document, Page, pdfjs } from 'react-pdf'
import 'react-pdf/dist/Page/AnnotationLayer.css'
import 'react-pdf/dist/Page/TextLayer.css'
import { fetchFileBlob, downloadFileBlob, type FileEntry } from '../lib/api-client'
import TagsPanel from './TagsPanel'
import CommentsPanel from './CommentsPanel'
import ShareDialog from './ShareDialog'

// react-pdf needs the pdf.js worker; use the bundled worker asset (Vite ?url import).
pdfjs.GlobalWorkerOptions.workerSrc = new URL(
  'pdfjs-dist/build/pdf.worker.min.mjs',
  import.meta.url,
).toString()

function kindOf(name: string): 'image' | 'pdf' | 'video' | 'other' {
  const ext = name.split('.').pop()?.toLowerCase() || ''
  if (['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'bmp'].includes(ext)) return 'image'
  if (ext === 'pdf') return 'pdf'
  if (['mp4', 'webm', 'ogg', 'mov'].includes(ext)) return 'video'
  return 'other'
}

export default function PreviewModal({ file, onClose }: { file: FileEntry; onClose: () => void }) {
  const [blobUrl, setBlobUrl] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [showShare, setShowShare] = useState(false)
  const kind = useMemo(() => kindOf(file.name), [file.name])

  useEffect(() => {
    let revoke: string | null = null
    if (kind !== 'other') {
      fetchFileBlob(file.id)
        .then((blob) => {
          const url = URL.createObjectURL(blob)
          revoke = url
          setBlobUrl(url)
        })
        .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load preview'))
    }
    return () => {
      if (revoke) URL.revokeObjectURL(revoke)
    }
  }, [file.id, kind])

  async function download() {
    const blob = await downloadFileBlob(file.id)
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = file.name
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-40 p-4" onClick={onClose}>
      <div
        className="bg-white dark:bg-gray-800 rounded-lg w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col md:flex-row"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex-1 flex flex-col items-center justify-center p-4 overflow-auto bg-gray-100 dark:bg-gray-900 min-h-[300px]">
          {error && <p className="text-red-500 text-sm">{error}</p>}
          {kind === 'image' && blobUrl && (
            <img src={blobUrl} alt={file.name} className="max-w-full max-h-[70vh] object-contain" />
          )}
          {kind === 'video' && blobUrl && (
            <video src={blobUrl} controls className="max-w-full max-h-[70vh]" />
          )}
          {kind === 'pdf' && blobUrl && (
            <Document file={blobUrl} loading="Loading PDF...">
              <Page pageNumber={1} width={500} />
            </Document>
          )}
          {kind === 'other' && (
            <p className="text-sm text-gray-500 dark:text-gray-400">No inline preview for this file type.</p>
          )}
          <button onClick={download} className="mt-4 bg-blue-600 text-white rounded px-3 py-1 text-sm">
            Download
          </button>
        </div>
        <div className="w-full md:w-80 border-t md:border-t-0 md:border-l border-gray-200 dark:border-gray-700 p-4 space-y-4 overflow-y-auto">
          <div className="flex items-center justify-between">
            <h2 className="font-medium text-gray-900 dark:text-gray-100 truncate">{file.name}</h2>
            <button onClick={onClose} className="text-gray-400">
              ×
            </button>
          </div>
          <p className="text-xs text-gray-400">
            {(file.size / 1024).toFixed(1)} KB · {new Date(file.created_at).toLocaleString()}
          </p>
          <button
            onClick={() => setShowShare(true)}
            className="text-sm bg-gray-200 dark:bg-gray-700 rounded px-2 py-1"
          >
            Share
          </button>
          <TagsPanel resourceType="file" resourceId={file.id} />
          <CommentsPanel resourceType="file" resourceId={file.id} />
        </div>
      </div>
      {showShare && (
        <ShareDialog resourceType="file" resourceId={file.id} onClose={() => setShowShare(false)} />
      )}
    </div>
  )
}
