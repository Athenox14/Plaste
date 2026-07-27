import { useCallback, useState } from 'react'
import { useDropzone } from 'react-dropzone'
import { uploadFile } from '../lib/api-client'

interface UploadState {
  name: string
  pct: number
  error?: string
}

export default function UploadDropzone({
  folderId,
  onUploaded,
}: {
  folderId: number | null
  onUploaded: () => void
}) {
  const [uploads, setUploads] = useState<UploadState[]>([])

  const onDrop = useCallback(
    (accepted: File[]) => {
      accepted.forEach((file) => {
        setUploads((u) => [...u, { name: file.name, pct: 0 }])
        uploadFile(file, folderId, (pct) => {
          setUploads((u) => u.map((x) => (x.name === file.name ? { ...x, pct } : x)))
        })
          .then(() => {
            setUploads((u) => u.filter((x) => x.name !== file.name))
            onUploaded()
          })
          .catch((err) => {
            setUploads((u) =>
              u.map((x) => (x.name === file.name ? { ...x, error: String(err) } : x)),
            )
          })
      })
    },
    [folderId, onUploaded],
  )

  const { getRootProps, getInputProps, isDragActive } = useDropzone({ onDrop })

  return (
    <div>
      <div
        {...getRootProps()}
        className={`border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition-colors ${
          isDragActive
            ? 'border-blue-500 bg-blue-50 dark:bg-blue-950'
            : 'border-gray-300 dark:border-gray-600'
        }`}
      >
        <input {...getInputProps()} />
        <p className="text-sm text-gray-500 dark:text-gray-400">
          {isDragActive ? 'Drop files here...' : 'Drag & drop files here, or click to select'}
        </p>
      </div>
      {uploads.length > 0 && (
        <ul className="mt-2 space-y-1">
          {uploads.map((u) => (
            <li key={u.name} className="text-xs text-gray-600 dark:text-gray-300">
              {u.name} — {u.error ? <span className="text-red-500">{u.error}</span> : `${u.pct}%`}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
