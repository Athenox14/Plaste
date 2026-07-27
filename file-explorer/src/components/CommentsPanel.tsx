import { useEffect, useState } from 'react'
import { commentsApi, type CommentListItem } from '../lib/api-client'

export default function CommentsPanel({
  resourceType,
  resourceId,
}: {
  resourceType: 'file' | 'folder'
  resourceId: number
}) {
  const [comments, setComments] = useState<CommentListItem[]>([])
  const [body, setBody] = useState('')
  const [busy, setBusy] = useState(false)

  function load() {
    commentsApi.list(resourceType, resourceId).then(setComments).catch(() => setComments([]))
  }

  useEffect(load, [resourceType, resourceId])

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!body.trim()) return
    setBusy(true)
    try {
      await commentsApi.create(resourceType, resourceId, body.trim())
      setBody('')
      load()
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-2">
      <h3 className="font-medium text-sm text-gray-700 dark:text-gray-200">Comments</h3>
      <ul className="space-y-2 max-h-48 overflow-y-auto">
        {comments.map((c) => (
          <li key={c.id} className="text-sm border-b border-gray-100 dark:border-gray-700 pb-1">
            <span className="font-semibold">{c.author_owner}</span>{' '}
            <span className="text-gray-400 text-xs">{new Date(c.created_at).toLocaleString()}</span>
            <p>{c.body}</p>
          </li>
        ))}
        {comments.length === 0 && <li className="text-xs text-gray-400">No comments yet.</li>}
      </ul>
      <form onSubmit={submit} className="flex gap-2">
        <input
          value={body}
          onChange={(e) => setBody(e.target.value)}
          placeholder="Add a comment... (@mention)"
          className="flex-1 border border-gray-300 dark:border-gray-600 bg-transparent rounded px-2 py-1 text-sm"
        />
        <button
          disabled={busy}
          className="bg-blue-600 text-white text-sm rounded px-3 py-1 disabled:opacity-50"
        >
          Post
        </button>
      </form>
    </div>
  )
}
