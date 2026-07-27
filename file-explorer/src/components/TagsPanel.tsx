import { useEffect, useState } from 'react'
import { tagsApi, favoritesApi, type Tag, type ResourceTagEntry, type FavoriteEntry } from '../lib/api-client'

export default function TagsPanel({
  resourceType,
  resourceId,
}: {
  resourceType: 'file' | 'folder'
  resourceId: number
}) {
  const [allTags, setAllTags] = useState<Tag[]>([])
  const [attached, setAttached] = useState<ResourceTagEntry[]>([])
  const [favorite, setFavorite] = useState<FavoriteEntry | null>(null)
  const [newTag, setNewTag] = useState('')

  function load() {
    tagsApi.list().then(setAllTags).catch(() => {})
    tagsApi.listForResource(resourceType, resourceId).then(setAttached).catch(() => {})
    favoritesApi
      .list()
      .then((favs) =>
        setFavorite(
          favs.find((f) => f.resource_type === resourceType && f.resource_id === resourceId) ||
            null,
        ),
      )
      .catch(() => {})
  }

  useEffect(load, [resourceType, resourceId])

  async function addTag(tagId: number) {
    await tagsApi.attach(resourceType, resourceId, tagId)
    load()
  }
  async function removeTag(id: number) {
    await tagsApi.detach(id)
    load()
  }
  async function createAndAttach() {
    if (!newTag.trim()) return
    const tag = await tagsApi.create(newTag.trim())
    setNewTag('')
    await tagsApi.attach(resourceType, resourceId, tag.id)
    load()
  }
  async function toggleFavorite() {
    if (favorite) {
      await favoritesApi.remove(favorite.id)
    } else {
      await favoritesApi.add(resourceType, resourceId)
    }
    load()
  }

  const attachedIds = new Set(attached.map((a) => a.tag_id))

  return (
    <div className="space-y-2">
      <button
        onClick={toggleFavorite}
        className={`text-sm rounded px-2 py-1 ${
          favorite ? 'bg-yellow-400 text-yellow-900' : 'bg-gray-100 dark:bg-gray-700'
        }`}
      >
        {favorite ? '★ Favorited' : '☆ Add to favorites'}
      </button>
      <div>
        <h4 className="text-sm font-medium text-gray-700 dark:text-gray-200">Tags</h4>
        <div className="flex flex-wrap gap-1 mt-1">
          {attached.map((t) => (
            <span
              key={t.id}
              className="text-xs bg-blue-100 dark:bg-blue-900 rounded-full px-2 py-0.5 flex items-center gap-1"
            >
              {t.name}
              <button onClick={() => removeTag(t.id)} className="text-blue-500">
                ×
              </button>
            </span>
          ))}
        </div>
        <div className="flex gap-1 mt-1">
          <select
            onChange={(e) => e.target.value && addTag(Number(e.target.value))}
            value=""
            className="text-xs border rounded px-1 py-0.5 bg-transparent"
          >
            <option value="">Attach existing...</option>
            {allTags
              .filter((t) => !attachedIds.has(t.id))
              .map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
          </select>
          <input
            value={newTag}
            onChange={(e) => setNewTag(e.target.value)}
            placeholder="New tag"
            className="text-xs border rounded px-1 py-0.5 bg-transparent w-24"
          />
          <button onClick={createAndAttach} className="text-xs bg-gray-200 dark:bg-gray-700 rounded px-2">
            Add
          </button>
        </div>
      </div>
    </div>
  )
}
