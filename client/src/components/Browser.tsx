// Explorateur distant : parcours, téléversement/téléchargement en flux, partage.
//
// POURQUOI aucun gestionnaire d'état (Redux/Zustand) : il y a une seule vue, un seul
// dossier courant et une liste de transferts. Trois `useState` suffisent.

import { useCallback, useEffect, useState } from "react";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { listen } from "@tauri-apps/api/event";
import * as api from "../lib/plaste";

type Crumb = { id: number | null; name: string };

type Transfer = {
  id: string;
  label: string;
  direction: "up" | "down";
  transferred: number;
  total: number;
  /** Présent une fois le transfert terminé (succès ou échec). */
  done?: { ok: boolean; text: string };
};

export function Browser({
  baseUrl,
  token,
  onLogout,
}: {
  baseUrl: string;
  token: string;
  onLogout: () => void;
}) {
  const [path, setPath] = useState<Crumb[]>([{ id: null, name: "Racine" }]);
  const [contents, setContents] = useState<api.FolderContents>({ folders: [], files: [] });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [transfers, setTransfers] = useState<Transfer[]>([]);
  const [shareLink, setShareLink] = useState<string | null>(null);

  const currentId = path[path.length - 1].id;

  const refresh = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      setContents(await api.remoteList(baseUrl, token, currentId));
    } catch (e) {
      setError(api.errorText(e));
    } finally {
      setLoading(false);
    }
  }, [baseUrl, token, currentId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Un seul abonnement aux événements de progression pour tous les transferts ; on
  // route sur `transfer_id`.
  useEffect(() => {
    const un = listen<api.Progress>("transfer://progress", (event) => {
      const p = event.payload;
      setTransfers((list) =>
        list.map((t) =>
          t.id === p.transfer_id ? { ...t, transferred: p.transferred, total: p.total } : t,
        ),
      );
    });
    return () => {
      un.then((f) => f());
    };
  }, []);

  function finish(id: string, ok: boolean, text: string) {
    setTransfers((list) => list.map((t) => (t.id === id ? { ...t, done: { ok, text } } : t)));
  }

  async function handleUpload() {
    const picked = await openDialog({ multiple: true });
    if (!picked) return;
    const paths = Array.isArray(picked) ? picked : [picked];
    for (const p of paths) {
      const id = crypto.randomUUID();
      const label = p.split(/[/\\]/).pop() ?? p;
      setTransfers((list) => [
        ...list,
        { id, label, direction: "up", transferred: 0, total: 0 },
      ]);
      // Pas d'`await` en série volontaire : on lance et on laisse la progression arriver.
      api
        .uploadStream(baseUrl, token, p, currentId, id)
        .then((r) => {
          finish(
            id,
            true,
            r.conflicted_copy_name
              ? `Envoyé, mais un conflit a créé « ${r.conflicted_copy_name} ».`
              : `Envoyé (${api.humanSize(r.size)}).`,
          );
          refresh();
        })
        .catch((e) => finish(id, false, api.errorText(e)));
    }
  }

  async function handleDownload(file: api.FileEntry) {
    const dest = await saveDialog({ defaultPath: file.name });
    if (!dest) return;
    const id = crypto.randomUUID();
    setTransfers((list) => [
      ...list,
      { id, label: file.name, direction: "down", transferred: 0, total: file.size },
    ]);
    api
      .downloadStream(baseUrl, token, file.id, dest, id)
      .then((finalPath) => finish(id, true, `Enregistré dans ${finalPath}`))
      .catch((e) => finish(id, false, api.errorText(e)));
  }

  async function handleShare(kind: "file" | "folder", id: number, name: string) {
    // Un `prompt` natif du webview : mot de passe optionnel, vide = lien sans mot de passe.
    const password = window.prompt(
      `Lien de partage pour « ${name} ».\nMot de passe (laisser vide pour aucun) :`,
      "",
    );
    if (password === null) return; // annulé
    try {
      const share = await api.shareCreate(baseUrl, token, kind, id, password || null, null);
      await writeText(share.url);
      setShareLink(
        `${share.url}${share.password_protected ? " (protégé par mot de passe)" : ""} — copié dans le presse-papiers`,
      );
    } catch (e) {
      setError(api.errorText(e));
    }
  }

  async function handleNewFolder() {
    const name = window.prompt("Nom du nouveau dossier :", "");
    if (!name) return;
    try {
      await api.remoteCreateFolder(baseUrl, token, name, currentId);
      refresh();
    } catch (e) {
      setError(api.errorText(e));
    }
  }

  async function handleRename(file: api.FileEntry) {
    const name = window.prompt("Nouveau nom :", file.name);
    if (!name || name === file.name) return;
    try {
      await api.remoteRenameFile(baseUrl, token, file.id, name);
      refresh();
    } catch (e) {
      setError(api.errorText(e));
    }
  }

  async function handleDelete(file: api.FileEntry) {
    if (!window.confirm(`Mettre « ${file.name} » à la corbeille du serveur ?`)) return;
    try {
      await api.remoteDeleteFile(baseUrl, token, file.id);
      refresh();
    } catch (e) {
      setError(api.errorText(e));
    }
  }

  return (
    <main className="min-h-screen bg-neutral-50 p-6 text-neutral-900">
      <header className="mb-4 flex items-center justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-lg font-semibold">Plaste</h1>
          <p className="truncate text-xs text-neutral-500">{baseUrl}</p>
        </div>
        <div className="flex shrink-0 gap-2">
          <button onClick={handleUpload} className="rounded-lg bg-neutral-900 px-3 py-1.5 text-sm font-medium text-white">
            Téléverser…
          </button>
          <button onClick={handleNewFolder} className="rounded-lg border border-neutral-300 px-3 py-1.5 text-sm">
            Nouveau dossier
          </button>
          <button onClick={onLogout} className="rounded-lg border border-neutral-300 px-3 py-1.5 text-sm">
            Déconnexion
          </button>
        </div>
      </header>

      {/* Fil d'Ariane : cliquer sur un segment remonte à ce niveau. */}
      <nav className="mb-3 flex flex-wrap items-center gap-1 text-sm text-neutral-600">
        {path.map((crumb, i) => (
          <span key={`${crumb.id}-${i}`} className="flex items-center gap-1">
            {i > 0 && <span className="text-neutral-400">/</span>}
            <button
              className="rounded px-1 hover:bg-neutral-200 disabled:font-medium disabled:text-neutral-900"
              disabled={i === path.length - 1}
              onClick={() => setPath(path.slice(0, i + 1))}
            >
              {crumb.name}
            </button>
          </span>
        ))}
      </nav>

      {error && (
        <p className="mb-3 rounded-lg border border-red-200 bg-red-50 px-4 py-2 text-sm text-red-800">
          {error}
        </p>
      )}
      {shareLink && (
        <p className="mb-3 flex items-start justify-between gap-3 rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-2 text-sm text-emerald-900">
          <span className="break-all">{shareLink}</span>
          <button className="shrink-0 underline" onClick={() => setShareLink(null)}>
            fermer
          </button>
        </p>
      )}

      <section className="rounded-xl border border-neutral-200 bg-white shadow-sm">
        {loading ? (
          <p className="p-4 text-sm text-neutral-500">Chargement…</p>
        ) : contents.folders.length === 0 && contents.files.length === 0 ? (
          <p className="p-4 text-sm text-neutral-500">Ce dossier est vide.</p>
        ) : (
          <ul className="divide-y divide-neutral-100">
            {contents.folders.map((f) => (
              <li key={`d${f.id}`} className="flex items-center justify-between px-4 py-2.5">
                <button
                  className="truncate text-left text-sm font-medium hover:underline"
                  onClick={() => setPath([...path, { id: f.id, name: f.name }])}
                >
                  📁 {f.name}
                </button>
                <button
                  className="shrink-0 text-xs text-neutral-500 hover:underline"
                  onClick={() => handleShare("folder", f.id, f.name)}
                >
                  Partager
                </button>
              </li>
            ))}
            {contents.files.map((f) => (
              <li key={`f${f.id}`} className="flex items-center justify-between gap-3 px-4 py-2.5">
                <div className="min-w-0">
                  <p className="truncate text-sm">📄 {f.name}</p>
                  <p className="text-xs text-neutral-500">{api.humanSize(f.size)}</p>
                </div>
                <div className="flex shrink-0 gap-3 text-xs text-neutral-500">
                  <button className="hover:underline" onClick={() => handleDownload(f)}>
                    Télécharger
                  </button>
                  <button className="hover:underline" onClick={() => handleShare("file", f.id, f.name)}>
                    Partager
                  </button>
                  <button className="hover:underline" onClick={() => handleRename(f)}>
                    Renommer
                  </button>
                  <button className="text-red-600 hover:underline" onClick={() => handleDelete(f)}>
                    Supprimer
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      {transfers.length > 0 && (
        <section className="mt-6 rounded-xl border border-neutral-200 bg-white shadow-sm">
          <div className="flex items-center justify-between border-b border-neutral-200 px-4 py-2.5">
            <h2 className="text-sm font-medium text-neutral-700">Transferts</h2>
            <button
              className="text-xs text-neutral-500 hover:underline"
              onClick={() => setTransfers((l) => l.filter((t) => !t.done))}
            >
              Effacer les terminés
            </button>
          </div>
          <ul className="divide-y divide-neutral-100">
            {transfers.map((t) => {
              const pct = t.total > 0 ? Math.round((t.transferred / t.total) * 100) : 0;
              return (
                <li key={t.id} className="px-4 py-2.5">
                  <div className="flex items-center justify-between gap-3 text-sm">
                    <span className="truncate">
                      {t.direction === "up" ? "↑" : "↓"} {t.label}
                    </span>
                    {t.done ? (
                      <span className={t.done.ok ? "text-emerald-700" : "text-red-700"}>
                        {t.done.text}
                      </span>
                    ) : (
                      <button
                        className="shrink-0 text-xs text-neutral-500 hover:underline"
                        onClick={() => api.transferCancel(t.id)}
                      >
                        Annuler
                      </button>
                    )}
                  </div>
                  {!t.done && (
                    <>
                      <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-neutral-200">
                        <div className="h-full bg-neutral-900" style={{ width: `${pct}%` }} />
                      </div>
                      <p className="mt-1 text-xs text-neutral-500">
                        {api.humanSize(t.transferred)}
                        {t.total > 0 && ` / ${api.humanSize(t.total)} (${pct} %)`}
                      </p>
                    </>
                  )}
                </li>
              );
            })}
          </ul>
        </section>
      )}
    </main>
  );
}
