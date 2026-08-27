// Réglages système préexistants (sélection de dossiers à synchroniser, redirection des
// dossiers connus de Windows). Déplacé tel quel depuis App.tsx quand l'écran de connexion
// et l'explorateur sont arrivés : ces réglages relèvent de la synchronisation, pas du
// parcours de fichiers, et n'ont donc plus leur place sur l'écran principal.

import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Toggle } from "./Toggle";

type SyncFolder = { path: string; synced: boolean };
type KnownFolderInfo = { folder: string; current_path: string; is_redirected: boolean };

export function SystemPanel() {
  const [folders, setFolders] = useState<SyncFolder[]>([]);
  const [loading, setLoading] = useState(true);
  const [vfsSupported, setVfsSupported] = useState(true);
  const [knownFolders, setKnownFolders] = useState<KnownFolderInfo[]>([]);

  useEffect(() => {
    invoke<SyncFolder[]>("list_sync_folders").then(setFolders).finally(() => setLoading(false));
    invoke<boolean>("check_virtual_files_support").then(setVfsSupported);
    invoke("ensure_plaste_folders_cmd").catch(() => {});
    invoke<KnownFolderInfo[]>("list_known_folders")
      .then(setKnownFolders)
      .catch(() => setKnownFolders([]));
  }, []);

  async function handleToggle(path: string) {
    setFolders(await invoke<SyncFolder[]>("toggle_folder_sync", { path }));
  }

  async function handleKnownFolderToggle(folder: KnownFolderInfo) {
    const cmd = folder.is_redirected ? "revert_folder_cmd" : "redirect_folder_cmd";
    try {
      await invoke(cmd, { folder: folder.folder });
      setKnownFolders(await invoke<KnownFolderInfo[]>("list_known_folders"));
    } catch (e) {
      console.error(e);
    }
  }

  return (
    <div className="p-6">
      {!vfsSupported && (
        <p className="mb-4 rounded-lg border border-amber-200 bg-amber-50 px-4 py-2 text-sm text-amber-800">
          Fichiers virtuels indisponibles sur cette plateforme — synchronisation classique
          uniquement.
        </p>
      )}

      <p className="mb-4 rounded-lg border border-neutral-200 bg-white px-4 py-2 text-sm text-neutral-600">
        La synchronisation bidirectionnelle d'un dossier local n'est pas implémentée : ces
        réglages ne font que préparer le terrain.
      </p>

      <section className="rounded-xl border border-neutral-200 bg-white shadow-sm">
        <div className="border-b border-neutral-200 px-4 py-3">
          <h2 className="text-sm font-medium text-neutral-700">Dossiers à synchroniser</h2>
        </div>
        {loading ? (
          <p className="p-4 text-sm text-neutral-500">Chargement…</p>
        ) : (
          <ul className="divide-y divide-neutral-100">
            {folders.map((folder) => (
              <li key={folder.path} className="flex items-center justify-between px-4 py-3">
                <div>
                  <p className="text-sm font-medium">{folder.path}</p>
                  <p className="text-xs text-neutral-500">
                    {folder.synced ? "Synchronisé localement" : "En ligne uniquement"}
                  </p>
                </div>
                <Toggle
                  checked={folder.synced}
                  onChange={() => handleToggle(folder.path)}
                  label={`Basculer la synchronisation de ${folder.path}`}
                />
              </li>
            ))}
          </ul>
        )}
      </section>

      {knownFolders.length > 0 && (
        <section className="mt-6 rounded-xl border border-neutral-200 bg-white shadow-sm">
          <div className="border-b border-neutral-200 px-4 py-3">
            <h2 className="text-sm font-medium text-neutral-700">
              Redirection des dossiers Windows
            </h2>
          </div>
          <ul className="divide-y divide-neutral-100">
            {knownFolders.map((kf) => (
              <li key={kf.folder} className="flex items-center justify-between px-4 py-3">
                <div className="min-w-0">
                  <p className="text-sm font-medium">{kf.folder}</p>
                  <p className="truncate text-xs text-neutral-500">{kf.current_path}</p>
                </div>
                <button
                  onClick={() => handleKnownFolderToggle(kf)}
                  className="shrink-0 rounded-lg border border-neutral-300 px-3 py-1 text-xs font-medium hover:bg-neutral-50"
                >
                  {kf.is_redirected ? "Rétablir" : "Rediriger vers Plaste"}
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
