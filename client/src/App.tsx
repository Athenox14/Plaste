import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Toggle } from "./components/Toggle";
import { StatusBadge } from "./components/StatusBadge";

type SyncFolder = {
  path: string;
  synced: boolean;
};

type KnownFolderInfo = {
  folder: string;
  current_path: string;
  is_redirected: boolean;
};

function App() {
  const [folders, setFolders] = useState<SyncFolder[]>([]);
  const [loading, setLoading] = useState(true);
  const [vfsSupported, setVfsSupported] = useState(true);
  const [knownFolders, setKnownFolders] = useState<KnownFolderInfo[]>([]);

  useEffect(() => {
    invoke<SyncFolder[]>("list_sync_folders")
      .then(setFolders)
      .finally(() => setLoading(false));
    invoke<boolean>("check_virtual_files_support").then(setVfsSupported);
    invoke("ensure_plaste_folders_cmd").catch(() => {});
    invoke<KnownFolderInfo[]>("list_known_folders")
      .then(setKnownFolders)
      .catch(() => setKnownFolders([]));
  }, []);

  async function handleToggle(path: string) {
    const updated = await invoke<SyncFolder[]>("toggle_folder_sync", { path });
    setFolders(updated);
  }

  async function handleKnownFolderToggle(folder: KnownFolderInfo) {
    const cmd = folder.is_redirected ? "revert_folder_cmd" : "redirect_folder_cmd";
    try {
      await invoke(cmd, { folder: folder.folder });
      const updated = await invoke<KnownFolderInfo[]>("list_known_folders");
      setKnownFolders(updated);
    } catch (e) {
      console.error(e);
    }
  }

  return (
    <main className="min-h-screen bg-neutral-50 p-6 text-neutral-900">
      <header className="mb-6 flex items-center justify-between">
        <h1 className="text-lg font-semibold">Plaste Sync</h1>
        {/* mock/hardcoded status — no real Plaste API calls yet */}
        <StatusBadge status="connected" />
      </header>

      {!vfsSupported && (
        <p className="mb-4 rounded-lg border border-amber-200 bg-amber-50 px-4 py-2 text-sm text-amber-800">
          Virtual files not available on macOS — classic sync only.
        </p>
      )}

      <section className="rounded-xl border border-neutral-200 bg-white shadow-sm">
        <div className="border-b border-neutral-200 px-4 py-3">
          <h2 className="text-sm font-medium text-neutral-700">Sync folders</h2>
          <p className="text-xs text-neutral-500">
            Toggle a folder to sync it locally, or leave it online-only.
          </p>
        </div>

        {loading ? (
          <p className="p-4 text-sm text-neutral-500">Loading…</p>
        ) : (
          <ul className="divide-y divide-neutral-100">
            {folders.map((folder) => (
              <li
                key={folder.path}
                className="flex items-center justify-between px-4 py-3"
              >
                <div>
                  <p className="text-sm font-medium">{folder.path}</p>
                  <p className="text-xs text-neutral-500">
                    {folder.synced ? "Synced locally" : "Online-only"}
                  </p>
                </div>
                <Toggle
                  checked={folder.synced}
                  onChange={() => handleToggle(folder.path)}
                  label={`Toggle sync for ${folder.path}`}
                />
              </li>
            ))}
          </ul>
        )}
      </section>

      {knownFolders.length > 0 && (
        <section className="mt-6 rounded-xl border border-neutral-200 bg-white shadow-sm">
          <div className="border-b border-neutral-200 px-4 py-3">
            <h2 className="text-sm font-medium text-neutral-700">Windows folder redirection</h2>
            <p className="text-xs text-neutral-500">
              Point a known folder at your Plaste/ folder, or revert it back.
            </p>
          </div>
          <ul className="divide-y divide-neutral-100">
            {knownFolders.map((kf) => (
              <li key={kf.folder} className="flex items-center justify-between px-4 py-3">
                <div>
                  <p className="text-sm font-medium">{kf.folder}</p>
                  <p className="text-xs text-neutral-500">{kf.current_path}</p>
                </div>
                <button
                  onClick={() => handleKnownFolderToggle(kf)}
                  className="rounded-lg border border-neutral-300 px-3 py-1 text-xs font-medium hover:bg-neutral-50"
                >
                  {kf.is_redirected ? "Revert" : "Redirect to Plaste"}
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}
    </main>
  );
}

export default App;
