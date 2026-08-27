// Racine de l'application : décide entre l'écran de configuration et l'explorateur.
//
// POURQUOI cette forme : le client n'est lié à aucun hébergeur. Au démarrage on regarde s'il
// existe une URL de serveur mémorisée et, pour cette URL, un jeton dans le trousseau. Si
// les deux sont là, on entre directement ; sinon on montre l'écran de configuration.
// Aucune URL n'est écrite en dur nulle part.

import { useEffect, useState } from "react";
import { Setup } from "./components/Setup";
import { Browser } from "./components/Browser";
import { SystemPanel } from "./components/SystemPanel";
import * as api from "./lib/plaste";

type Session = { baseUrl: string; token: string };

function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [savedUrl, setSavedUrl] = useState<string | undefined>();
  const [booting, setBooting] = useState(true);
  const [tab, setTab] = useState<"files" | "system">("files");

  useEffect(() => {
    (async () => {
      try {
        const cfg = await api.serverGet();
        if (cfg?.base_url) {
          setSavedUrl(cfg.base_url);
          const token = await api.tokenGet(cfg.base_url);
          if (token) setSession({ baseUrl: cfg.base_url, token });
        }
      } catch {
        // Trousseau indisponible ou config illisible : on retombe simplement sur l'écran
        // de configuration, qui affichera l'erreur exacte à la première tentative.
      } finally {
        setBooting(false);
      }
    })();
  }, []);

  async function logout() {
    if (session) await api.tokenClear(session.baseUrl).catch(() => {});
    setSession(null);
  }

  if (booting) {
    return (
      <main className="min-h-screen bg-neutral-50 p-8 text-sm text-neutral-500">Démarrage…</main>
    );
  }

  if (!session) {
    return (
      <Setup
        initialUrl={savedUrl}
        onConnected={(baseUrl, token) => setSession({ baseUrl, token })}
      />
    );
  }

  return (
    <div className="min-h-screen bg-neutral-50">
      <div className="flex gap-1 border-b border-neutral-200 bg-white px-6 pt-3 text-sm">
        {(["files", "system"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`rounded-t-lg px-3 py-2 ${
              tab === t
                ? "border-b-2 border-neutral-900 font-medium text-neutral-900"
                : "text-neutral-500 hover:text-neutral-800"
            }`}
          >
            {t === "files" ? "Fichiers" : "Système"}
          </button>
        ))}
      </div>
      {tab === "files" ? (
        <Browser baseUrl={session.baseUrl} token={session.token} onLogout={logout} />
      ) : (
        <SystemPanel />
      )}
    </div>
  );
}

export default App;
