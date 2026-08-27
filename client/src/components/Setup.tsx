// Écran de première configuration : URL du serveur, puis jeton.
//
// POURQUOI en deux temps (tester l'adresse, PUIS le jeton) : ce sont deux échecs très
// différents. Si on demandait tout d'un coup, un utilisateur avec une mauvaise URL croirait
// que son jeton est refusé. On valide donc l'adresse seule d'abord — le serveur répond 401
// sans jeton, ce qui prouve à la fois qu'il est joignable et que c'est bien Plaste.

import { useState } from "react";
import * as api from "../lib/plaste";

type Props = {
  /** URL déjà mémorisée d'un lancement précédent, si elle existe. */
  initialUrl?: string;
  onConnected: (baseUrl: string, token: string) => void;
};

export function Setup({ initialUrl, onConnected }: Props) {
  const [url, setUrl] = useState(initialUrl ?? "");
  const [token, setToken] = useState("");
  // `null` = adresse pas encore validée ; une chaîne = adresse normalisée retenue.
  const [validatedUrl, setValidatedUrl] = useState<string | null>(null);
  const [message, setMessage] = useState("");
  const [kind, setKind] = useState<"info" | "error" | "ok">("info");
  const [busy, setBusy] = useState(false);

  function say(text: string, k: "info" | "error" | "ok") {
    setMessage(text);
    setKind(k);
  }

  async function checkUrl() {
    setBusy(true);
    try {
      const saved = await api.serverSet(url);
      const probe = await api.serverProbe(saved.base_url);
      if (!probe.is_plaste) {
        setValidatedUrl(null);
        say(probe.message, "error");
        return;
      }
      setValidatedUrl(saved.base_url);
      setUrl(saved.base_url);
      say(probe.message, "ok");
      // Un jeton peut déjà dormir dans le trousseau pour ce serveur (réinstallation,
      // changement d'URL puis retour) : on le propose plutôt que de le redemander.
      const existing = await api.tokenGet(saved.base_url);
      if (existing) {
        setToken(existing);
        say(`${probe.message} Un jeton enregistré a été retrouvé dans le trousseau.`, "ok");
      }
    } catch (e) {
      setValidatedUrl(null);
      say(api.errorText(e), "error");
    } finally {
      setBusy(false);
    }
  }

  async function checkToken() {
    if (!validatedUrl) return;
    setBusy(true);
    try {
      const probe = await api.serverProbe(validatedUrl, token);
      if (!probe.authenticated) {
        say(probe.message, "error");
        return;
      }
      // On n'écrit dans le trousseau qu'un jeton dont le serveur a confirmé la validité.
      await api.tokenSet(validatedUrl, token);
      onConnected(validatedUrl, token.trim());
    } catch (e) {
      say(api.errorText(e), "error");
    } finally {
      setBusy(false);
    }
  }

  const banner =
    kind === "error"
      ? "border-red-200 bg-red-50 text-red-800"
      : kind === "ok"
        ? "border-emerald-200 bg-emerald-50 text-emerald-800"
        : "border-neutral-200 bg-neutral-50 text-neutral-700";

  return (
    <main className="min-h-screen bg-neutral-50 p-8 text-neutral-900">
      <div className="mx-auto max-w-lg">
        <h1 className="text-xl font-semibold">Connexion à votre serveur Plaste</h1>
        <p className="mt-1 text-sm text-neutral-600">
          Plaste est auto-hébergeable : indiquez l'adresse de votre propre serveur.
        </p>

        <label className="mt-6 block text-sm font-medium" htmlFor="url">
          Adresse du serveur
        </label>
        <div className="mt-1 flex gap-2">
          <input
            id="url"
            className="flex-1 rounded-lg border border-neutral-300 px-3 py-2 text-sm"
            placeholder="plaste.exemple.org"
            value={url}
            onChange={(e) => {
              setUrl(e.target.value);
              setValidatedUrl(null);
            }}
            onKeyDown={(e) => e.key === "Enter" && !busy && checkUrl()}
          />
          <button
            onClick={checkUrl}
            disabled={busy}
            className="rounded-lg bg-neutral-900 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
          >
            Tester
          </button>
        </div>
        <p className="mt-1 text-xs text-neutral-500">
          Sans préfixe, <code>https://</code> est supposé.
        </p>

        {validatedUrl && (
          <>
            <label className="mt-6 block text-sm font-medium" htmlFor="token">
              Jeton d'accès
            </label>
            <div className="mt-1 flex gap-2">
              <input
                id="token"
                type="password"
                className="flex-1 rounded-lg border border-neutral-300 px-3 py-2 text-sm"
                placeholder="collez votre jeton"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && !busy && checkToken()}
              />
              <button
                onClick={checkToken}
                disabled={busy || !token}
                className="rounded-lg bg-neutral-900 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
              >
                Se connecter
              </button>
            </div>
            <p className="mt-1 text-xs text-neutral-500">
              Le jeton est rangé dans le trousseau du système, jamais en clair sur le disque.
            </p>
          </>
        )}

        {message && (
          <p className={`mt-6 rounded-lg border px-4 py-3 text-sm ${banner}`}>{message}</p>
        )}
      </div>
    </main>
  );
}
