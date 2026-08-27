// Fine couche au-dessus de `invoke` : un endroit unique où les noms de commandes Tauri
// et leurs formes de retour sont écrits. POURQUOI : toute la logique réseau vit côté Rust
// (flux, trousseau, messages d'erreur) — le TypeScript ne fait que l'appeler.

import { invoke } from "@tauri-apps/api/core";

export type ProbeResult = {
  is_plaste: boolean;
  authenticated: boolean;
  message: string;
};

export type SubFolder = { id: number; name: string; created_at: string };
export type FileEntry = { id: number; name: string; size: number; created_at: string };
export type FolderContents = { folders: SubFolder[]; files: FileEntry[] };

export type ShareCreated = {
  id: number;
  share_token: string;
  url: string;
  password_protected: boolean;
};

export type Progress = { transfer_id: string; transferred: number; total: number };

export const serverGet = () => invoke<{ base_url: string } | null>("server_get");
export const serverSet = (baseUrl: string) =>
  invoke<{ base_url: string }>("server_set", { baseUrl });
export const serverProbe = (baseUrl: string, token?: string) =>
  invoke<ProbeResult>("server_probe", { baseUrl, token: token ?? null });

export const tokenGet = (baseUrl: string) => invoke<string | null>("token_get", { baseUrl });
export const tokenSet = (baseUrl: string, token: string) =>
  invoke<void>("token_set", { baseUrl, token });
export const tokenClear = (baseUrl: string) => invoke<void>("token_clear", { baseUrl });

export const remoteList = (baseUrl: string, token: string, folderId: number | null) =>
  invoke<FolderContents>("remote_list", { baseUrl, token, folderId });

export const remoteCreateFolder = (
  baseUrl: string,
  token: string,
  name: string,
  parentId: number | null,
) => invoke("remote_create_folder", { baseUrl, token, name, parentId });

export const remoteRenameFile = (
  baseUrl: string,
  token: string,
  fileId: number,
  name: string,
) => invoke("remote_update_file", { baseUrl, token, fileId, name, moveToFolder: false, folderId: null });

export const remoteMoveFile = (
  baseUrl: string,
  token: string,
  fileId: number,
  folderId: number | null,
) => invoke("remote_update_file", { baseUrl, token, fileId, name: null, moveToFolder: true, folderId });

export const remoteDeleteFile = (baseUrl: string, token: string, fileId: number) =>
  invoke<void>("remote_delete_file", { baseUrl, token, fileId });

export const uploadStream = (
  baseUrl: string,
  token: string,
  path: string,
  folderId: number | null,
  transferId: string,
) =>
  invoke<{ name: string; size: number; conflicted_copy_name: string | null }>("upload_stream", {
    baseUrl,
    token,
    path,
    folderId,
    transferId,
  });

export const downloadStream = (
  baseUrl: string,
  token: string,
  fileId: number,
  destPath: string,
  transferId: string,
) => invoke<string>("download_stream", { baseUrl, token, fileId, destPath, transferId });

export const transferCancel = (transferId: string) =>
  invoke<void>("transfer_cancel", { transferId });

export const shareCreate = (
  baseUrl: string,
  token: string,
  resourceType: "file" | "folder",
  resourceId: number,
  password: string | null,
  expiresAt: string | null,
) =>
  invoke<ShareCreated>("share_create", {
    baseUrl,
    token,
    resourceType,
    resourceId,
    password,
    expiresAt,
  });

/// Formate une taille pour l'affichage. Doublon assumé du `human_size` Rust : le côté Rust
/// s'en sert dans ses messages d'erreur, le côté TS dans les listes — un aller-retour IPC
/// par ligne de tableau serait absurde.
export function humanSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} o`;
  const units = ["Kio", "Mio", "Gio", "Tio"];
  let value = bytes / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  return `${value.toFixed(1)} ${units[i]}`;
}

/// Une erreur remontée par `invoke` est déjà une phrase française (les commandes Rust
/// renvoient `Result<_, String>`). On se contente de ne jamais afficher un objet brut.
export function errorText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return "Erreur inattendue.";
}
