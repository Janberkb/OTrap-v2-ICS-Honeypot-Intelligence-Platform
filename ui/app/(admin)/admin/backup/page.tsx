"use client";

import { useEffect, useRef, useState } from "react";
import {
  HardDriveDownload, Plus, Trash2, UploadCloud,
  RotateCcw, AlertTriangle, CheckCircle2, Loader2,
} from "lucide-react";
import { ReauthModal } from "@/components/ui";
import { apiPath } from "@/lib/api";

interface Backup {
  filename: string;
  size_bytes: number;
  created_at: string;
}

type OpState = "idle" | "running" | "ok" | "error";
type PendingAction =
  | { kind: "create" }
  | { kind: "download"; filename: string }
  | { kind: "delete"; filename: string }
  | { kind: "restore"; filename: string }
  | { kind: "upload"; file: File };

function formatBytes(b: number) {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 / 1024).toFixed(2)} MB`;
}

function formatDT(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    year: "numeric", month: "short", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function getCsrf() {
  return document.cookie.match(/csrf_token=([^;]+)/)?.[1] ?? "";
}

function errorMessage(data: any, fallback: string) {
  if (!data) return fallback;
  if (typeof data.detail === "string") return data.detail;
  if (typeof data.error === "string") return data.error;
  if (typeof data.detail?.message === "string") return data.detail.message;
  if (typeof data.detail?.error === "string") return data.detail.error;
  return fallback;
}

export default function BackupPage() {
  const [backups,        setBackups]        = useState<Backup[]>([]);
  const [loading,        setLoading]        = useState(true);
  const [createState,    setCreateState]    = useState<OpState>("idle");
  const [actionState,    setActionState]    = useState<OpState>("idle");
  const [actionMsg,      setActionMsg]      = useState("");
  const [confirmFile,    setConfirmFile]    = useState<string | null>(null);
  const [deleteTarget,   setDeleteTarget]   = useState<string | null>(null);
  const [downloadTarget, setDownloadTarget] = useState<string | null>(null);
  const [reauthOpen,     setReauthOpen]     = useState(false);
  const [reauthLoading,  setReauthLoading]  = useState(false);
  const [reauthError,    setReauthError]    = useState("");
  const [pendingAction,  setPendingAction]  = useState<PendingAction | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  async function loadBackups() {
    setLoading(true);
    const r = await fetch(apiPath("/admin/system/backups"), { credentials: "include" });
    if (r.ok) {
      const d = await r.json();
      setBackups(d.backups ?? []);
    }
    setLoading(false);
  }

  useEffect(() => { void loadBackups(); }, []);

  async function createBackup() {
    setCreateState("running");
    const r = await fetch(apiPath("/admin/system/backups"), {
      method: "POST",
      credentials: "include",
      headers: { "X-CSRF-Token": getCsrf() },
    });
    if (r.ok) {
      setCreateState("ok");
      setActionState("ok");
      setActionMsg("Backup created successfully.");
      await loadBackups();
      setTimeout(() => setCreateState("idle"), 3000);
      return;
    }

    const d = await r.json().catch(() => ({}));
    setCreateState("error");
    setActionState("error");
    setActionMsg(errorMessage(d, "Backup creation failed."));
    setTimeout(() => setCreateState("idle"), 4000);
  }

  async function deleteBackup(filename: string) {
    setDeleteTarget(null);
    setActionState("running");
    setActionMsg("");
    const r = await fetch(apiPath(`/admin/system/backups/${filename}`), {
      method: "DELETE",
      credentials: "include",
      headers: { "X-CSRF-Token": getCsrf() },
    });
    if (r.ok) {
      setActionState("ok");
      setActionMsg(`${filename} deleted.`);
      await loadBackups();
      return;
    }

    const d = await r.json().catch(() => ({}));
    setActionState("error");
    setActionMsg(errorMessage(d, "Delete failed."));
  }

  async function restoreFromFile(filename: string) {
    setConfirmFile(null);
    setActionState("running");
    setActionMsg("");
    const r = await fetch(apiPath(`/admin/system/backups/${filename}/restore`), {
      method: "POST",
      credentials: "include",
      headers: { "X-CSRF-Token": getCsrf() },
    });
    if (r.ok) {
      setActionState("ok");
      setActionMsg(`Restored from ${filename}. Refresh the page to verify data.`);
      return;
    }

    const d = await r.json().catch(() => ({}));
    setActionState("error");
    setActionMsg(errorMessage(d, "Restore failed."));
  }

  async function uploadAndRestore(file: File) {
    setActionState("running");
    setActionMsg("");
    const form = new FormData();
    form.append("file", file);
    const r = await fetch(apiPath("/admin/system/restore/upload"), {
      method: "POST",
      credentials: "include",
      headers: { "X-CSRF-Token": getCsrf() },
      body: form,
    });
    if (r.ok) {
      setActionState("ok");
      setActionMsg(`Uploaded and restored from ${file.name}. Refresh the page to verify data.`);
      await loadBackups();
    } else {
      const d = await r.json().catch(() => ({}));
      setActionState("error");
      setActionMsg(errorMessage(d, "Restore failed."));
    }
    if (fileRef.current) fileRef.current.value = "";
  }

  async function downloadBackup(filename: string) {
    setDownloadTarget(filename);
    setActionState("running");
    setActionMsg(`Downloading ${filename}…`);
    try {
      const r = await fetch(apiPath(`/admin/system/backups/${filename}`), {
        credentials: "include",
      });
      if (!r.ok) {
        const d = r.headers.get("content-type")?.includes("application/json")
          ? await r.json().catch(() => ({}))
          : {};
        setActionState("error");
        setActionMsg(errorMessage(d, "Download failed."));
        return;
      }

      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
      setActionState("ok");
      setActionMsg(`${filename} downloaded.`);
    } finally {
      setDownloadTarget(null);
    }
  }

  function startProtectedAction(action: PendingAction) {
    setPendingAction(action);
    setReauthError("");
    setReauthOpen(true);
  }

  function cancelReauth() {
    if (pendingAction?.kind === "upload" && fileRef.current) {
      fileRef.current.value = "";
    }
    setPendingAction(null);
    setReauthError("");
    setReauthOpen(false);
  }

  async function doReauth(password: string) {
    setReauthLoading(true);
    setReauthError("");
    const r = await fetch(apiPath("/auth/reauth"), {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": getCsrf() },
      body: JSON.stringify({ password }),
    });
    if (!r.ok) {
      setReauthError("Incorrect password");
      setReauthLoading(false);
      return;
    }

    const action = pendingAction;
    setPendingAction(null);
    setReauthOpen(false);
    setReauthLoading(false);

    if (!action) return;
    if (action.kind === "create") await createBackup();
    if (action.kind === "download") await downloadBackup(action.filename);
    if (action.kind === "delete") await deleteBackup(action.filename);
    if (action.kind === "restore") await restoreFromFile(action.filename);
    if (action.kind === "upload") await uploadAndRestore(action.file);
  }

  function handleUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    startProtectedAction({ kind: "upload", file });
  }

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2">
            <HardDriveDownload className="w-5 h-5" />
            Backup & Restore
          </h1>
          <p className="text-sm text-text-muted mt-0.5">
            Create PostgreSQL snapshots and restore from a previous backup
          </p>
        </div>
        <button
          onClick={() => startProtectedAction({ kind: "create" })}
          disabled={createState === "running" || reauthLoading}
          className="btn-primary flex items-center gap-2 px-4 py-2 text-sm"
        >
          {createState === "running" ? (
            <><Loader2 className="w-4 h-4 animate-spin" />Creating…</>
          ) : createState === "ok" ? (
            <><CheckCircle2 className="w-4 h-4" />Backup created</>
          ) : createState === "error" ? (
            <><AlertTriangle className="w-4 h-4" />Failed</>
          ) : (
            <><Plus className="w-4 h-4" />New Backup</>
          )}
        </button>
      </div>

      {actionState !== "idle" && actionMsg && (
        <div className={`flex items-start gap-3 rounded-md border px-4 py-3 text-sm ${
          actionState === "ok"
            ? "bg-green-900/20 border-green-800/40 text-severity-low"
            : actionState === "error"
            ? "bg-red-900/20 border-red-800/40 text-severity-high"
            : "bg-bg-elevated border-bg-border text-text-muted"
        }`}>
          {actionState === "running" && <Loader2 className="w-4 h-4 animate-spin flex-shrink-0 mt-0.5" />}
          {actionState === "ok"      && <CheckCircle2 className="w-4 h-4 flex-shrink-0 mt-0.5" />}
          {actionState === "error"   && <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />}
          <span>{actionMsg}</span>
        </div>
      )}

      <div className="card p-5">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h2 className="font-semibold text-sm">Restore from File Upload</h2>
            <p className="text-xs text-text-muted mt-0.5">
              Upload a <span className="font-mono">.sql.gz</span> file from your computer
            </p>
          </div>
          <label className="btn-secondary flex items-center gap-2 px-4 py-2 text-sm cursor-pointer">
            <UploadCloud className="w-4 h-4" />
            Upload & Restore
            <input
              ref={fileRef}
              type="file"
              accept=".sql.gz"
              className="hidden"
              onChange={handleUpload}
            />
          </label>
        </div>
        <p className="text-xs text-text-faint bg-yellow-900/10 border border-yellow-800/30 rounded px-3 py-2 flex items-start gap-2">
          <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5 text-severity-medium" />
          Restoring will <strong>overwrite all current data</strong> in the database. This action cannot be undone.
        </p>
      </div>

      <div className="card">
        <div className="px-5 py-4 border-b border-bg-border flex items-center justify-between">
          <h2 className="font-semibold text-sm">Stored Backups</h2>
          <span className="text-xs text-text-faint">{backups.length} file{backups.length !== 1 ? "s" : ""}</span>
        </div>

        {loading ? (
          <div className="p-8 text-center text-text-muted text-sm">Loading…</div>
        ) : backups.length === 0 ? (
          <div className="p-8 text-center text-text-faint text-sm">
            No backups yet. Click <strong>New Backup</strong> to create one.
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Filename</th>
                <th>Created</th>
                <th>Size</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {backups.map((b) => (
                <tr key={b.filename}>
                  <td className="font-mono text-xs">{b.filename}</td>
                  <td className="text-xs text-text-muted">{formatDT(b.created_at)}</td>
                  <td className="text-xs tabular-nums">{formatBytes(b.size_bytes)}</td>
                  <td className="text-right">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        type="button"
                        onClick={() => startProtectedAction({ kind: "download", filename: b.filename })}
                        className="btn-secondary text-xs px-3 py-1 flex items-center gap-1"
                        title="Download"
                      >
                        {downloadTarget === b.filename
                          ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          : <HardDriveDownload className="w-3.5 h-3.5" />}
                        Download
                      </button>

                      {confirmFile === b.filename ? (
                        <div className="flex items-center gap-1">
                          <span className="text-xs text-severity-medium mr-1">Confirm?</span>
                          <button
                            onClick={() => startProtectedAction({ kind: "restore", filename: b.filename })}
                            className="btn-primary text-xs px-3 py-1"
                          >
                            {actionState === "running" ? <Loader2 className="w-3 h-3 animate-spin" /> : "Yes, restore"}
                          </button>
                          <button
                            onClick={() => setConfirmFile(null)}
                            className="btn-secondary text-xs px-3 py-1"
                          >
                            Cancel
                          </button>
                        </div>
                      ) : (
                        <button
                          onClick={() => setConfirmFile(b.filename)}
                          className="btn-secondary text-xs px-3 py-1 flex items-center gap-1"
                          title="Restore from this backup"
                        >
                          <RotateCcw className="w-3.5 h-3.5" />
                          Restore
                        </button>
                      )}

                      {deleteTarget === b.filename ? (
                        <div className="flex items-center gap-1">
                          <span className="text-xs text-severity-high mr-1">Delete?</span>
                          <button
                            onClick={() => startProtectedAction({ kind: "delete", filename: b.filename })}
                            className="btn-danger text-xs px-3 py-1"
                          >
                            Yes
                          </button>
                          <button
                            onClick={() => setDeleteTarget(null)}
                            className="btn-secondary text-xs px-3 py-1"
                          >
                            No
                          </button>
                        </div>
                      ) : (
                        <button
                          onClick={() => setDeleteTarget(b.filename)}
                          className="btn-secondary text-xs px-3 py-1 text-severity-high hover:border-severity-high"
                          title="Delete backup"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <ReauthModal
        open={reauthOpen}
        onConfirm={doReauth}
        onCancel={cancelReauth}
        loading={reauthLoading}
        error={reauthError}
      />
    </div>
  );
}
