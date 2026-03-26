"use client";

import { useEffect, useRef, useState } from "react";
import {
  HardDriveDownload, Plus, Trash2, UploadCloud,
  RotateCcw, AlertTriangle, CheckCircle2, Loader2,
} from "lucide-react";
import { apiPath } from "@/lib/api";

interface Backup {
  filename: string;
  size_bytes: number;
  created_at: string;
}

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

type OpState = "idle" | "running" | "ok" | "error";

export default function BackupPage() {
  const [backups,      setBackups]      = useState<Backup[]>([]);
  const [loading,      setLoading]      = useState(true);
  const [createState,  setCreateState]  = useState<OpState>("idle");
  const [restoreState, setRestoreState] = useState<OpState>("idle");
  const [restoreMsg,   setRestoreMsg]   = useState("");
  const [confirmFile,  setConfirmFile]  = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
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

  useEffect(() => { loadBackups(); }, []);

  async function createBackup() {
    setCreateState("running");
    const r = await fetch(apiPath("/admin/system/backups"), {
      method: "POST", credentials: "include",
      headers: { "X-CSRF-Token": getCsrf() },
    });
    if (r.ok) {
      setCreateState("ok");
      await loadBackups();
      setTimeout(() => setCreateState("idle"), 3000);
    } else {
      setCreateState("error");
      setTimeout(() => setCreateState("idle"), 4000);
    }
  }

  async function deleteBackup(filename: string) {
    await fetch(apiPath(`/admin/system/backups/${filename}`), {
      method: "DELETE", credentials: "include",
      headers: { "X-CSRF-Token": getCsrf() },
    });
    setDeleteTarget(null);
    await loadBackups();
  }

  async function restoreFromFile(filename: string) {
    setConfirmFile(null);
    setRestoreState("running");
    setRestoreMsg("");
    const r = await fetch(apiPath(`/admin/system/backups/${filename}/restore`), {
      method: "POST", credentials: "include",
      headers: { "X-CSRF-Token": getCsrf() },
    });
    if (r.ok) {
      setRestoreState("ok");
      setRestoreMsg(`Restored from ${filename}. Refresh the page to verify data.`);
    } else {
      const d = await r.json().catch(() => ({}));
      setRestoreState("error");
      setRestoreMsg(d.detail ?? "Restore failed.");
    }
  }

  async function handleUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setRestoreState("running");
    setRestoreMsg("");
    const form = new FormData();
    form.append("file", file);
    const r = await fetch(apiPath("/admin/system/restore/upload"), {
      method: "POST", credentials: "include",
      headers: { "X-CSRF-Token": getCsrf() },
      body: form,
    });
    if (r.ok) {
      setRestoreState("ok");
      setRestoreMsg(`Uploaded and restored from ${file.name}. Refresh the page to verify data.`);
      await loadBackups();
    } else {
      const d = await r.json().catch(() => ({}));
      setRestoreState("error");
      setRestoreMsg(d.detail ?? "Restore failed.");
    }
    if (fileRef.current) fileRef.current.value = "";
  }

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
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
          onClick={createBackup}
          disabled={createState === "running"}
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

      {/* Restore status banner */}
      {restoreState !== "idle" && restoreMsg && (
        <div className={`flex items-start gap-3 rounded-md border px-4 py-3 text-sm ${
          restoreState === "ok"
            ? "bg-green-900/20 border-green-800/40 text-severity-low"
            : restoreState === "error"
            ? "bg-red-900/20 border-red-800/40 text-severity-high"
            : "bg-bg-elevated border-bg-border text-text-muted"
        }`}>
          {restoreState === "running" && <Loader2 className="w-4 h-4 animate-spin flex-shrink-0 mt-0.5" />}
          {restoreState === "ok"      && <CheckCircle2 className="w-4 h-4 flex-shrink-0 mt-0.5" />}
          {restoreState === "error"   && <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />}
          <span>{restoreMsg}</span>
        </div>
      )}

      {/* Upload restore */}
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

      {/* Backup list */}
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
                      {/* Download */}
                      <a
                        href={apiPath(`/admin/system/backups/${b.filename}`)}
                        download={b.filename}
                        className="btn-secondary text-xs px-3 py-1 flex items-center gap-1"
                        title="Download"
                      >
                        <HardDriveDownload className="w-3.5 h-3.5" />
                        Download
                      </a>

                      {/* Restore */}
                      {confirmFile === b.filename ? (
                        <div className="flex items-center gap-1">
                          <span className="text-xs text-severity-medium mr-1">Confirm?</span>
                          <button
                            onClick={() => restoreFromFile(b.filename)}
                            className="btn-primary text-xs px-3 py-1"
                          >
                            {restoreState === "running" ? <Loader2 className="w-3 h-3 animate-spin" /> : "Yes, restore"}
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

                      {/* Delete */}
                      {deleteTarget === b.filename ? (
                        <div className="flex items-center gap-1">
                          <span className="text-xs text-severity-high mr-1">Delete?</span>
                          <button
                            onClick={() => deleteBackup(b.filename)}
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
    </div>
  );
}
