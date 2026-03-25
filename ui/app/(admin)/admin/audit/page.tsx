"use client";

import { useEffect, useState } from "react";
import { FileText, RefreshCw, Trash2, Settings2 } from "lucide-react";
import { formatDateTime, ReauthModal } from "@/components/ui";
import { apiPath } from "@/lib/api";

function getCSRF(): string {
  return document.cookie.match(/csrf_token=([^;]+)/)?.[1] ?? "";
}

const ACTION_COLORS: Record<string, string> = {
  // Auth
  login:                 "badge-low",
  logout:                "badge-noise",
  login_failed:          "badge-critical",
  reauth:                "badge-medium",
  reauth_failed:         "badge-high",
  change_password:       "badge-medium",
  // Users
  create_user:           "badge-medium",
  update_user:           "badge-medium",
  delete_user:           "badge-critical",
  // Sensors
  generate_sensor_token: "badge-medium",
  revoke_sensor:         "badge-high",
  delete_sensor:         "badge-high",
  sensor_online:         "badge-low",
  sensor_offline:        "badge-high",
  // Config
  update_smtp_config:    "badge-medium",
  update_siem_config:    "badge-medium",
  test_smtp:             "badge-noise",
  test_siem:             "badge-noise",
  // Data
  export_sessions:       "badge-medium",
};

export default function AuditLogPage() {
  const [logs,           setLogs]           = useState<any[]>([]);
  const [loading,        setLoading]        = useState(true);
  const [page,           setPage]           = useState(0);
  const [purgeDate,      setPurgeDate]      = useState("");
  const [purgeResult,    setPurgeResult]    = useState<string | null>(null);
  const [retentionDays,  setRetentionDays]  = useState<number>(0);
  const [retentionSaved, setRetentionSaved] = useState(false);
  const [reauthOpen,     setReauthOpen]     = useState(false);
  const [reauthLoading,  setReauthLoading]  = useState(false);
  const [reauthError,    setReauthError]    = useState("");
  const PAGE = 100;

  async function load(p = 0) {
    setLoading(true);
    const r = await fetch(apiPath(`/admin/audit?limit=${PAGE}&offset=${p * PAGE}`), { credentials: "include" });
    const d = await r.json();
    setLogs(d.items ?? []);
    setLoading(false);
  }

  async function loadRetention() {
    const r = await fetch(apiPath("/admin/audit/retention"), { credentials: "include" });
    if (r.ok) {
      const d = await r.json();
      setRetentionDays(d.audit_retention_days ?? 0);
    }
  }

  useEffect(() => { load(page); }, [page]);
  useEffect(() => { void loadRetention(); }, []);

  async function doReauth(password: string) {
    setReauthLoading(true);
    setReauthError("");
    const r = await fetch(apiPath("/auth/reauth"), {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": getCSRF() },
      body: JSON.stringify({ password }),
    });
    if (!r.ok) { setReauthError("Invalid password"); setReauthLoading(false); return; }
    setReauthOpen(false);
    setReauthLoading(false);
    await doPurge();
  }

  async function doPurge() {
    if (!purgeDate) return;
    // Use end-of-day (23:59:59) so the selected date is fully included in the purge
    const before = new Date(`${purgeDate}T23:59:59Z`).toISOString();
    const r = await fetch(apiPath(`/admin/audit?before=${encodeURIComponent(before)}`), {
      method: "DELETE", credentials: "include",
      headers: { "X-CSRF-Token": getCSRF() },
    });
    if (r.ok) {
      const d = await r.json();
      setPurgeResult(`${d.deleted} entry deleted.`);
      void load(0);
      setPage(0);
    } else {
      setPurgeResult("Purge failed.");
    }
  }

  async function saveRetention() {
    const r = await fetch(apiPath("/admin/audit/retention"), {
      method: "PUT", credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": getCSRF() },
      body: JSON.stringify({ audit_retention_days: retentionDays }),
    });
    if (r.ok) { setRetentionSaved(true); setTimeout(() => setRetentionSaved(false), 2000); }
  }

  return (
    <div className="p-6 space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2"><FileText className="w-5 h-5" />Audit Log</h1>
          <p className="text-sm text-text-muted mt-0.5">Immutable record of all admin actions</p>
        </div>
        <button onClick={() => load(page)} className="btn-secondary p-2">
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
        </button>
      </div>

      {/* ── Retention & Purge ───────────────────────────────────────────── */}
      <div className="card p-5 space-y-5">
        <h2 className="font-semibold text-sm flex items-center gap-2">
          <Settings2 className="w-4 h-4 text-text-muted" />
          Retention &amp; Purge
        </h2>

        {/* Auto-retention setting */}
        <div className="space-y-2">
          <p className="text-xs font-semibold uppercase text-text-faint">Auto-Retention</p>
          <p className="text-xs text-text-muted">
            Keep only the last <strong>N days</strong> of audit log entries. A background job runs daily and removes older entries automatically. Set to <code className="text-accent">0</code> to disable.
          </p>
          <div className="flex items-center gap-3">
            <input
              type="number"
              min={0}
              className="input w-28 text-sm"
              value={retentionDays}
              onChange={(e) => setRetentionDays(Math.max(0, parseInt(e.target.value) || 0))}
            />
            <span className="text-xs text-text-muted">days {retentionDays === 0 && <span className="text-text-faint">(disabled)</span>}</span>
            <button onClick={() => void saveRetention()} className="btn-secondary text-xs px-3 py-1">
              {retentionSaved ? "Saved ✓" : "Save"}
            </button>
          </div>
        </div>

        {/* Manual purge */}
        <div className="space-y-2 border-t border-bg-border pt-4">
          <p className="text-xs font-semibold uppercase text-text-faint">Manual Purge</p>
          <p className="text-xs text-text-muted">
            Permanently delete all audit entries <strong>before</strong> the selected date. This action requires re-authentication and cannot be undone.
          </p>
          <div className="flex items-center gap-3 flex-wrap">
            <input
              type="date"
              className="input text-sm"
              value={purgeDate}
              onChange={(e) => { setPurgeDate(e.target.value); setPurgeResult(null); }}
            />
            <button
              disabled={!purgeDate}
              onClick={() => setReauthOpen(true)}
              className="btn-secondary text-xs px-3 py-1 flex items-center gap-1.5 text-severity-critical border-severity-critical/30 hover:bg-severity-critical/10 disabled:opacity-40"
            >
              <Trash2 className="w-3.5 h-3.5" />
              Purge Before This Date
            </button>
            {purgeResult && (
              <span className="text-xs text-text-muted">{purgeResult}</span>
            )}
          </div>
        </div>
      </div>

      <div className="card overflow-hidden">
        <table className="data-table">
          <thead>
            <tr><th>Time</th><th>User</th><th>Action</th><th>Target</th><th>Detail</th><th>IP</th></tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} className="text-center text-text-faint py-12">Loading…</td></tr>
            ) : logs.length === 0 ? (
              <tr><td colSpan={6} className="text-center text-text-faint py-12">No audit entries</td></tr>
            ) : logs.map((l) => (
              <tr key={l.id}>
                <td className="text-xs font-mono whitespace-nowrap">{formatDateTime(l.timestamp)}</td>
                <td className="text-xs font-semibold">{l.username ?? "—"}</td>
                <td>
                  <span className={ACTION_COLORS[l.action] ?? "badge-noise"}>
                    {l.action.replace(/_/g, " ")}
                  </span>
                </td>
                <td className="text-xs text-text-muted">
                  {l.target_type && <span>{l.target_type}</span>}
                  {l.target_id && <span className="font-mono ml-1 text-text-faint">{l.target_id.slice(0,8)}…</span>}
                </td>
                <td className="text-xs text-text-faint max-w-xs truncate">
                  {l.detail && Object.keys(l.detail).length > 0 ? JSON.stringify(l.detail).slice(0,60) : "—"}
                </td>
                <td className="text-xs font-mono text-text-faint">{l.source_ip ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="flex justify-between px-4 py-3 border-t border-bg-border">
          <button disabled={page === 0} onClick={() => setPage(p => p - 1)} className="btn-secondary text-xs px-3 py-1 disabled:opacity-40">Previous</button>
          <span className="text-xs text-text-muted self-center">Page {page + 1}</span>
          <button disabled={logs.length < PAGE} onClick={() => setPage(p => p + 1)} className="btn-secondary text-xs px-3 py-1 disabled:opacity-40">Next</button>
        </div>
      </div>

      <ReauthModal
        open={reauthOpen}
        onConfirm={doReauth}
        onCancel={() => setReauthOpen(false)}
        loading={reauthLoading}
        error={reauthError}
      />
    </div>
  );
}
