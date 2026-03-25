"use client";

import { useEffect, useState } from "react";
import { FileText, RefreshCw } from "lucide-react";
import { formatDateTime } from "@/components/ui";
import { apiPath } from "@/lib/api";

const ACTION_COLORS: Record<string, string> = {
  login:                 "badge-low",
  logout:                "badge-noise",
  create_user:           "badge-medium",
  delete_user:           "badge-critical",
  update_user:           "badge-medium",
  change_password:       "badge-medium",
  update_smtp_config:    "badge-medium",
  update_siem_config:    "badge-medium",
  generate_sensor_token: "badge-medium",
  revoke_sensor:         "badge-high",
  delete_sensor:         "badge-high",
};

export default function AuditLogPage() {
  const [logs,    setLogs]    = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [page,    setPage]    = useState(0);
  const PAGE = 100;

  async function load(p = 0) {
    setLoading(true);
    const r = await fetch(apiPath(`/admin/audit?limit=${PAGE}&offset=${p * PAGE}`), { credentials: "include" });
    const d = await r.json();
    setLogs(d.items ?? []);
    setLoading(false);
  }

  useEffect(() => { load(page); }, [page]);

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
    </div>
  );
}
