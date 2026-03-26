"use client";

// ═══════════════════════════════════════════════════════════════════
// app/(admin)/admin/siem/page.tsx
// ═══════════════════════════════════════════════════════════════════

import { useEffect, useState } from "react";
import { Database, Send, Eye, EyeOff } from "lucide-react";
import { ReauthModal, formatDateTime } from "@/components/ui";
import { apiPath } from "@/lib/api";
const getCSRF = () => document.cookie.match(/csrf_token=([^;]+)/)?.[1] ?? "";

export default function SIEMPage() {
  const [cfg,          setCfg]          = useState<any>({});
  const [form,         setForm]         = useState<any>({});
  const [logs,         setLogs]         = useState<any[]>([]);
  const [saving,       setSaving]       = useState(false);
  const [testing,      setTesting]      = useState(false);
  const [testResult,   setTestResult]   = useState<{ ok: boolean; message: string } | null>(null);
  const [showToken,    setShowToken]    = useState(false);
  const isSyslog = form.siem_type === "syslog_cef";
  const [reauthOpen,   setReauthOpen]   = useState(false);
  const [reauthLoading,setReauthLoading]= useState(false);
  const [reauthError,  setReauthError]  = useState("");

  async function load() {
    const [cfgR, logR] = await Promise.all([
      fetch(apiPath("/admin/siem"), { credentials: "include" }),
      fetch(apiPath("/admin/siem/delivery-log"), { credentials: "include" }),
    ]);
    const d = await cfgR.json();
    setCfg(d);
    setForm({ siem_type: d.siem_type ?? "splunk_hec", url: d.url ?? "", token: "", min_severity: d.min_severity ?? "medium", enabled: d.enabled ?? false });
    setLogs((await logR.json()).items ?? []);
  }

  useEffect(() => { load(); }, []);

  async function doReauth(password: string) {
    setReauthLoading(true); setReauthError("");
    const r = await fetch(apiPath("/auth/reauth"), {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": getCSRF() },
      body: JSON.stringify({ password }),
    });
    if (!r.ok) { setReauthError("Incorrect password"); setReauthLoading(false); return; }
    setReauthOpen(false); setReauthLoading(false);
    await doSave();
  }

  async function doSave() {
    setSaving(true);
    await fetch(apiPath("/admin/siem"), {
      method: "PUT", credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": getCSRF() },
      body: JSON.stringify({ ...form, token: form.token || undefined }),
    });
    setSaving(false); load();
  }

  async function testSIEM() {
    setTesting(true); setTestResult(null);
    const r = await fetch(apiPath("/admin/siem/test"), {
      method: "POST", credentials: "include",
      headers: { "X-CSRF-Token": getCSRF() },
    });
    const d = await r.json();
    setTestResult({ ok: r.ok, message: d.http_status ? `HTTP ${d.http_status}` : d.detail?.error ?? "Unknown" });
    setTesting(false); load();
  }

  const f = (k: string) => form[k] ?? "";
  const set = (k: string, v: any) => setForm((p: any) => ({ ...p, [k]: v }));

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2"><Database className="w-5 h-5" />SIEM Integration</h1>
          <p className="text-sm text-text-muted mt-0.5">Splunk HEC and webhook delivery</p>
        </div>
        <div className="flex gap-2">
          <button className="btn-secondary flex items-center gap-2" onClick={testSIEM} disabled={testing || !cfg.configured}>
            <Send className="w-4 h-4" />{testing ? "Sending…" : "Test Delivery"}
          </button>
          <button className="btn-primary" onClick={() => setReauthOpen(true)} disabled={saving}>{saving ? "Saving…" : "Save"}</button>
        </div>
      </div>

      {testResult && (
        <div className={`card p-3 text-sm ${testResult.ok ? "border-severity-low/40 text-severity-low" : "border-severity-critical/40 text-severity-critical"}`}>
          {testResult.ok ? "✓" : "✗"} {testResult.message}
        </div>
      )}

      <div className="card p-5 space-y-4">
        <div className="flex items-center justify-between">
          <p className="font-semibold text-sm">Enable SIEM Forwarding</p>
          <button onClick={() => set("enabled", !form.enabled)}
            className={`relative inline-flex h-6 w-11 rounded-full transition-colors ${form.enabled ? "bg-accent" : "bg-bg-border"}`}>
            <span className={`inline-block w-4 h-4 rounded-full bg-white transition-transform m-1 ${form.enabled ? "translate-x-5" : "translate-x-0"}`} />
          </button>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div><label>SIEM Type</label>
            <select className="select" value={f("siem_type")} onChange={e => set("siem_type", e.target.value)}>
              <option value="splunk_hec">Splunk HEC</option>
              <option value="webhook">Generic Webhook</option>
              <option value="syslog_cef">Syslog (CEF)</option>
            </select>
          </div>
          <div><label>Minimum Severity</label>
            <select className="select" value={f("min_severity")} onChange={e => set("min_severity", e.target.value)}>
              {["low","medium","high","critical"].map(s => <option key={s} value={s} className="capitalize">{s}</option>)}
            </select>
          </div>
          <div className="col-span-2">
            <label>{isSyslog ? "Syslog Host:Port" : "Endpoint URL"}</label>
            <input className="input" value={f("url")} onChange={e => set("url", e.target.value)}
              placeholder={isSyslog ? "192.168.1.100:514" : "https://splunk.example.com:8088/services/collector/event"} />
            {isSyslog && <p className="text-xs text-text-faint mt-1">UDP syslog with CEF format. Default port: 514.</p>}
          </div>
          {!isSyslog && (
            <div className="col-span-2">
              <label>{form.siem_type === "splunk_hec" ? "HEC Token" : "Bearer Token (optional)"}</label>
              <div className="relative">
                <input className="input pr-9" type={showToken ? "text" : "password"}
                  value={f("token")} onChange={e => set("token", e.target.value)}
                  placeholder={cfg.configured ? "Leave blank to keep existing" : ""} />
                <button type="button" onClick={() => setShowToken(v => !v)} className="absolute right-2 top-2 text-text-faint hover:text-text-primary">
                  {showToken ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Delivery log */}
      <div className="card overflow-hidden">
        <div className="px-4 py-3 border-b border-bg-border">
          <h2 className="font-semibold text-sm">Delivery Log</h2>
        </div>
        <table className="data-table">
          <thead><tr><th>Time</th><th>Type</th><th>Status</th><th>HTTP</th><th>Error</th></tr></thead>
          <tbody>
            {logs.length === 0 ? (
              <tr><td colSpan={5} className="text-center text-text-faint py-8">No deliveries yet</td></tr>
            ) : logs.map((l) => (
              <tr key={l.id}>
                <td className="text-xs font-mono">{formatDateTime(l.delivered_at)}</td>
                <td className="text-xs uppercase">{l.siem_type}</td>
                <td><span className={l.status === "success" ? "badge-low" : "badge-critical"}>{l.status}</span></td>
                <td className="text-xs tabular-nums">{l.http_status ?? "—"}</td>
                <td className="text-xs text-text-faint truncate max-w-xs">{l.error_detail ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
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
