"use client";

import { useEffect, useState } from "react";
import { Bell, Send, Eye, EyeOff } from "lucide-react";
import { ReauthModal, formatDateTime } from "@/components/ui";
import { apiPath } from "@/lib/api";
const getCSRF = () => document.cookie.match(/csrf_token=([^;]+)/)?.[1] ?? "";

const SEVERITIES = ["low", "medium", "high", "critical"];

export default function NotificationsPage() {
  const [cfg,          setCfg]          = useState<any>({});
  const [form,         setForm]         = useState<any>({});
  const [logs,         setLogs]         = useState<any[]>([]);
  const [saving,       setSaving]       = useState(false);
  const [testing,      setTesting]      = useState(false);
  const [testResult,   setTestResult]   = useState<{ ok: boolean; message: string } | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [reauthOpen,   setReauthOpen]   = useState(false);
  const [reauthLoading,setReauthLoading]= useState(false);
  const [reauthError,  setReauthError]  = useState("");
  const [pendingAction,setPendingAction]= useState<"save" | null>(null);

  async function load() {
    const [cfgR, logR] = await Promise.all([
      fetch(apiPath("/admin/smtp"), { credentials: "include" }),
      fetch(apiPath("/admin/smtp/delivery-log"), { credentials: "include" }),
    ]);
    const d = await cfgR.json();
    setCfg(d);
    setForm({
      host:            d.host ?? "",
      port:            d.port ?? 587,
      username:        d.username ?? "",
      password:        "",
      from_address:    d.from_address ?? "",
      to_addresses:    (d.to_addresses ?? []).join(", "),
      use_tls:         d.use_tls ?? true,
      use_starttls:    d.use_starttls ?? false,
      min_severity:    d.min_severity ?? "high",
      health_alerts:   d.health_alerts ?? true,
      cooldown_seconds: d.cooldown_seconds ?? 300,
      enabled:         d.enabled ?? false,
    });
    if (logR.ok) setLogs((await logR.json()).items ?? []);
  }

  useEffect(() => { load(); }, []);

  function startSave() { setPendingAction("save"); setReauthOpen(true); }

  async function doReauth(password: string) {
    setReauthLoading(true); setReauthError("");
    const r = await fetch(apiPath("/auth/reauth"), {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": getCSRF() },
      body: JSON.stringify({ password }),
    });
    if (!r.ok) { setReauthError("Incorrect password"); setReauthLoading(false); return; }
    setReauthOpen(false); setReauthLoading(false);
    if (pendingAction === "save") await doSave();
  }

  async function doSave() {
    setSaving(true);
    const payload = {
      ...form,
      port: Number(form.port),
      cooldown_seconds: Number(form.cooldown_seconds),
      to_addresses: form.to_addresses.split(",").map((s: string) => s.trim()).filter(Boolean),
      password: form.password || undefined,
    };
    await fetch(apiPath("/admin/smtp"), {
      method: "PUT", credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": getCSRF() },
      body: JSON.stringify(payload),
    });
    setSaving(false);
    load();
  }

  async function testSMTP() {
    setTesting(true); setTestResult(null);
    const r = await fetch(apiPath("/admin/smtp/test"), {
      method: "POST", credentials: "include",
      headers: { "X-CSRF-Token": getCSRF() },
    });
    const d = await r.json();
    setTestResult({ ok: r.ok, message: d.message ?? d.detail?.error ?? "Unknown result" });
    setTesting(false);
  }

  const f = (k: string) => form[k] ?? "";
  const set = (k: string, v: any) => setForm((p: any) => ({ ...p, [k]: v }));

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2"><Bell className="w-5 h-5" />Notifications</h1>
          <p className="text-sm text-text-muted mt-0.5">SMTP alert configuration</p>
        </div>
        <div className="flex gap-2">
          <button className="btn-secondary flex items-center gap-2" onClick={testSMTP} disabled={testing || !cfg.configured}>
            <Send className="w-4 h-4" />{testing ? "Sending…" : "Test"}
          </button>
          <button className="btn-primary" onClick={startSave} disabled={saving}>
            {saving ? "Saving…" : "Save Changes"}
          </button>
        </div>
      </div>

      {testResult && (
        <div className={`card p-3 text-sm ${testResult.ok ? "border-severity-low/40 text-severity-low" : "border-severity-critical/40 text-severity-critical"}`}>
          {testResult.ok ? "✓" : "✗"} {testResult.message}
        </div>
      )}

      <div className="card p-5 space-y-5">
        {/* Enable toggle */}
        <div className="flex items-center justify-between">
          <div>
            <p className="font-semibold text-sm">Enable Email Notifications</p>
            <p className="text-xs text-text-muted mt-0.5">Send alerts for high-severity events</p>
          </div>
          <button onClick={() => set("enabled", !form.enabled)}
            className={`relative inline-flex h-6 w-11 rounded-full transition-colors ${form.enabled ? "bg-accent" : "bg-bg-border"}`}>
            <span className={`inline-block w-4 h-4 rounded-full bg-white transition-transform m-1 ${form.enabled ? "translate-x-5" : "translate-x-0"}`} />
          </button>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div><label>SMTP Host</label><input className="input" value={f("host")} onChange={e => set("host", e.target.value)} placeholder="smtp.example.com" /></div>
          <div><label>Port</label><input className="input" type="number" value={f("port")} onChange={e => set("port", e.target.value)} /></div>
          <div><label>Username</label><input className="input" value={f("username")} onChange={e => set("username", e.target.value)} /></div>
          <div>
            <label>Password</label>
            <div className="relative">
              <input className="input pr-9" type={showPassword ? "text" : "password"}
                value={f("password")} onChange={e => set("password", e.target.value)}
                placeholder={cfg.configured ? "Leave blank to keep existing" : ""} />
              <button type="button" onClick={() => setShowPassword(v => !v)}
                className="absolute right-2 top-2 text-text-faint hover:text-text-primary">
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>
          <div><label>From Address</label><input className="input" value={f("from_address")} onChange={e => set("from_address", e.target.value)} /></div>
          <div><label>To Addresses (comma-separated)</label><input className="input" value={f("to_addresses")} onChange={e => set("to_addresses", e.target.value)} /></div>
          <div>
            <label>Minimum Severity</label>
            <select className="select" value={f("min_severity")} onChange={e => set("min_severity", e.target.value)}>
              {SEVERITIES.map(s => <option key={s} value={s} className="capitalize">{s}</option>)}
            </select>
          </div>
          <div><label>Cooldown (seconds)</label><input className="input" type="number" value={f("cooldown_seconds")} onChange={e => set("cooldown_seconds", e.target.value)} /></div>
        </div>

        <div className="flex gap-4">
          {[["use_tls", "Use TLS (SMTP_SSL)"], ["use_starttls", "Use STARTTLS"], ["health_alerts", "Health Threshold Alerts"]].map(([k, label]) => (
            <label key={k} className="flex items-center gap-2 cursor-pointer">
              <input type="checkbox" checked={!!form[k]} onChange={e => set(k, e.target.checked)}
                className="w-4 h-4 rounded border-bg-border bg-bg-base accent-accent" />
              <span className="text-sm text-text-muted">{label}</span>
            </label>
          ))}
        </div>
      </div>

      {/* Delivery log */}
      <div className="card overflow-hidden">
        <div className="px-4 py-3 border-b border-bg-border">
          <h2 className="font-semibold text-sm">Email Delivery Log</h2>
        </div>
        <table className="data-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Status</th>
              <th>Recipient</th>
              <th>Subject</th>
              <th>Error</th>
            </tr>
          </thead>
          <tbody>
            {logs.length === 0 ? (
              <tr><td colSpan={5} className="text-center text-text-faint py-8">No deliveries yet</td></tr>
            ) : logs.map((l) => (
              <tr key={l.id}>
                <td className="text-xs font-mono whitespace-nowrap">{formatDateTime(l.delivered_at)}</td>
                <td>
                  <span className={
                    l.status === "success" ? "badge-low" :
                    l.status === "skipped" ? "badge-noise" :
                    "badge-critical"
                  }>{l.status}</span>
                </td>
                <td className="text-xs text-text-muted truncate max-w-xs">{l.recipient ?? "—"}</td>
                <td className="text-xs text-text-muted truncate max-w-xs">{l.subject ?? "—"}</td>
                <td className="text-xs text-text-faint truncate max-w-xs">{l.error_detail ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <ReauthModal
        open={reauthOpen}
        onConfirm={doReauth}
        onCancel={() => { setReauthOpen(false); setPendingAction(null); }}
        loading={reauthLoading}
        error={reauthError}
      />
    </div>
  );
}
