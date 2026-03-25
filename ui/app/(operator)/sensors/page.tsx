"use client";

import { useEffect, useState } from "react";
import {
  AlertTriangle,
  CheckCircle,
  Copy,
  Plus,
  Terminal,
  Trash2,
  Wifi,
  WifiOff,
} from "lucide-react";
import { HealthBadge, formatRelative, ReauthModal } from "@/components/ui";
import { apiPath } from "@/lib/api";

type OnboardingPayload = {
  sensor_id: string;
  sensor_name: string;
  join_token: string;
  expires_at: string;
  sensor_cert_enc_key: string;
  manager_addr: string;
  sensor_image_ref: string;
  installer_url?: string;
  installer_command?: string;
  deployment_command: string;
  env_file_snippet: string;
  compose_command: string;
  warnings?: string[];
  warning?: string;
  remote_ready: boolean;
};

function getCSRF(): string {
  return document.cookie.match(/csrf_token=([^;]+)/)?.[1] ?? "";
}

async function readErrorMessage(response: Response): Promise<string> {
  try {
    const data = await response.json();
    if (typeof data?.detail === "string") return data.detail;
    if (typeof data?.detail?.message === "string") return data.detail.message;
    if (typeof data?.detail?.error === "string") return data.detail.error;
  } catch {
    // Ignore non-JSON errors and fall back to status text.
  }
  return `Request failed (${response.status})`;
}

export default function SensorsPage() {
  const [sensors,       setSensors]       = useState<any[]>([]);
  const [user,          setUser]          = useState<any>(null);
  const [loading,       setLoading]       = useState(true);
  const [newName,       setNewName]       = useState("");
  const [newPayload,    setNewPayload]    = useState<OnboardingPayload | null>(null);
  const [copiedField,   setCopiedField]   = useState<"token" | "install" | "command" | "env" | null>(null);
  const [generating,    setGenerating]    = useState(false);
  const [showForm,      setShowForm]      = useState(false);
  const [formError,     setFormError]     = useState("");
  const [revokeTarget,  setRevokeTarget]  = useState<string | null>(null);
  const [reauthOpen,    setReauthOpen]    = useState(false);
  const [reauthLoading, setReauthLoading] = useState(false);
  const [reauthError,   setReauthError]   = useState("");

  async function load() {
    setLoading(true);
    const [sensorRes, meRes] = await Promise.all([
      fetch(apiPath("/sensors"), { credentials: "include" }),
      fetch(apiPath("/auth/me"), { credentials: "include" }),
    ]);
    setSensors((await sensorRes.json()).items ?? []);
    setUser(await meRes.json());
    setLoading(false);
  }

  useEffect(() => {
    void load();
  }, []);

  async function generateToken() {
    if (!newName.trim()) return;
    setGenerating(true);
    setFormError("");

    const r = await fetch(apiPath("/sensors/token"), {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": getCSRF() },
      body: JSON.stringify({ sensor_name: newName.trim() }),
    });

    if (r.ok) {
      const data = await r.json();
      if (!data?.join_token || !data?.sensor_id) {
        setFormError("Manager API returned an invalid sensor onboarding payload.");
      } else if (!data?.deployment_command || !data?.manager_addr || !data?.sensor_name) {
        setFormError("Manager API is outdated. Rebuild the manager container to get remote sensor onboarding fields.");
      } else {
        setNewPayload(data);
        setNewName("");
        setShowForm(false);
        void load();
      }
    } else {
      setFormError(await readErrorMessage(r));
    }

    setGenerating(false);
  }

  async function doReauth(password: string) {
    setReauthLoading(true);
    setReauthError("");
    const r = await fetch(apiPath("/auth/reauth"), {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": getCSRF() },
      body: JSON.stringify({ password }),
    });
    if (!r.ok) {
      setReauthError("Invalid password");
      setReauthLoading(false);
      return;
    }
    setReauthOpen(false);
    setReauthLoading(false);
    if (revokeTarget) await doRevoke(revokeTarget);
  }

  function startRevoke(sensorId: string) {
    setRevokeTarget(sensorId);
    setReauthOpen(true);
  }

  async function doRevoke(sensorId: string) {
    await fetch(apiPath(`/sensors/${sensorId}`), {
      method: "DELETE", credentials: "include",
      headers: { "X-CSRF-Token": getCSRF() },
    });
    setRevokeTarget(null);
    void load();
  }

  function copyValue(field: "token" | "install" | "command" | "env", text: string) {
    void navigator.clipboard.writeText(text);
    setCopiedField(field);
    window.setTimeout(() => setCopiedField(null), 2000);
  }

  const isAdmin = user?.role === "superadmin";

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-text-primary">Sensors</h1>
          <p className="text-sm text-text-muted mt-0.5">Registered OT decoy sensors</p>
        </div>
        {isAdmin && (
          <button onClick={() => setShowForm((s) => !s)} className="btn-primary flex items-center gap-2">
            <Plus className="w-4 h-4" />Add Sensor
          </button>
        )}
      </div>

      {showForm && (
        <div className="card p-4 animate-slide-in">
          <h2 className="font-semibold text-sm mb-3">Generate Sensor Onboarding Command</h2>
          <div className="flex gap-3">
            <input
              className="input flex-1"
              placeholder="Sensor name (e.g. ot-segment-a)"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && void generateToken()}
            />
            <button className="btn-primary" disabled={generating || !newName.trim()} onClick={() => void generateToken()}>
              {generating ? "Generating…" : "Generate"}
            </button>
          </div>
          <p className="text-xs text-text-faint mt-2">
            This creates a single-use join token, a one-line Docker command, and a manual `.env.sensor` snippet.
          </p>
          {formError && (
            <div className="mt-3 rounded-md border border-severity-critical/30 bg-red-900/10 px-3 py-2 text-xs text-red-300">
              {formError}
            </div>
          )}
        </div>
      )}

      {newPayload && (
        <div className="card p-5 border-accent/40 animate-slide-in space-y-4">
          <div className="flex items-start gap-3">
            <CheckCircle className="w-5 h-5 text-severity-low flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <p className="font-semibold text-sm mb-1">Sensor Onboarding Ready</p>
              <p className="text-xs text-text-muted">
                Copy the install command below and run it on the target host. It will clone the repo, build the
                sensor image, and start the container automatically.
              </p>
            </div>
          </div>

          <div className="grid gap-3 md:grid-cols-2">
            <div className="rounded-md border border-bg-border bg-bg-base/70 p-3">
              <p className="text-xs uppercase text-text-faint mb-1">Sensor</p>
              <p className="font-mono text-xs break-all">{newPayload.sensor_name}</p>
            </div>
            <div className="rounded-md border border-bg-border bg-bg-base/70 p-3">
              <p className="text-xs uppercase text-text-faint mb-1">Manager gRPC</p>
              <p className="font-mono text-xs break-all">{newPayload.manager_addr}</p>
            </div>
            <div className="rounded-md border border-bg-border bg-bg-base/70 p-3">
              <p className="text-xs uppercase text-text-faint mb-1">Token Expires</p>
              <p className="font-mono text-xs break-all">{newPayload.expires_at}</p>
            </div>
          </div>

          {newPayload.warnings && newPayload.warnings.length > 0 && (
            <div className="rounded-md border border-yellow-500/30 bg-yellow-900/10 p-3">
              <div className="flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 mt-0.5 text-yellow-300 flex-shrink-0" />
                <div className="space-y-1">
                  <p className="text-xs font-semibold uppercase text-yellow-200">Deployment warnings</p>
                  {newPayload.warnings.map((warning) => (
                    <p key={warning} className="text-xs text-yellow-100/90">{warning}</p>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* PRIMARY: single-command installer */}
          {newPayload.installer_command && (
            <div className="rounded-md border-2 border-accent/50 bg-bg-base/70 p-4 space-y-3">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-accent" />
                  <p className="font-semibold text-sm">Install Command</p>
                  <span className="text-xs px-1.5 py-0.5 rounded bg-accent/20 text-accent font-medium">run on target host</span>
                </div>
                <button
                  onClick={() => copyValue("install", newPayload.installer_command!)}
                  className="btn-primary flex items-center gap-1.5 text-xs whitespace-nowrap"
                >
                  {copiedField === "install"
                    ? <CheckCircle className="w-3.5 h-3.5" />
                    : <Copy className="w-3.5 h-3.5" />}
                  {copiedField === "install" ? "Copied!" : "Copy"}
                </button>
              </div>
              <pre className="font-mono text-xs bg-bg-base border border-accent/20 rounded px-3 py-3 text-severity-low whitespace-pre-wrap break-all overflow-x-auto">
                {newPayload.installer_command}
              </pre>
              <p className="text-xs text-text-faint">
                Requires Docker 24+ and git. Clones the repo, builds the sensor image locally, and starts the container.
                Takes ~2 min on first run.
              </p>
            </div>
          )}

          {/* ADVANCED: pre-built image, join token, compose */}
          <details className="rounded-md border border-bg-border bg-bg-base/70 p-4">
            <summary className="cursor-pointer list-none font-semibold text-sm flex items-center gap-2">
              <span>Advanced options</span>
              <span className="text-xs text-text-faint">(pre-built image / join token / compose)</span>
            </summary>
            <div className="mt-4 space-y-4">

              <div className="space-y-2">
                <div className="flex items-center justify-between gap-3">
                  <p className="text-xs font-semibold uppercase text-text-faint">Docker run (pre-built image)</p>
                  <button
                    onClick={() => copyValue("command", newPayload.deployment_command)}
                    className="btn-secondary flex items-center gap-1.5 text-xs whitespace-nowrap"
                  >
                    {copiedField === "command"
                      ? <CheckCircle className="w-3.5 h-3.5 text-severity-low" />
                      : <Copy className="w-3.5 h-3.5" />}
                    {copiedField === "command" ? "Copied!" : "Copy"}
                  </button>
                </div>
                <pre className="font-mono text-xs bg-bg-base border border-bg-border rounded px-3 py-3 text-severity-low whitespace-pre-wrap break-all overflow-x-auto">
                  {newPayload.deployment_command}
                </pre>
                <p className="text-xs text-text-faint">
                  Use this only if you have already built and pushed the sensor image to a registry.
                  Set <code className="text-accent">SENSOR_IMAGE_REF</code> in .env before generating.
                </p>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between gap-3">
                  <p className="text-xs font-semibold uppercase text-text-faint">Join Token (single-use)</p>
                  <button
                    onClick={() => copyValue("token", newPayload.join_token)}
                    className="btn-secondary flex items-center gap-1.5 text-xs whitespace-nowrap"
                  >
                    {copiedField === "token"
                      ? <CheckCircle className="w-3.5 h-3.5 text-severity-low" />
                      : <Copy className="w-3.5 h-3.5" />}
                    {copiedField === "token" ? "Copied!" : "Copy"}
                  </button>
                </div>
                <code className="block font-mono text-xs bg-bg-base border border-bg-border rounded px-3 py-3 text-severity-low break-all">
                  {newPayload.join_token}
                </code>
                <p className="text-xs text-text-faint">{newPayload.warning}</p>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between gap-3">
                  <p className="text-xs font-semibold uppercase text-text-faint">.env.sensor (Docker Compose path)</p>
                  <button
                    onClick={() => copyValue("env", newPayload.env_file_snippet)}
                    className="btn-secondary flex items-center gap-1.5 text-xs whitespace-nowrap"
                  >
                    {copiedField === "env"
                      ? <CheckCircle className="w-3.5 h-3.5 text-severity-low" />
                      : <Copy className="w-3.5 h-3.5" />}
                    {copiedField === "env" ? "Copied!" : "Copy"}
                  </button>
                </div>
                <pre className="font-mono text-xs bg-bg-base border border-bg-border rounded px-3 py-3 whitespace-pre-wrap break-all overflow-x-auto">
                  {newPayload.env_file_snippet}
                </pre>
                <p className="text-xs text-text-muted">Then run:</p>
                <pre className="font-mono text-xs bg-bg-base border border-bg-border rounded px-3 py-3 whitespace-pre-wrap break-all overflow-x-auto">
                  {newPayload.compose_command}
                </pre>
              </div>

            </div>
          </details>
        </div>
      )}

      <div className="card overflow-hidden">
        <table className="data-table">
          <thead>
            <tr>
              <th>Status</th>
              <th>Name</th>
              <th>IP</th>
              <th>Version</th>
              <th>Capabilities</th>
              <th>Last Seen</th>
              {isAdmin && <th></th>}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={7} className="text-center text-text-faint py-12">Loading…</td></tr>
            ) : sensors.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-12">
                  <div className="text-center text-text-faint">
                    <Wifi className="w-10 h-10 mx-auto mb-2 opacity-30" />
                    <p className="text-sm">No sensors registered</p>
                    <p className="text-xs mt-1">Generate an onboarding command to add your first sensor</p>
                  </div>
                </td>
              </tr>
            ) : sensors.map((s) => (
              <tr key={s.id}>
                <td>
                  <div className="flex items-center gap-2">
                    {s.status === "active"
                      ? <Wifi className="w-3.5 h-3.5 text-severity-low" />
                      : <WifiOff className="w-3.5 h-3.5 text-text-faint" />}
                    <HealthBadge status={s.status === "active" ? (s.health ? "healthy" : "degraded") : s.status} />
                  </div>
                </td>
                <td className="font-semibold">{s.name}</td>
                <td className="font-mono text-xs">{s.reported_ip ?? "—"}</td>
                <td className="text-xs text-text-muted">{s.version ?? "—"}</td>
                <td>
                  <div className="flex gap-1 flex-wrap">
                    {(s.capabilities ?? []).map((cap: string) => (
                      <span key={cap} className="badge-noise uppercase">{cap}</span>
                    ))}
                  </div>
                </td>
                <td className="text-xs text-text-muted">{formatRelative(s.last_seen_at)}</td>
                {isAdmin && (
                  <td>
                    {s.status !== "revoked" && (
                      <button
                        onClick={() => startRevoke(s.id)}
                        className="text-text-faint hover:text-severity-critical transition-colors p-1"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {sensors.some((s) => s.health?.port_status) && (
        <div className="card p-4">
          <h2 className="font-semibold text-sm mb-3 text-text-muted uppercase">Port Coverage</h2>
          <div className="grid grid-cols-4 gap-3">
            {[102, 502, 80, 443].map((port) => {
              const active = sensors.some((s) =>
                s.health?.port_status?.find((p: any) => p.port === port && p.listening),
              );
              return (
                <div
                  key={port}
                  className={`rounded-md p-3 text-center border ${
                    active ? "border-severity-low/30 bg-green-900/10" : "border-bg-border bg-bg-surface"
                  }`}
                >
                  <p className={`text-lg font-bold font-mono ${active ? "text-severity-low" : "text-text-faint"}`}>{port}</p>
                  <p className="text-xs text-text-muted">
                    {port === 102 ? "S7comm" : port === 502 ? "Modbus" : port === 80 ? "HMI HTTP" : "HMI HTTPS"}
                  </p>
                </div>
              );
            })}
          </div>
        </div>
      )}

      <ReauthModal
        open={reauthOpen}
        onConfirm={doReauth}
        onCancel={() => { setReauthOpen(false); setRevokeTarget(null); }}
        loading={reauthLoading}
        error={reauthError}
      />
    </div>
  );
}
