"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  AlertTriangle,
  CheckCircle,
  ChevronDown,
  ChevronRight,
  Copy,
  Pencil,
  Plus,
  Settings2,
  Terminal,
  Trash2,
  Wifi,
  WifiOff,
  X,
} from "lucide-react";
import { HealthBadge, SeverityBadge, formatRelative, ReauthModal } from "@/components/ui";
import { apiPath, streamUrl } from "@/lib/api";

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

const TRIAGE_BADGE: Record<string, string> = {
  new:            "badge-noise",
  investigating:  "badge-warning",
  reviewed:       "badge-success",
  false_positive: "text-text-faint text-xs",
  escalated:      "badge-critical",
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
    // ignore
  }
  return `Request failed (${response.status})`;
}

export default function SensorsPage() {
  const router = useRouter();
  const [sensors,       setSensors]       = useState<any[]>([]);
  const [user,          setUser]          = useState<any>(null);
  const [loading,       setLoading]       = useState(true);
  const [newName,       setNewName]       = useState("");
  const [newPayload,    setNewPayload]    = useState<OnboardingPayload | null>(null);
  const [copiedField,   setCopiedField]   = useState<"token" | "install" | "command" | "env" | null>(null);
  const [generating,    setGenerating]    = useState(false);
  const [showForm,      setShowForm]      = useState(false);
  const [formError,     setFormError]     = useState("");
  const [selected,      setSelected]      = useState<Set<string>>(new Set());
  const [revokeTargets, setRevokeTargets] = useState<string[]>([]);
  const [reauthOpen,    setReauthOpen]    = useState(false);
  const [reauthLoading, setReauthLoading] = useState(false);
  const [reauthError,   setReauthError]   = useState("");

  // D1: inline rename
  const [editingId,   setEditingId]   = useState<string | null>(null);
  const [editingName, setEditingName] = useState("");

  // D2: expand sessions
  const [expandedId,       setExpandedId]       = useState<string | null>(null);
  const [expandedSessions, setExpandedSessions] = useState<any[]>([]);
  const [sessionsLoading,  setSessionsLoading]  = useState(false);

  // Q1: sensor config modal
  const [configSensorId,  setConfigSensorId]  = useState<string | null>(null);
  const [configForm,      setConfigForm]      = useState<any>({});
  const [configSaving,    setConfigSaving]    = useState(false);
  const [configSaved,     setConfigSaved]     = useState(false);

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

  useEffect(() => { void load(); }, []);

  // SSE: react instantly to sensor health changes without polling
  useEffect(() => {
    const es = new EventSource(streamUrl(), { withCredentials: true });
    es.addEventListener("health_update", (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data as string);
        if (!data.sensor_id) return;
        setSensors((prev) =>
          prev.map((s) => {
            if (s.id !== data.sensor_id) return s;
            if (data.status === "offline") return { ...s, status: "offline", health: null };
            if (data.status === "active")  return { ...s, status: "active" };
            if (data.cpu_percent !== undefined) return { ...s, health: { ...(s.health ?? {}), ...data } };
            return s;
          })
        );
      } catch { /* ignore */ }
    });
    es.onerror = () => { void load(); };
    return () => es.close();
  // eslint-disable-next-line react-hooks/exhaustive-deps
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

  // D1 — rename
  function startEdit(s: any) {
    setEditingId(s.id);
    setEditingName(s.name);
  }

  function cancelEdit() {
    setEditingId(null);
    setEditingName("");
  }

  async function saveRename(sensorId: string) {
    const name = editingName.trim();
    if (!name) return;
    const r = await fetch(apiPath(`/sensors/${sensorId}`), {
      method: "PATCH",
      credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": getCSRF() },
      body: JSON.stringify({ name }),
    });
    if (r.ok) {
      setSensors((prev) => prev.map((s) => s.id === sensorId ? { ...s, name } : s));
      cancelEdit();
    }
  }

  // D2 — expand sessions
  async function toggleExpand(sensorId: string) {
    if (expandedId === sensorId) {
      setExpandedId(null);
      setExpandedSessions([]);
      return;
    }
    setExpandedId(sensorId);
    setSessionsLoading(true);
    const r = await fetch(apiPath(`/sensors/${sensorId}/sessions?limit=10`), { credentials: "include" });
    if (r.ok) {
      const d = await r.json();
      setExpandedSessions(d.items ?? []);
    }
    setSessionsLoading(false);
  }

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
    await Promise.all(revokeTargets.map((id) => doRevoke(id)));
    setSelected(new Set());
    setRevokeTargets([]);
    void load();
  }

  function startRevoke(sensorId: string) { setRevokeTargets([sensorId]); setReauthOpen(true); }
  function startBulkRevoke() { setRevokeTargets([...selected]); setReauthOpen(true); }

  async function doRevoke(sensorId: string) {
    await fetch(apiPath(`/sensors/${sensorId}`), {
      method: "DELETE", credentials: "include",
      headers: { "X-CSRF-Token": getCSRF() },
    });
  }

  function toggleSelect(id: string) {
    setSelected((prev) => { const next = new Set(prev); next.has(id) ? next.delete(id) : next.add(id); return next; });
  }
  function toggleSelectAll() {
    const deletable = sensors.filter((s) => s.status !== "revoked").map((s) => s.id);
    setSelected((prev) => prev.size === deletable.length ? new Set() : new Set(deletable));
  }
  async function openConfig(sensorId: string) {
    const r = await fetch(apiPath(`/sensors/${sensorId}/config`), { credentials: "include" });
    if (r.ok) {
      const d = await r.json();
      setConfigForm(d.config ?? {});
    }
    setConfigSensorId(sensorId);
    setConfigSaved(false);
  }

  async function saveConfig() {
    if (!configSensorId) return;
    setConfigSaving(true);
    const r = await fetch(apiPath(`/sensors/${configSensorId}/config`), {
      method: "PATCH", credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": getCSRF() },
      body: JSON.stringify({
        s7_plc_name:          configForm.s7_plc_name          || undefined,
        s7_module_type:       configForm.s7_module_type        || undefined,
        s7_serial_number:     configForm.s7_serial_number      || undefined,
        hmi_brand_name:       configForm.hmi_brand_name        || undefined,
        hmi_plant_name:       configForm.hmi_plant_name        || undefined,
        brute_force_threshold: configForm.brute_force_threshold != null
          ? Number(configForm.brute_force_threshold) : undefined,
        stateful_s7_memory:   configForm.stateful_s7_memory,
      }),
    });
    setConfigSaving(false);
    if (r.ok) { setConfigSaved(true); setTimeout(() => setConfigSaved(false), 1500); }
  }

  function copyValue(field: "token" | "install" | "command" | "env", text: string) {
    void navigator.clipboard.writeText(text);
    setCopiedField(field);
    window.setTimeout(() => setCopiedField(null), 2000);
  }

  const isAdmin = user?.role === "superadmin";
  const colCount = isAdmin ? 9 : 7;

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
                  {copiedField === "install" ? <CheckCircle className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
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

          <details className="rounded-md border border-bg-border bg-bg-base/70 p-4">
            <summary className="cursor-pointer list-none font-semibold text-sm flex items-center gap-2">
              <span>Advanced options</span>
              <span className="text-xs text-text-faint">(pre-built image / join token / compose)</span>
            </summary>
            <div className="mt-4 space-y-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between gap-3">
                  <p className="text-xs font-semibold uppercase text-text-faint">Docker run (pre-built image)</p>
                  <button onClick={() => copyValue("command", newPayload.deployment_command)} className="btn-secondary flex items-center gap-1.5 text-xs whitespace-nowrap">
                    {copiedField === "command" ? <CheckCircle className="w-3.5 h-3.5 text-severity-low" /> : <Copy className="w-3.5 h-3.5" />}
                    {copiedField === "command" ? "Copied!" : "Copy"}
                  </button>
                </div>
                <pre className="font-mono text-xs bg-bg-base border border-bg-border rounded px-3 py-3 text-severity-low whitespace-pre-wrap break-all overflow-x-auto">
                  {newPayload.deployment_command}
                </pre>
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between gap-3">
                  <p className="text-xs font-semibold uppercase text-text-faint">Join Token (single-use)</p>
                  <button onClick={() => copyValue("token", newPayload.join_token)} className="btn-secondary flex items-center gap-1.5 text-xs whitespace-nowrap">
                    {copiedField === "token" ? <CheckCircle className="w-3.5 h-3.5 text-severity-low" /> : <Copy className="w-3.5 h-3.5" />}
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
                  <button onClick={() => copyValue("env", newPayload.env_file_snippet)} className="btn-secondary flex items-center gap-1.5 text-xs whitespace-nowrap">
                    {copiedField === "env" ? <CheckCircle className="w-3.5 h-3.5 text-severity-low" /> : <Copy className="w-3.5 h-3.5" />}
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
        {isAdmin && selected.size > 0 && (
          <div className="flex items-center justify-between px-4 py-2 border-b border-bg-border bg-red-900/10">
            <span className="text-xs text-text-muted">{selected.size} sensor{selected.size > 1 ? "s" : ""} selected</span>
            <button onClick={startBulkRevoke} className="btn-secondary text-xs px-3 py-1 flex items-center gap-1.5 text-severity-critical border-severity-critical/30 hover:bg-severity-critical/10">
              <Trash2 className="w-3.5 h-3.5" />
              Delete Selected ({selected.size})
            </button>
          </div>
        )}
        <table className="data-table">
          <thead>
            <tr>
              <th className="w-6"></th>
              {isAdmin && <th className="w-8"><input type="checkbox" className="accent-accent" checked={selected.size > 0 && selected.size === sensors.filter((s) => s.status !== "revoked").length} onChange={toggleSelectAll} /></th>}
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
              <tr><td colSpan={colCount} className="text-center text-text-faint py-12">Loading…</td></tr>
            ) : sensors.length === 0 ? (
              <tr>
                <td colSpan={colCount} className="py-12">
                  <div className="text-center text-text-faint">
                    <Wifi className="w-10 h-10 mx-auto mb-2 opacity-30" />
                    <p className="text-sm">No sensors registered</p>
                    <p className="text-xs mt-1">Generate an onboarding command to add your first sensor</p>
                  </div>
                </td>
              </tr>
            ) : sensors.map((s) => (
              <>
                <tr key={s.id} className={selected.has(s.id) ? "bg-red-900/5" : ""}>
                  {/* D2: expand toggle */}
                  <td className="w-6">
                    <button
                      onClick={() => void toggleExpand(s.id)}
                      className="text-text-faint hover:text-text-primary transition-colors p-1"
                      title="Show sessions"
                    >
                      {expandedId === s.id
                        ? <ChevronDown className="w-3.5 h-3.5" />
                        : <ChevronRight className="w-3.5 h-3.5" />}
                    </button>
                  </td>
                  {isAdmin && (
                    <td className="w-8">
                      {s.status !== "revoked" && (
                        <input type="checkbox" className="accent-accent" checked={selected.has(s.id)} onChange={() => toggleSelect(s.id)} />
                      )}
                    </td>
                  )}
                  <td>
                    <div className="flex items-center gap-2">
                      {s.status === "active"
                        ? <Wifi className="w-3.5 h-3.5 text-severity-low" />
                        : <WifiOff className="w-3.5 h-3.5 text-text-faint" />}
                      <HealthBadge status={s.status === "active" ? (s.health ? "healthy" : "degraded") : s.status} />
                    </div>
                  </td>
                  {/* D1: inline name edit */}
                  <td className="font-semibold">
                    {editingId === s.id ? (
                      <div className="flex items-center gap-1.5">
                        <input
                          className="input text-xs py-0.5 px-2 h-7 w-40"
                          value={editingName}
                          onChange={(e) => setEditingName(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") void saveRename(s.id);
                            if (e.key === "Escape") cancelEdit();
                          }}
                          autoFocus
                        />
                        <button onClick={() => void saveRename(s.id)} className="text-severity-low hover:opacity-80 p-0.5" title="Save">
                          <CheckCircle className="w-4 h-4" />
                        </button>
                        <button onClick={cancelEdit} className="text-text-faint hover:text-text-primary p-0.5" title="Cancel">
                          <X className="w-4 h-4" />
                        </button>
                      </div>
                    ) : (
                      <div className="flex items-center gap-1.5 group">
                        <span>{s.name}</span>
                        {isAdmin && (
                          <button
                            onClick={() => startEdit(s)}
                            className="opacity-0 group-hover:opacity-100 text-text-faint hover:text-text-primary transition-all p-0.5"
                            title="Rename sensor"
                          >
                            <Pencil className="w-3 h-3" />
                          </button>
                        )}
                      </div>
                    )}
                  </td>
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
                      <div className="flex items-center gap-1">
                        <button onClick={() => void openConfig(s.id)} className="text-text-faint hover:text-accent transition-colors p-1" title="Configure sensor">
                          <Settings2 className="w-4 h-4" />
                        </button>
                        {s.status !== "revoked" && (
                          <button onClick={() => startRevoke(s.id)} className="text-text-faint hover:text-severity-critical transition-colors p-1">
                            <Trash2 className="w-4 h-4" />
                          </button>
                        )}
                      </div>
                    </td>
                  )}
                </tr>

                {/* D2: expanded sessions row */}
                {expandedId === s.id && (
                  <tr key={`${s.id}-sessions`} className="bg-bg-surface/50">
                    <td colSpan={colCount} className="px-6 py-3">
                      {/* Sensor telemetry stats */}
                      {s.health && (
                        <div className="flex gap-6 mb-3 pb-3 border-b border-bg-border">
                          <div>
                            <p className="text-xs text-text-faint">CPU</p>
                            <p className="text-sm font-mono font-semibold">{s.health.cpu_percent != null ? `${s.health.cpu_percent.toFixed(1)}%` : "—"}</p>
                          </div>
                          <div>
                            <p className="text-xs text-text-faint">Memory</p>
                            <p className="text-sm font-mono font-semibold">{s.health.mem_bytes_rss != null ? `${(s.health.mem_bytes_rss / 1024 / 1024).toFixed(1)} MB` : "—"}</p>
                          </div>
                          <div>
                            <p className="text-xs text-text-faint">Events Buffered</p>
                            <p className="text-sm font-mono font-semibold">{s.health.events_buffered ?? "—"}</p>
                          </div>
                          <div>
                            <p className="text-xs text-text-faint">Events Sent</p>
                            <p className="text-sm font-mono font-semibold">{s.health.events_sent_total ?? "—"}</p>
                          </div>
                        </div>
                      )}
                      {sessionsLoading ? (
                        <p className="text-xs text-text-faint">Loading sessions…</p>
                      ) : expandedSessions.length === 0 ? (
                        <p className="text-xs text-text-faint">No sessions from this sensor yet.</p>
                      ) : (
                        <div className="space-y-1">
                          <p className="text-xs font-semibold text-text-muted uppercase mb-2">Recent Sessions</p>
                          <table className="w-full text-xs">
                            <thead>
                              <tr className="text-text-faint">
                                <th className="text-left pb-1 font-normal">Source IP</th>
                                <th className="text-left pb-1 font-normal">Protocol</th>
                                <th className="text-left pb-1 font-normal">Severity</th>
                                <th className="text-left pb-1 font-normal">Events</th>
                                <th className="text-left pb-1 font-normal">Triage</th>
                                <th className="text-left pb-1 font-normal">Started</th>
                              </tr>
                            </thead>
                            <tbody>
                              {expandedSessions.map((sess) => (
                                <tr
                                  key={sess.id}
                                  className="cursor-pointer hover:bg-bg-border/30 transition-colors"
                                  onClick={() => router.push(`/sessions/${sess.id}`)}
                                >
                                  <td className="font-mono py-0.5 pr-4">{sess.source_ip}</td>
                                  <td className="uppercase pr-4">{sess.primary_protocol ?? "—"}</td>
                                  <td className="pr-4"><SeverityBadge severity={sess.severity} /></td>
                                  <td className="pr-4">{sess.event_count}</td>
                                  <td className="pr-4">
                                    <span className={TRIAGE_BADGE[sess.triage_status] ?? "badge-noise"}>
                                      {sess.triage_status.replace("_", " ")}
                                    </span>
                                  </td>
                                  <td className="text-text-muted">{sess.started_at ? new Date(sess.started_at).toLocaleString() : "—"}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </td>
                  </tr>
                )}
              </>
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
                <div key={port} className={`rounded-md p-3 text-center border ${active ? "border-severity-low/30 bg-green-900/10" : "border-bg-border bg-bg-surface"}`}>
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

      {/* Q1: sensor config modal */}
      {configSensorId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="card w-full max-w-lg p-6 space-y-5 animate-slide-in">
            <div className="flex items-center justify-between">
              <h2 className="font-semibold text-text-primary flex items-center gap-2">
                <Settings2 className="w-4 h-4 text-accent" />
                Sensor Configuration
              </h2>
              <button onClick={() => setConfigSensorId(null)} className="text-text-faint hover:text-text-primary p-1">
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-text-muted">
              Overrides apply on next sensor reconnect. Leave blank to use sensor defaults.
            </p>

            <div className="space-y-4">
              <p className="text-xs font-semibold text-text-faint uppercase tracking-wider">S7 / PLC Identity</p>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-text-muted mb-1">PLC Name</label>
                  <input className="input text-xs" placeholder="e.g. SIMATIC S7-300"
                    value={configForm.s7_plc_name ?? ""}
                    onChange={(e) => setConfigForm((f: any) => ({ ...f, s7_plc_name: e.target.value }))} />
                </div>
                <div>
                  <label className="block text-xs text-text-muted mb-1">Module Type</label>
                  <input className="input text-xs" placeholder="e.g. CPU 315-2 DP"
                    value={configForm.s7_module_type ?? ""}
                    onChange={(e) => setConfigForm((f: any) => ({ ...f, s7_module_type: e.target.value }))} />
                </div>
                <div>
                  <label className="block text-xs text-text-muted mb-1">Serial Number</label>
                  <input className="input text-xs" placeholder="e.g. S C-X4UR71942013"
                    value={configForm.s7_serial_number ?? ""}
                    onChange={(e) => setConfigForm((f: any) => ({ ...f, s7_serial_number: e.target.value }))} />
                </div>
              </div>

              <p className="text-xs font-semibold text-text-faint uppercase tracking-wider pt-1">HMI Identity</p>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-text-muted mb-1">HMI Brand</label>
                  <input className="input text-xs" placeholder="e.g. Siemens"
                    value={configForm.hmi_brand_name ?? ""}
                    onChange={(e) => setConfigForm((f: any) => ({ ...f, hmi_brand_name: e.target.value }))} />
                </div>
                <div>
                  <label className="block text-xs text-text-muted mb-1">Plant Name</label>
                  <input className="input text-xs" placeholder="e.g. Water Treatment Plant A"
                    value={configForm.hmi_plant_name ?? ""}
                    onChange={(e) => setConfigForm((f: any) => ({ ...f, hmi_plant_name: e.target.value }))} />
                </div>
              </div>

              <p className="text-xs font-semibold text-text-faint uppercase tracking-wider pt-1">Detection Settings</p>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-text-muted mb-1">Brute Force Threshold</label>
                  <input className="input text-xs" type="number" min={1} max={100} placeholder="default: 5"
                    value={configForm.brute_force_threshold ?? ""}
                    onChange={(e) => setConfigForm((f: any) => ({ ...f, brute_force_threshold: e.target.value }))} />
                </div>
                <div className="flex items-center gap-2 pt-5">
                  <input type="checkbox" id="stateful_s7" className="w-4 h-4 accent-accent"
                    checked={configForm.stateful_s7_memory ?? true}
                    onChange={(e) => setConfigForm((f: any) => ({ ...f, stateful_s7_memory: e.target.checked }))} />
                  <label htmlFor="stateful_s7" className="text-xs text-text-muted cursor-pointer">Stateful S7 Memory</label>
                </div>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button onClick={() => setConfigSensorId(null)} className="btn-secondary text-sm">Cancel</button>
              <button onClick={() => void saveConfig()} disabled={configSaving} className="btn-primary text-sm disabled:opacity-60 flex items-center gap-2">
                {configSaving ? "Saving…" : configSaved ? "Saved!" : "Save Configuration"}
              </button>
            </div>
          </div>
        </div>
      )}

      <ReauthModal
        open={reauthOpen}
        onConfirm={doReauth}
        onCancel={() => { setReauthOpen(false); setRevokeTargets([]); }}
        loading={reauthLoading}
        error={reauthError}
      />
    </div>
  );
}
