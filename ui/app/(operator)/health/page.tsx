"use client";

import { useEffect, useState } from "react";
import { Activity, Database, Cpu, Wifi, Server, RefreshCw } from "lucide-react";
import { HealthBadge, formatRelative } from "@/components/ui";
import { apiPath } from "@/lib/api";

interface ServiceHealth {
  status:  string;
  detail?: string;
  fix?:    string;
  count?:  number;
  sensors?: SensorStatus[];
}

interface SensorStatus {
  id:        string;
  name:      string;
  status:    string;
  last_seen: string;
}

interface HealthData {
  status:   string;
  services: Record<string, ServiceHealth>;
}

const SERVICE_META: Record<string, { label: string; icon: any; desc: string }> = {
  postgres:   { label: "PostgreSQL 16", icon: Database, desc: "Primary data store" },
  redis:      { label: "Redis 7",       icon: Server,   desc: "Pub/sub + rate limiting" },
  sensors:    { label: "Sensors",       icon: Wifi,     desc: "Active OT decoy sensors" },
  llm_engine: { label: "LLM Engine",   icon: Cpu,      desc: "Optional AI analysis" },
};

export default function HealthPage() {
  const [health,  setHealth]  = useState<HealthData | null>(null);
  const [loading, setLoading] = useState(true);

  async function load() {
    setLoading(true);
    try {
      const r = await fetch(apiPath("/health"), { credentials: "include" });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setHealth(await r.json());
    } catch {
      // silently ignore — loading spinner stops, health stays null
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  const overallColor = {
    healthy:  "text-severity-low",
    degraded: "text-severity-medium",
    unhealthy:"text-severity-critical",
  }[health?.status ?? ""] ?? "text-text-muted";

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-text-primary">Platform Health</h1>
          <p className="text-sm text-text-muted mt-0.5">Service status and sensor heartbeats</p>
        </div>
        <div className="flex items-center gap-3">
          {health && (
            <div className="flex items-center gap-2">
              <span className="text-sm text-text-muted">Overall:</span>
              <span className={`font-semibold capitalize ${overallColor}`}>{health.status}</span>
            </div>
          )}
          <button onClick={load} className="btn-secondary p-2">
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* Service cards grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {health && Object.entries(health.services).map(([key, svc]) => {
          const meta = SERVICE_META[key] ?? { label: key, icon: Activity, desc: "" };
          const Icon = meta.icon;
          return (
            <div key={key} className="card p-5">
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-3">
                  <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                    svc.status === "healthy"  ? "bg-green-900/30 text-severity-low" :
                    svc.status === "degraded" ? "bg-yellow-900/30 text-severity-medium" :
                    svc.status === "disabled" ? "bg-gray-800/60 text-text-faint" :
                    "bg-red-900/30 text-severity-critical"
                  }`}>
                    <Icon className="w-5 h-5" />
                  </div>
                  <div>
                    <p className="font-semibold text-sm text-text-primary">{meta.label}</p>
                    <p className="text-xs text-text-muted">{meta.desc}</p>
                  </div>
                </div>
                <HealthBadge status={svc.status} />
              </div>

              {svc.detail && (
                <p className="text-xs text-text-muted bg-bg-base rounded px-2 py-1 mb-2 font-mono">
                  {svc.detail}
                </p>
              )}

              {svc.fix && (
                <p className="text-xs text-severity-medium mt-1">
                  Fix: {svc.fix}
                </p>
              )}

              {/* Sensor list */}
              {key === "sensors" && svc.sensors && svc.sensors.length > 0 && (
                <div className="mt-3 space-y-1.5">
                  <p className="text-xs font-semibold text-text-muted uppercase mb-2">
                    Active Sensors ({svc.count})
                  </p>
                  {svc.sensors.map((s) => (
                    <div key={s.id} className="flex items-center justify-between py-1.5 px-3 bg-bg-base rounded">
                      <div className="flex items-center gap-2">
                        <div className={`w-1.5 h-1.5 rounded-full ${
                          s.status === "healthy" ? "bg-severity-low" : "bg-severity-high"
                        }`} />
                        <span className="text-xs font-mono text-text-primary">{s.name}</span>
                      </div>
                      <span className="text-xs text-text-faint">{formatRelative(s.last_seen)}</span>
                    </div>
                  ))}
                </div>
              )}

              {key === "sensors" && (!svc.sensors || svc.sensors.length === 0) && (
                <p className="text-xs text-text-faint mt-2">
                  No active sensors. Generate a join token to add sensors.
                </p>
              )}
            </div>
          );
        })}

        {loading && !health && (
          Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="card p-5 animate-pulse">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-10 h-10 rounded-lg bg-bg-elevated" />
                <div className="space-y-2">
                  <div className="w-24 h-3 bg-bg-elevated rounded" />
                  <div className="w-32 h-2 bg-bg-elevated rounded" />
                </div>
              </div>
              <div className="w-full h-2 bg-bg-elevated rounded" />
            </div>
          ))
        )}
      </div>
    </div>
  );
}
