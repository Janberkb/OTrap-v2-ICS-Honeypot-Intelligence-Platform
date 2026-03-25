"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Settings, Users, Database, FileText, Activity } from "lucide-react";
import { HealthBadge } from "@/components/ui";
import { apiPath } from "@/lib/api";

function StatusChip({ tone, children }: { tone: "good" | "warn" | "muted"; children: React.ReactNode }) {
  const styles = {
    good: "bg-green-900/30 text-severity-low border border-green-800/40",
    warn: "bg-yellow-900/30 text-severity-medium border border-yellow-800/40",
    muted: "bg-bg-base text-text-muted border border-bg-border",
  }[tone];

  return (
    <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold ${styles}`}>
      {children}
    </span>
  );
}

interface SystemData {
  product: {
    name: string;
    version: string;
    build_ref: string;
    license_tier: string;
    deployment_mode: string;
  };
  pki: {
    ca_mode: string;
    ca_persisted: boolean;
    grpc_bind: string;
    public_manager_addr: string;
  };
  defaults: {
    join_token_ttl_hours: number;
    session_max_age_hours: number;
    sensor_image_ref: string;
    session_secure: boolean;
    docs_enabled: boolean;
  };
  background_jobs: {
    analyzer_worker: string;
    llm_engine: string;
  };
  retention_policy: {
    mode: string;
    detail: string;
  };
  backup_restore: {
    mode: string;
    detail: string;
  };
  cluster: {
    mode: string;
    detail: string;
  };
  diagnostics: {
    management_api: string;
    grpc_listener: string;
    sensor_public_manager_addr: string;
    cors_origins: string[];
    docs_enabled: boolean;
  };
}

export default function SystemPage() {
  const [health, setHealth] = useState<any>(null);
  const [system, setSystem] = useState<SystemData | null>(null);
  const [users, setUsers] = useState<any[]>([]);

  useEffect(() => {
    Promise.all([
      fetch(apiPath("/health"), { credentials: "include" }).then((r) => r.json()),
      fetch(apiPath("/admin/system"), { credentials: "include" }).then((r) => r.json()),
      fetch(apiPath("/admin/users"), { credentials: "include" }).then((r) => r.json()),
    ]).then(([healthData, systemData, usersData]) => {
      setHealth(healthData);
      setSystem(systemData);
      setUsers(usersData.items ?? []);
    });
  }, []);

  const quickLinks = [
    { href: "/admin/users", icon: Users, label: "Users", desc: `${users.length} accounts` },
    { href: "/admin/integrations", icon: Database, label: "Integrations", desc: "Email notifications and SIEM" },
    { href: "/admin/audit", icon: FileText, label: "Audit Log", desc: "Administrative activity trail" },
    { href: "/health", icon: Activity, label: "Health", desc: "Runtime service health" },
  ];

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      <div>
        <h1 className="text-xl font-bold flex items-center gap-2">
          <Settings className="w-5 h-5" />
          System
        </h1>
        <p className="text-sm text-text-muted mt-0.5">Platform control plane, defaults, and deployment diagnostics</p>
      </div>

      {health && (
        <div className="card p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="font-semibold text-sm">Platform Status</h2>
            <HealthBadge status={health.status} />
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {Object.entries(health.services ?? {}).map(([key, svc]: [string, any]) => (
              <div key={key} className="flex items-center gap-2 px-3 py-2 rounded bg-bg-base">
                <div className={`w-2 h-2 rounded-full ${
                  svc.status === "healthy"  ? "bg-severity-low" :
                  svc.status === "disabled" ? "bg-text-faint" :
                  "bg-severity-critical"
                }`} />
                <span className="text-xs text-text-muted capitalize">{key.replace("_", " ")}</span>
                <span className="text-xs text-text-primary ml-auto capitalize">{svc.status}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {system && (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="card p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="font-semibold text-sm">Version & Deployment</h2>
              <StatusChip tone="muted">{system.product.deployment_mode}</StatusChip>
            </div>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div>
                <p className="text-xs uppercase text-text-faint mb-1">Product</p>
                <p>{system.product.name}</p>
              </div>
              <div>
                <p className="text-xs uppercase text-text-faint mb-1">Version</p>
                <p>{system.product.version}</p>
              </div>
              <div>
                <p className="text-xs uppercase text-text-faint mb-1">Build Ref</p>
                <p className="font-mono text-xs text-text-muted">{system.product.build_ref}</p>
              </div>
              <div>
                <p className="text-xs uppercase text-text-faint mb-1">License</p>
                <p className="capitalize">{system.product.license_tier}</p>
              </div>
            </div>
          </div>

          <div className="card p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="font-semibold text-sm">CA & Sensor Bootstrap</h2>
              <StatusChip tone={system.pki.ca_persisted ? "good" : "warn"}>
                {system.pki.ca_mode}
              </StatusChip>
            </div>
            <div className="space-y-3 text-sm">
              <div>
                <p className="text-xs uppercase text-text-faint mb-1">gRPC Listener</p>
                <p className="font-mono text-xs text-text-muted">{system.pki.grpc_bind}</p>
              </div>
              <div>
                <p className="text-xs uppercase text-text-faint mb-1">Sensor Public Address</p>
                <p className="font-mono text-xs text-text-muted">{system.pki.public_manager_addr}</p>
              </div>
              <p className="text-xs text-text-muted">
                {system.pki.ca_persisted
                  ? "The Manager CA is persisted through environment variables and survives restarts."
                  : "The Manager CA is currently ephemeral. Persist GRPC_CA_* values to keep remote sensors stable across restarts."}
              </p>
            </div>
          </div>

          <div className="card p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="font-semibold text-sm">Platform Defaults</h2>
              <StatusChip tone="muted">read-only</StatusChip>
            </div>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div>
                <p className="text-xs uppercase text-text-faint mb-1">Join Token TTL</p>
                <p>{system.defaults.join_token_ttl_hours} hours</p>
              </div>
              <div>
                <p className="text-xs uppercase text-text-faint mb-1">Session Lifetime</p>
                <p>{system.defaults.session_max_age_hours} hours</p>
              </div>
              <div className="col-span-2">
                <p className="text-xs uppercase text-text-faint mb-1">Default Sensor Image</p>
                <p className="font-mono text-xs text-text-muted break-all">{system.defaults.sensor_image_ref}</p>
              </div>
              <div>
                <p className="text-xs uppercase text-text-faint mb-1">Secure Cookies</p>
                <p>{system.defaults.session_secure ? "Enabled" : "Disabled"}</p>
              </div>
              <div>
                <p className="text-xs uppercase text-text-faint mb-1">Docs</p>
                <p>{system.defaults.docs_enabled ? "Enabled" : "Disabled"}</p>
              </div>
            </div>
          </div>

          <div className="card p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="font-semibold text-sm">Jobs & Diagnostics</h2>
              <StatusChip tone={system.background_jobs.analyzer_worker === "running" ? "good" : "warn"}>
                {system.background_jobs.analyzer_worker}
              </StatusChip>
            </div>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div>
                <p className="text-xs uppercase text-text-faint mb-1">API Bind</p>
                <p className="font-mono text-xs text-text-muted">{system.diagnostics.management_api}</p>
              </div>
              <div>
                <p className="text-xs uppercase text-text-faint mb-1">gRPC Bind</p>
                <p className="font-mono text-xs text-text-muted">{system.diagnostics.grpc_listener}</p>
              </div>
              <div>
                <p className="text-xs uppercase text-text-faint mb-1">LLM Engine</p>
                <p className="capitalize">{system.background_jobs.llm_engine}</p>
              </div>
              <div>
                <p className="text-xs uppercase text-text-faint mb-1">CORS</p>
                <p className="text-xs text-text-muted">
                  {system.diagnostics.cors_origins.length > 0 ? system.diagnostics.cors_origins.join(", ") : "Disabled"}
                </p>
              </div>
            </div>
          </div>

          <div className="card p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="font-semibold text-sm">Retention & Policy</h2>
              <StatusChip tone="warn">{system.retention_policy.mode}</StatusChip>
            </div>
            <p className="text-sm text-text-muted">{system.retention_policy.detail}</p>
            <p className="text-xs text-text-faint">
              This is where retention, cleanup, and default security policy controls should converge as the product matures.
            </p>
          </div>

          <div className="card p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="font-semibold text-sm">Backup, Restore & Cluster</h2>
              <StatusChip tone="muted">{system.cluster.mode}</StatusChip>
            </div>
            <p className="text-sm text-text-muted">{system.backup_restore.detail}</p>
            <p className="text-xs text-text-faint">{system.cluster.detail}</p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {quickLinks.map(({ href, icon: Icon, label, desc }) => (
          <Link key={href} href={href} className="card p-5 hover:bg-bg-elevated transition-colors group">
            <Icon className="w-5 h-5 text-accent mb-3 group-hover:scale-110 transition-transform" />
            <p className="font-semibold text-sm">{label}</p>
            <p className="text-xs text-text-muted mt-0.5">{desc}</p>
          </Link>
        ))}
      </div>
    </div>
  );
}
