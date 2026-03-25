"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Bell, Database, ArrowRight } from "lucide-react";
import { formatDateTime } from "@/components/ui";
import { apiPath } from "@/lib/api";

function ConfigChip({ active, label }: { active: boolean; label: string }) {
  return (
    <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold ${
      active
        ? "bg-green-900/30 text-severity-low border border-green-800/40"
        : "bg-bg-base text-text-muted border border-bg-border"
    }`}>
      {label}
    </span>
  );
}

export default function IntegrationsPage() {
  const [smtp, setSmtp] = useState<any>(null);
  const [siem, setSiEM] = useState<any>(null);
  const [deliveryLog, setDeliveryLog] = useState<any[]>([]);

  useEffect(() => {
    Promise.all([
      fetch(apiPath("/admin/smtp"), { credentials: "include" }).then((r) => r.json()),
      fetch(apiPath("/admin/siem"), { credentials: "include" }).then((r) => r.json()),
      fetch(apiPath("/admin/siem/delivery-log"), { credentials: "include" }).then((r) => r.json()),
    ]).then(([smtpData, siemData, logData]) => {
      setSmtp(smtpData);
      setSiEM(siemData);
      setDeliveryLog(logData.items ?? []);
    });
  }, []);

  const recentFailures = deliveryLog.filter((entry) => entry.status !== "success").length;

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      <div>
        <h1 className="text-xl font-bold">Integrations</h1>
        <p className="text-sm text-text-muted mt-0.5">External delivery channels for alerting and telemetry forwarding</p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <div className="card p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Bell className="w-5 h-5 text-accent" />
              <h2 className="font-semibold text-sm">Email Notifications</h2>
            </div>
            <ConfigChip active={!!smtp?.enabled} label={smtp?.enabled ? "enabled" : smtp?.configured ? "configured" : "not configured"} />
          </div>
          <div className="space-y-2 text-sm">
            <div>
              <p className="text-xs uppercase text-text-faint mb-1">SMTP Host</p>
              <p className="text-text-muted">{smtp?.host ?? "Not configured"}</p>
            </div>
            <div>
              <p className="text-xs uppercase text-text-faint mb-1">Recipients</p>
              <p className="text-text-muted">{smtp?.to_addresses?.length ? smtp.to_addresses.join(", ") : "No recipients configured"}</p>
            </div>
            <div>
              <p className="text-xs uppercase text-text-faint mb-1">Minimum Severity</p>
              <p className="capitalize text-text-muted">{smtp?.min_severity ?? "—"}</p>
            </div>
          </div>
          <Link href="/admin/notifications" className="btn-secondary inline-flex items-center gap-2 w-fit">
            Manage Email
            <ArrowRight className="w-4 h-4" />
          </Link>
        </div>

        <div className="card p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Database className="w-5 h-5 text-accent" />
              <h2 className="font-semibold text-sm">SIEM Forwarding</h2>
            </div>
            <ConfigChip active={!!siem?.enabled} label={siem?.enabled ? "enabled" : siem?.configured ? "configured" : "not configured"} />
          </div>
          <div className="space-y-2 text-sm">
            <div>
              <p className="text-xs uppercase text-text-faint mb-1">Integration Type</p>
              <p className="text-text-muted">{siem?.siem_type === "splunk_hec" ? "Splunk HEC" : siem?.siem_type ?? "Not configured"}</p>
            </div>
            <div>
              <p className="text-xs uppercase text-text-faint mb-1">Endpoint</p>
              <p className="text-xs text-text-muted break-all">{siem?.url ?? "No endpoint configured"}</p>
            </div>
            <div>
              <p className="text-xs uppercase text-text-faint mb-1">Recent Delivery Failures</p>
              <p className="text-text-muted">{recentFailures}</p>
            </div>
          </div>
          <Link href="/admin/siem" className="btn-secondary inline-flex items-center gap-2 w-fit">
            Manage SIEM
            <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      </div>

      <div className="card overflow-hidden">
        <div className="px-4 py-3 border-b border-bg-border flex items-center justify-between">
          <div>
            <h2 className="font-semibold text-sm">Recent Delivery Activity</h2>
            <p className="text-xs text-text-muted mt-0.5">Latest SIEM test and delivery attempts</p>
          </div>
          <Link href="/admin/siem" className="text-xs text-accent hover:underline">
            Open detailed log
          </Link>
        </div>
        <table className="data-table">
          <thead>
            <tr><th>Time</th><th>Type</th><th>Status</th><th>HTTP</th><th>Error</th></tr>
          </thead>
          <tbody>
            {deliveryLog.length === 0 ? (
              <tr><td colSpan={5} className="text-center text-text-faint py-10">No integration deliveries recorded yet</td></tr>
            ) : deliveryLog.slice(0, 10).map((entry) => (
              <tr key={entry.id}>
                <td className="text-xs font-mono whitespace-nowrap">{formatDateTime(entry.delivered_at)}</td>
                <td className="text-xs uppercase">{entry.siem_type}</td>
                <td>
                  <span className={entry.status === "success" ? "badge-low" : "badge-critical"}>
                    {entry.status}
                  </span>
                </td>
                <td className="text-xs tabular-nums">{entry.http_status ?? "—"}</td>
                <td className="text-xs text-text-faint truncate max-w-xs">{entry.error_detail ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
