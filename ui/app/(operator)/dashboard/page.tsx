"use client";

import { useEffect, useState } from "react";
import { Shield, Zap, AlertTriangle, Activity } from "lucide-react";
import { useStream } from "../layout";
import { SeverityBadge, formatTime } from "@/components/ui";
import { apiPath } from "@/lib/api";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";

export default function DashboardPage() {
  const { events, stats, connected } = useStream();
  const [topAttackers, setTopAttackers] = useState<any[]>([]);
  const [recentSessions, setRecentSessions] = useState<any[]>([]);

  // ── Load initial data ──────────────────────────────────────────────────────
  useEffect(() => {
    fetch(apiPath("/events/top-attackers?limit=8"), { credentials: "include" })
      .then((r) => r.ok ? r.json() : null).then((d) => { if (d) setTopAttackers(d.items ?? []); });

    fetch(apiPath("/sessions?is_actionable=true&limit=5"), { credentials: "include" })
      .then((r) => r.ok ? r.json() : null).then((d) => { if (d) setRecentSessions(d.items ?? []); });
  }, []);

  const kpis = [
    {
      label: "Total Sessions",
      value: stats?.total_sessions ?? "—",
      icon:  Shield,
      color: "text-accent",
    },
    {
      label: "Critical / High",
      value: stats?.critical_sessions ?? "—",
      icon:  AlertTriangle,
      color: "text-severity-high",
    },
    {
      label: "CPU STOP Events",
      value: stats?.cpu_stop_count ?? "—",
      icon:  Zap,
      color: "text-severity-critical",
    },
    {
      label: "Events (24h)",
      value: stats?.events_24h ?? "—",
      icon:  Activity,
      color: "text-severity-medium",
    },
  ];

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-text-primary">Operator Dashboard</h1>
          <p className="text-sm text-text-muted mt-0.5">
            OT Deception Platform · Live threat intelligence
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <div className={`w-2 h-2 rounded-full ${connected ? "bg-severity-low animate-pulse-slow" : "bg-severity-high"}`} />
          <span className="text-text-muted">{connected ? "Live stream connected" : "Reconnecting…"}</span>
        </div>
      </div>

      {/* ── KPI row ─────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {kpis.map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="kpi-card">
            <div className="flex items-center justify-between mb-2">
              <span className="kpi-label">{label}</span>
              <Icon className={`w-4 h-4 ${color}`} />
            </div>
            <span className={`kpi-value ${color}`}>{value}</span>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* ── Live event feed ──────────────────────────────────────────── */}
        <div className="xl:col-span-2 card">
          <div className="flex items-center justify-between px-4 py-3 border-b border-bg-border">
            <h2 className="font-semibold text-sm text-text-primary">Live Attack Feed</h2>
            <span className="text-xs text-text-muted">{events.length} events buffered</span>
          </div>
          <div className="overflow-y-auto" style={{ maxHeight: 420 }}>
            {events.length === 0 ? (
              <div className="flex items-center justify-center py-16 text-text-faint text-sm">
                Waiting for events…
              </div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Severity</th>
                    <th>Source IP</th>
                    <th>Event</th>
                    <th>Protocol</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((ev) => (
                    <tr key={ev.event_id}
                      className={ev.cpu_stop ? "bg-red-900/10 border-l-2 border-severity-critical" : ""}>
                      <td className="font-mono text-xs text-text-muted whitespace-nowrap">
                        {formatTime(ev.timestamp)}
                      </td>
                      <td><SeverityBadge severity={ev.severity} /></td>
                      <td className="font-mono text-xs">{ev.source_ip}</td>
                      <td className="text-xs max-w-xs truncate" title={ev.summary}>
                        {ev.cpu_stop && <span className="mr-1 text-severity-critical">⚡</span>}
                        {ev.event_type.replace(/_/g, " ")}
                      </td>
                      <td className="text-xs text-text-muted uppercase">{ev.protocol}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* ── Top Attackers chart ──────────────────────────────────────── */}
        <div className="card">
          <div className="px-4 py-3 border-b border-bg-border">
            <h2 className="font-semibold text-sm text-text-primary">Top Attackers</h2>
          </div>
          <div className="p-4">
            {topAttackers.length === 0 ? (
              <div className="text-center py-8 text-text-faint text-sm">No data yet</div>
            ) : (
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={topAttackers} layout="vertical" margin={{ left: 8 }}>
                  <XAxis type="number" tick={{ fill: "#94A3B8", fontSize: 11 }} tickLine={false} axisLine={false} />
                  <YAxis
                    type="category"
                    dataKey="source_ip"
                    width={110}
                    tick={{ fill: "#94A3B8", fontSize: 11, fontFamily: "JetBrains Mono" }}
                    tickLine={false} axisLine={false}
                  />
                  <Tooltip
                    contentStyle={{ background: "#1A2236", border: "1px solid #1E2A3B", borderRadius: 6, fontSize: 12 }}
                    labelStyle={{ color: "#F8FAFC" }}
                    itemStyle={{ color: "#94A3B8" }}
                  />
                  <Bar dataKey="event_count" radius={[0, 4, 4, 0]} maxBarSize={20}>
                    {topAttackers.map((entry, i) => (
                      <Cell key={i} fill={
                        entry.max_severity === "critical" ? "#EF4444" :
                        entry.max_severity === "high"     ? "#F97316" :
                        entry.max_severity === "medium"   ? "#EAB308" :
                        "#3B82F6"
                      } />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* Actionable sessions */}
          <div className="px-4 pb-4 border-t border-bg-border pt-3">
            <p className="text-xs font-semibold text-text-muted uppercase mb-2">Actionable Sessions</p>
            {recentSessions.length === 0 ? (
              <p className="text-xs text-text-faint">None yet</p>
            ) : (
              <div className="space-y-1.5">
                {recentSessions.slice(0, 4).map((s) => (
                  <div key={s.id} className="flex items-center justify-between text-xs">
                    <span className="font-mono text-text-muted">{s.source_ip}</span>
                    <div className="flex items-center gap-1.5">
                      {s.cpu_stop_occurred && <span className="text-severity-critical">⚡</span>}
                      <SeverityBadge severity={s.severity} />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
