"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  ChevronLeft, Globe, Building2, MapPin, Shield, Activity,
  AlertTriangle, Zap, Clock, Network,
} from "lucide-react";
import { SeverityBadge, SignalTierBadge, formatDateTime, formatDuration } from "@/components/ui";
import { apiPath } from "@/lib/api";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "noise"];
const SEV_COLOR: Record<string, string> = {
  critical: "text-severity-critical",
  high:     "text-severity-high",
  medium:   "text-severity-medium",
  low:      "text-severity-low",
  noise:    "text-text-faint",
};

export default function AttackerProfilePage() {
  const { ip }  = useParams<{ ip: string }>();
  const router  = useRouter();
  const [profile,  setProfile]  = useState<any>(null);
  const [sessions, setSessions] = useState<any[]>([]);
  const [iocs,     setIocs]     = useState<any[]>([]);
  const [loading,  setLoading]  = useState(true);

  const decodedIp = decodeURIComponent(ip);

  useEffect(() => {
    if (!decodedIp) return;
    Promise.all([
      fetch(apiPath(`/attackers/${encodeURIComponent(decodedIp)}`), { credentials: "include" }).then((r) => r.ok ? r.json() : null),
      fetch(apiPath(`/sessions?source_ip=${encodeURIComponent(decodedIp)}&limit=20&sort_by=started_at&sort_dir=desc`), { credentials: "include" }).then((r) => r.ok ? r.json() : null),
      fetch(apiPath(`/iocs?search=${encodeURIComponent(decodedIp)}&ioc_type=ip`), { credentials: "include" }).then((r) => r.ok ? r.json() : null),
    ]).then(([prof, sess, iocData]) => {
      if (prof)     setProfile(prof);
      if (sess)     setSessions(sess.items ?? []);
      if (iocData)  setIocs(iocData.items ?? []);
    }).finally(() => setLoading(false));
  }, [decodedIp]);

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center py-24 text-text-faint text-sm">
        Loading attacker profile…
      </div>
    );
  }

  if (!profile) {
    return (
      <div className="p-6">
        <button onClick={() => router.back()} className="btn-secondary flex items-center gap-2 mb-6">
          <ChevronLeft className="w-4 h-4" />Back
        </button>
        <div className="card p-12 text-center text-text-faint text-sm">No data found for {decodedIp}</div>
      </div>
    );
  }

  const geo      = profile.geo ?? {};
  const topSev   = SEVERITY_ORDER.find((s) => (profile.severity_dist?.[s] ?? 0) > 0);
  const totalSevCount = Object.values(profile.severity_dist ?? {}).reduce((a: number, b) => a + (b as number), 0);

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center gap-3">
        <button onClick={() => router.back()} className="btn-secondary p-2">
          <ChevronLeft className="w-4 h-4" />
        </button>
        <div className="flex items-center gap-3">
          {geo.flag && <span className="text-3xl">{geo.flag}</span>}
          <div>
            <h1 className="text-xl font-bold font-mono text-text-primary">{decodedIp}</h1>
            <p className="text-sm text-text-muted">
              {[geo.city, geo.country_name].filter(Boolean).join(", ") || "Unknown location"}
              {geo.org && <span className="ml-2 text-text-faint">· {geo.org}</span>}
            </p>
          </div>
          {profile.cpu_stop_ever && (
            <span className="flex items-center gap-1 text-severity-critical text-xs font-semibold bg-severity-critical/10 border border-severity-critical/30 px-2 py-1 rounded">
              <Zap className="w-3 h-3" />CPU STOP
            </span>
          )}
        </div>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Sessions",   value: profile.session_count,  icon: Shield,        color: "text-accent" },
          { label: "Events",     value: profile.event_count,    icon: Activity,      color: "text-severity-medium" },
          { label: "IOCs",       value: profile.ioc_count,      icon: AlertTriangle, color: "text-severity-high" },
          { label: "First Seen", value: formatDateTime(profile.first_seen), icon: Clock, color: "text-text-muted" },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="kpi-card">
            <div className="flex items-center justify-between mb-2">
              <span className="kpi-label">{label}</span>
              <Icon className={`w-4 h-4 ${color}`} />
            </div>
            <span className={`kpi-value ${color}`}>{value ?? "—"}</span>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* GeoIP + Severity distribution */}
        <div className="space-y-4">
          {/* GeoIP card */}
          <div className="card p-4 space-y-3">
            <h2 className="font-semibold text-sm text-text-primary">Location</h2>
            {[
              { icon: Globe,     label: "Country", value: geo.country_name },
              { icon: MapPin,    label: "City",    value: geo.city },
              { icon: Building2, label: "ISP/Org", value: geo.org },
            ].map(({ icon: Icon, label, value }) => value ? (
              <div key={label} className="flex items-center gap-3">
                <Icon className="w-4 h-4 text-text-faint flex-shrink-0" />
                <div>
                  <p className="text-xs text-text-faint">{label}</p>
                  <p className="text-sm text-text-primary">{value}</p>
                </div>
              </div>
            ) : null)}
          </div>

          {/* Severity distribution */}
          {totalSevCount > 0 && (
            <div className="card p-4">
              <h2 className="font-semibold text-sm text-text-primary mb-3">Severity Breakdown</h2>
              <div className="space-y-2">
                {SEVERITY_ORDER.filter((s) => profile.severity_dist?.[s]).map((s) => {
                  const count = profile.severity_dist[s];
                  const pct   = Math.round((count / totalSevCount) * 100);
                  return (
                    <div key={s} className="flex items-center gap-2">
                      <span className={`text-xs w-16 capitalize ${SEV_COLOR[s]}`}>{s}</span>
                      <div className="flex-1 h-1.5 bg-bg-base rounded-full overflow-hidden">
                        <div className={`h-full rounded-full ${
                          s === "critical" ? "bg-severity-critical" :
                          s === "high"     ? "bg-severity-high" :
                          s === "medium"   ? "bg-severity-medium" :
                          s === "low"      ? "bg-severity-low" :
                          "bg-bg-border"
                        }`} style={{ width: `${pct}%` }} />
                      </div>
                      <span className="text-xs tabular-nums text-text-muted w-6 text-right">{count}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Protocol distribution */}
          {profile.protocol_dist?.length > 0 && (
            <div className="card p-4">
              <h2 className="font-semibold text-sm text-text-primary mb-3">Protocols</h2>
              <div className="flex flex-wrap gap-2">
                {profile.protocol_dist.map((p: any) => (
                  <span key={p.protocol} className="text-xs px-2 py-1 rounded bg-bg-elevated text-text-muted uppercase font-mono">
                    {p.protocol} <span className="text-text-faint">×{p.count}</span>
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Sessions */}
        <div className="xl:col-span-2 space-y-4">
          <div className="card overflow-hidden">
            <div className="px-4 py-3 border-b border-bg-border flex items-center justify-between">
              <h2 className="font-semibold text-sm text-text-primary">Sessions</h2>
              <button
                onClick={() => router.push(`/sessions?source_ip=${encodeURIComponent(decodedIp)}`)}
                className="text-xs text-accent hover:underline"
              >
                View all →
              </button>
            </div>
            {sessions.length === 0 ? (
              <div className="py-8 text-center text-text-faint text-sm">No sessions</div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Started</th>
                    <th>Severity</th>
                    <th>Signal</th>
                    <th>Protocol</th>
                    <th>Phase</th>
                    <th>Events</th>
                    <th>Duration</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.map((s) => (
                    <tr key={s.id} className="cursor-pointer" onClick={() => router.push(`/sessions/${s.id}`)}>
                      <td className="text-xs font-mono whitespace-nowrap">{formatDateTime(s.started_at)}</td>
                      <td><SeverityBadge severity={s.severity} /></td>
                      <td><SignalTierBadge tier={s.signal_tier} /></td>
                      <td className="text-xs uppercase text-text-muted">{s.primary_protocol}</td>
                      <td className="text-xs text-text-muted">{s.attack_phase?.replace(/_/g, " ")}</td>
                      <td className="text-xs tabular-nums">{s.event_count}</td>
                      <td className="text-xs text-text-muted">{formatDuration(s.duration_seconds)}</td>
                      <td className="text-xs">
                        <span className="capitalize text-text-muted">{(s.triage_status || "new").replace(/_/g, " ")}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* IOCs */}
          {iocs.length > 0 && (
            <div className="card overflow-hidden">
              <div className="px-4 py-3 border-b border-bg-border">
                <h2 className="font-semibold text-sm text-text-primary">IOCs</h2>
              </div>
              <table className="data-table">
                <thead>
                  <tr><th>Type</th><th>Value</th><th>Confidence</th><th>Sessions</th><th>Last Seen</th></tr>
                </thead>
                <tbody>
                  {iocs.map((ioc, i) => (
                    <tr key={i}>
                      <td className="text-xs uppercase font-mono text-text-muted">{ioc.ioc_type}</td>
                      <td className="text-xs font-mono">{ioc.value}</td>
                      <td className="text-xs tabular-nums">{Math.round((ioc.confidence ?? 0) * 100)}%</td>
                      <td className="text-xs tabular-nums">{ioc.session_count}</td>
                      <td className="text-xs text-text-muted whitespace-nowrap">{formatDateTime(ioc.last_seen_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
