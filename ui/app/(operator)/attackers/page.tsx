"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { Target, Zap } from "lucide-react";
import { SeverityBadge, formatDateTime } from "@/components/ui";
import { apiPath } from "@/lib/api";

const RANGES = [
  { label: "24h", hours: 24 },
  { label: "7d",  hours: 168 },
  { label: "30d", hours: 720 },
] as const;

type RangeHours = 24 | 168 | 720;

export default function AttackersPage() {
  const router = useRouter();
  const [range,     setRange]     = useState<RangeHours>(24);
  const [attackers, setAttackers] = useState<any[]>([]);
  const [loading,   setLoading]   = useState(false);

  const load = useCallback(async (h: RangeHours) => {
    setLoading(true);
    try {
      const r = await fetch(apiPath(`/events/top-attackers?limit=50&hours=${h}`), { credentials: "include" });
      if (r.ok) {
        const d = await r.json();
        setAttackers(d.items ?? []);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(range); }, [range, load]);

  return (
    <div className="p-6 space-y-4 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2 text-text-primary">
            <Target className="w-5 h-5 text-severity-high" />
            Attackers
          </h1>
          <p className="text-sm text-text-muted mt-0.5">
            Top attacking IPs by event volume
          </p>
        </div>
        <div className="flex items-center bg-bg-surface border border-bg-border rounded-md p-0.5">
          {RANGES.map(({ label, hours }) => (
            <button
              key={hours}
              onClick={() => setRange(hours as RangeHours)}
              className={`px-3 py-1 text-xs font-medium rounded transition-colors ${
                range === hours ? "bg-accent text-white" : "text-text-muted hover:text-text-primary"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        <table className="data-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Source IP</th>
              <th>Country</th>
              <th>ISP / Org</th>
              <th>Events</th>
              <th>Sessions</th>
              <th>Max Severity</th>
              <th>CPU STOP</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={9} className="text-center text-text-faint py-12">Loading…</td></tr>
            ) : attackers.length === 0 ? (
              <tr><td colSpan={9} className="text-center text-text-faint py-12">No attackers in this window</td></tr>
            ) : attackers.map((a, i) => (
              <tr
                key={a.source_ip}
                className="cursor-pointer"
                onClick={() => router.push(`/attackers/${encodeURIComponent(a.source_ip)}`)}
              >
                <td className="text-xs text-text-faint tabular-nums">{i + 1}</td>
                <td className="font-mono text-xs">
                  <span className="flex items-center gap-1.5">
                    {a.flag && <span title={a.country_name}>{a.flag}</span>}
                    <span className="text-accent hover:underline">{a.source_ip}</span>
                  </span>
                </td>
                <td className="text-xs text-text-muted">{a.country_name || "—"}</td>
                <td className="text-xs text-text-muted truncate max-w-[160px]">{a.org || "—"}</td>
                <td className="text-xs tabular-nums font-semibold">{a.event_count}</td>
                <td className="text-xs tabular-nums">{a.session_count ?? "—"}</td>
                <td><SeverityBadge severity={a.max_severity} /></td>
                <td className="text-xs">
                  {a.cpu_stop_ever
                    ? <span className="flex items-center gap-1 text-severity-critical"><Zap className="w-3 h-3" />Yes</span>
                    : <span className="text-text-faint">—</span>
                  }
                </td>
                <td className="text-xs text-text-muted whitespace-nowrap">{a.last_seen ? formatDateTime(a.last_seen) : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
